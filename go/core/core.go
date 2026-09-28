package core

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Version defaults. A receiver enforces its own limits and never negotiates
// them online.
const (
	DefaultMaxMessageBytes    = 1024 * 1024
	DefaultRequestTTLSeconds  = 60
	DefaultMaxRequestTTL      = 60
	DefaultClockSkewSeconds   = 5
	DefaultCallTimeout        = 15 * time.Second
	DefaultNonceBytes         = 32
	ReplayErrorCode           = "REQUEST_ALREADY_SEEN"
	HandlerErrorCode          = "HANDLER_FAILED"
	handlerFailureMessage     = "handler failed"
	replayFailureMessage      = "this request has already been received"
	requestWindowExceededText = "request expiry is further away than the local window allows"
)

// Exchange moves one request envelope to one response envelope. It performs no
// signature handling and no business work.
type Exchange func(ctx context.Context, requestBytes []byte) ([]byte, error)

// HandlerContext is what the application receives.
type HandlerContext struct {
	CallerPublicKey []byte
	RequestID       string
	Body            Value
	Envelope        RequestEnvelope
}

// Handler is the application entry point. Structure, recipient, signature and
// dedup checks have already passed when it runs, so authorization belongs here.
type Handler func(ctx context.Context, input HandlerContext) (Outcome, error)

// Config configures a Core.
type Config struct {
	Signer  Signer
	Handler Handler
	Replay  ReplayGuard

	MaxMessageBytes   int
	RequestTTLSeconds int64
	MaxRequestTTL     int64
	// ClockSkewSeconds overrides the allowed clock skew. It is a pointer because
	// zero is a meaningful value, and an unset field must not be mistaken for
	// it: the default is DefaultClockSkewSeconds.
	ClockSkewSeconds *int64
	CallTimeout      time.Duration
	Now              func() int64
	RandomBytes      func(length int) ([]byte, error)
}

// Core is the protocol core: encoding, signing, verification, request
// correlation, dedup coordination and the call lifecycle.
type Core struct {
	signer            Signer
	handler           Handler
	replay            ReplayGuard
	publicKey         []byte
	maxMessageBytes   int
	requestTTLSeconds int64
	maxRequestTTL     int64
	clockSkewSeconds  int64
	callTimeout       time.Duration
	now               func() int64
	randomBytes       func(int) ([]byte, error)
}

// New builds a Core and fixes its identity from the signer.
func New(config Config) (*Core, error) {
	publicKey := config.Signer.PublicKey()
	if err := ValidatePublicKey(publicKey); err != nil {
		return nil, err
	}
	core := &Core{
		signer:            config.Signer,
		handler:           config.Handler,
		replay:            config.Replay,
		publicKey:         append([]byte(nil), publicKey...),
		maxMessageBytes:   DefaultMaxMessageBytes,
		requestTTLSeconds: DefaultRequestTTLSeconds,
		maxRequestTTL:     DefaultMaxRequestTTL,
		clockSkewSeconds:  DefaultClockSkewSeconds,
		callTimeout:       DefaultCallTimeout,
		now:               func() int64 { return time.Now().Unix() },
		randomBytes: func(length int) ([]byte, error) {
			buffer := make([]byte, length)
			if _, err := rand.Read(buffer); err != nil {
				return nil, err
			}
			return buffer, nil
		},
	}
	if config.MaxMessageBytes > 0 {
		core.maxMessageBytes = config.MaxMessageBytes
	}
	if config.RequestTTLSeconds > 0 {
		core.requestTTLSeconds = config.RequestTTLSeconds
	}
	if config.MaxRequestTTL > 0 {
		core.maxRequestTTL = config.MaxRequestTTL
	}
	if config.ClockSkewSeconds != nil {
		if *config.ClockSkewSeconds < 0 {
			return nil, failf(ErrJSONNumber, "ClockSkewSeconds must not be negative")
		}
		core.clockSkewSeconds = *config.ClockSkewSeconds
	}
	if config.CallTimeout > 0 {
		core.callTimeout = config.CallTimeout
	}
	if config.Now != nil {
		core.now = config.Now
	}
	if config.RandomBytes != nil {
		core.randomBytes = config.RandomBytes
	}
	if config.Replay == nil {
		// The default guard gets this instance's clock, so record retention and
		// the expiry check can never disagree.
		config.Replay = NewMemoryReplayGuard(core.now)
	}
	core.replay = config.Replay
	return core, nil
}

// PublicKey returns a copy of this instance's identity. The identity of an
// instance is fixed; replace the instance to replace the identity.
func (c *Core) PublicKey() []byte {
	return append([]byte(nil), c.publicKey...)
}

// Replay exposes the configured store, mostly for diagnostics and tests.
func (c *Core) Replay() ReplayGuard { return c.replay }

// Limits reports the enforced local limits.
func (c *Core) Limits() (maxMessageBytes int, requestTTL, maxRequestTTL, clockSkew int64) {
	return c.maxMessageBytes, c.requestTTLSeconds, c.maxRequestTTL, c.clockSkewSeconds
}

// CallTimeout reports the default call timeout.
func (c *Core) CallTimeout() time.Duration { return c.callTimeout }

// PreparedRequest is a signed request that is ready to send. A retransmission
// must reuse these bytes.
type PreparedRequest struct {
	Unsigned  UnsignedRequest
	Bytes     []byte
	RequestID string
}

// BuildRequestOptions overrides the nonce and expiry for a single call.
type BuildRequestOptions struct {
	Nonce   []byte
	Expires int64
}

// BuildRequest builds and signs one request.
func (c *Core) BuildRequest(ctx context.Context, to []byte, body Value, options BuildRequestOptions) (PreparedRequest, error) {
	var result PreparedRequest
	if err := ValidatePublicKey(to); err != nil {
		return result, err
	}
	nonce := options.Nonce
	if nonce == nil {
		generated, err := c.randomBytes(DefaultNonceBytes)
		if err != nil {
			return result, &Error{Code: ErrNonce, Err: err}
		}
		nonce = generated
	}
	if len(nonce) < MinNonceBytes {
		return result, failf(ErrNonce, "nonce must be at least %d bytes", MinNonceBytes)
	}
	expires := options.Expires
	if expires == 0 {
		expires = c.now() + c.requestTTLSeconds
	}
	unsigned := UnsignedRequest{
		From:    append([]byte(nil), c.publicKey...),
		To:      append([]byte(nil), to...),
		Nonce:   append([]byte(nil), nonce...),
		Expires: expires,
		Body:    body,
	}
	signature, err := c.sign(unsigned)
	if err != nil {
		return result, err
	}
	bytes, err := EncodeEnvelopeBytes(unsigned, signature)
	if err != nil {
		return result, err
	}
	requestID, err := RequestIDOf(unsigned)
	if err != nil {
		return result, err
	}
	return PreparedRequest{Unsigned: unsigned, Bytes: bytes, RequestID: requestID}, nil
}

// Call performs one request and one response.
func (c *Core) Call(ctx context.Context, to []byte, body Value, exchange Exchange) (Outcome, PreparedRequest, error) {
	prepared, err := c.BuildRequest(ctx, to, body, BuildRequestOptions{})
	if err != nil {
		return Outcome{}, PreparedRequest{}, err
	}
	outcome, err := c.Send(ctx, prepared, exchange)
	return outcome, prepared, err
}

// Send delivers a prepared request and verifies the response.
//
// The response must come from the requested peer, must be addressed to this
// instance, must quote the id of the request that is waiting, and must carry a
// valid signature. A waiting call completes at most once.
//
// The deadline bounds the wait on its own: a transport that only stops when it is
// told to would otherwise hold the caller for ever, so the abort races the
// exchange instead of being left to the adapter.
func (c *Core) Send(ctx context.Context, prepared PreparedRequest, exchange Exchange) (Outcome, error) {
	callCtx, cancel := context.WithTimeout(ctx, c.callTimeout)
	defer cancel()
	type exchangeResult struct {
		bytes []byte
		err   error
	}
	// Buffered, so a transport that answers after the caller gave up can still
	// finish and exit.
	settled := make(chan exchangeResult, 1)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				settled <- exchangeResult{err: fmt.Errorf("exchange panicked: %v", recovered)}
			}
		}()
		bytes, err := exchange(callCtx, prepared.Bytes)
		settled <- exchangeResult{bytes: bytes, err: err}
	}()

	var responseBytes []byte
	select {
	case result := <-settled:
		if result.err != nil {
			if callCtx.Err() != nil {
				return Outcome{}, c.callEnded(ctx, callCtx)
			}
			if coded := CodeOf(result.err); coded != "" {
				return Outcome{}, result.err
			}
			return Outcome{}, &Error{Code: ErrTransport, Err: result.err}
		}
		responseBytes = result.bytes
	case <-callCtx.Done():
		return Outcome{}, c.callEnded(ctx, callCtx)
	}
	// The transport can also win this race and then hand over bytes after the
	// deadline. A late answer is not a result for this call, so it is refused
	// before any of it is verified.
	if callCtx.Err() != nil {
		return Outcome{}, c.callEnded(ctx, callCtx)
	}
	return c.VerifyResponse(responseBytes, prepared)
}

// callEnded classifies why a call stopped waiting. A caller that cancelled gets
// the abort reason; a deadline that expired on its own is a timeout.
func (c *Core) callEnded(parent, callCtx context.Context) error {
	if parent.Err() != nil {
		return &Error{Code: ErrCallAborted, Err: parent.Err()}
	}
	if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
		return &Error{Code: ErrCallTimeout, Err: fmt.Errorf("no response within %s", c.callTimeout)}
	}
	return &Error{Code: ErrCallAborted, Err: callCtx.Err()}
}

// VerifyResponse checks every condition a base response has to satisfy.
func (c *Core) VerifyResponse(responseBytes []byte, prepared PreparedRequest) (Outcome, error) {
	if len(responseBytes) > c.maxMessageBytes {
		return Outcome{}, failf(ErrResponseSize, "response exceeds the local message limit")
	}
	value, err := ParseJSONBytes(responseBytes)
	if err != nil {
		return Outcome{}, err
	}
	envelope, err := ParseResponse(value)
	if err != nil {
		return Outcome{}, err
	}
	unsigned := envelope.Unsigned
	if !EqualBytes(unsigned.To, c.publicKey) {
		return Outcome{}, failf(ErrResponseTo, "response is not addressed to this identity")
	}
	if !EqualBytes(unsigned.From, prepared.Unsigned.To) {
		return Outcome{}, failf(ErrResponseFrom, "response did not come from the requested peer")
	}
	requestDigest, err := DigestOf(prepared.Unsigned)
	if err != nil {
		return Outcome{}, err
	}
	if !EqualBytes(unsigned.ReplyTo, requestDigest) {
		return Outcome{}, failf(ErrResponseReplyTo, "response does not belong to the waiting request")
	}
	digest, err := DigestOf(unsigned)
	if err != nil {
		return Outcome{}, err
	}
	if err := VerifyDigest(unsigned.From, digest, envelope.Signature); err != nil {
		return Outcome{}, &Error{Code: ErrResponseSignature, Err: err}
	}
	return BodyToOutcome(unsigned.Body)
}

// HandleOptions carries transport facts the core cannot know by itself.
type HandleOptions struct {
	// CallerPublicKey is the authenticated transport identity of the sender,
	// when the transport has one. It must equal the request From.
	CallerPublicKey []byte
}

// ProcessedRequest is the result of serving one request.
type ProcessedRequest struct {
	RequestID string
	Outcome   Outcome
	Bytes     []byte
}

// Handle processes one signed request and returns the signed response bytes.
//
// Order matters: structure and size, then expiry, then recipient, then
// signature, then the atomic replay claim, and only then the application.
// Claiming before the handler is what stops two concurrent deliveries of the
// same request from both producing side effects.
func (c *Core) Handle(ctx context.Context, requestBytes []byte, options HandleOptions) (ProcessedRequest, error) {
	var empty ProcessedRequest
	if c.handler == nil {
		return empty, failf(ErrNoHandler, "this instance has no request handler")
	}
	if len(requestBytes) > c.maxMessageBytes {
		return empty, failf(ErrMessageTooLarge, "request exceeds %d bytes", c.maxMessageBytes)
	}
	value, err := ParseJSONBytes(requestBytes)
	if err != nil {
		return empty, err
	}
	envelope, err := ParseRequest(value)
	if err != nil {
		return empty, err
	}
	unsigned := envelope.Unsigned
	now := c.now()
	if unsigned.Expires > now+c.maxRequestTTL {
		return empty, failf(ErrExpiryWindow, "%s", requestWindowExceededText)
	}
	if unsigned.Expires+c.clockSkewSeconds < now {
		return empty, failf(ErrExpired, "request has expired")
	}
	if !EqualBytes(unsigned.To, c.publicKey) {
		return empty, failf(ErrRecipient, "request is not addressed to this identity")
	}
	if options.CallerPublicKey != nil && !EqualBytes(options.CallerPublicKey, unsigned.From) {
		return empty, failf(ErrCallerIdentity, "request from does not match the authenticated transport peer")
	}
	requestDigest, err := DigestOf(unsigned)
	if err != nil {
		return empty, err
	}
	if err := VerifyDigest(unsigned.From, requestDigest, envelope.Signature); err != nil {
		return empty, &Error{Code: ErrSignature, Err: err}
	}
	requestID, err := RequestIDOf(unsigned)
	if err != nil {
		return empty, err
	}
	outcome, err := c.dispatch(ctx, requestID, unsigned, envelope)
	if err != nil {
		return empty, err
	}
	response := UnsignedResponse{
		From:    append([]byte(nil), c.publicKey...),
		To:      append([]byte(nil), unsigned.From...),
		ReplyTo: requestDigest,
		Body:    OutcomeToBody(outcome),
	}
	signature, err := c.sign(response)
	if err != nil {
		return empty, err
	}
	bytes, err := EncodeEnvelopeBytes(response, signature)
	if err != nil {
		return empty, err
	}
	return ProcessedRequest{RequestID: requestID, Outcome: outcome, Bytes: bytes}, nil
}

func (c *Core) dispatch(ctx context.Context, requestID string, unsigned UnsignedRequest, envelope RequestEnvelope) (Outcome, error) {
	claimed, err := c.replay.Claim(ctx, ReplayClaim{ID: requestID, RetainUntil: unsigned.Expires + c.clockSkewSeconds})
	if err != nil {
		return Outcome{}, err
	}
	if !claimed {
		// Every duplicate gets the same signed business error. The first
		// version does not cache or replay the original result.
		return Outcome{Error: BusinessError{Code: ReplayErrorCode, Message: replayFailureMessage}}, nil
	}
	outcome, err := c.handler(ctx, HandlerContext{
		CallerPublicKey: append([]byte(nil), unsigned.From...),
		RequestID:       requestID,
		Body:            unsigned.Body,
		Envelope:        envelope,
	})
	if err != nil {
		// A handler failure is a signed business error, not a transport error,
		// and it must not leak internals to the caller.
		outcome = Outcome{Error: BusinessError{Code: HandlerErrorCode, Message: handlerFailureMessage}}
	}
	if err := c.replay.Complete(ctx, requestID); err != nil {
		return Outcome{}, err
	}
	return outcome, nil
}

func (c *Core) sign(unsigned any) ([]byte, error) {
	signature, err := c.signer.SignRoundtrip(unsigned)
	if err != nil {
		if coded := CodeOf(err); coded != "" {
			return nil, err
		}
		return nil, &Error{Code: ErrSignerFailed, Err: err}
	}
	// Verify before anything leaves this process: a signer whose output does not
	// match the canonical bytes is a configuration error, not a network error.
	message, ok := unsigned.(UnsignedRequest)
	if !ok {
		response, isResponse := unsigned.(UnsignedResponse)
		if !isResponse {
			return nil, failf(ErrSignerFailed, "unsupported unsigned message type")
		}
		message = UnsignedRequest{From: response.From, To: response.To, Expires: 0, Body: response.Body}
	}
	digest, err := DigestOf(unsigned)
	if err != nil {
		return nil, err
	}
	if err := VerifyDigest(message.From, digest, signature); err != nil {
		return nil, &Error{Code: ErrSignerKey, Err: err}
	}
	return signature, nil
}

// DeterministicNonce is a test helper that turns a label into a distinct nonce.
func DeterministicNonce(seed uint32) []byte {
	buffer := make([]byte, DefaultNonceBytes)
	binary.BigEndian.PutUint32(buffer[0:4], seed)
	for index := 4; index < len(buffer); index++ {
		buffer[index] = byte(index * 31)
	}
	return buffer
}
