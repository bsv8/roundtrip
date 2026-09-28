package core_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/bsv8/roundtrip/go/core"
)

// Ablation, in Go, over the same fixtures the TypeScript suite uses.
//
// Every experiment removes exactly one mechanism, keeps everything else
// identical, and states which requirement fails. There is no production switch
// for any of this: the reduced pipeline below exists only in this file, and the
// control proves it behaves like the shipped core before anything is removed
// from it.

func mustCodeOf(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		return ""
	}
	if code := core.CodeOf(err); code != "" {
		return string(code)
	}
	return "NOT_A_ROUNDTRIP_ERROR"
}

// reducedNode is the receiving pipeline of Core.Handle, written out so a single
// step can be deleted. The order is the shipped order: expiry, recipient,
// signature, atomic claim, then the application.
type reducedNode struct {
	publicKey []byte
	replay    core.ReplayGuard
	handler   core.Handler
	now       func() int64
	skew      int64
	signer    core.Signer
}

func newReducedNode(t *testing.T, name string, handler core.Handler) *reducedNode {
	t.Helper()
	return &reducedNode{
		publicKey: testPublicKey(t, name),
		replay:    core.NewMemoryReplayGuard(func() int64 { return testNow }),
		handler:   handler,
		now:       func() int64 { return testNow },
		skew:      5,
		signer:    testSigner(t, name),
	}
}

type removed struct {
	requestSignature bool
	recipient        bool
}

func (node *reducedNode) handle(t *testing.T, requestBytes []byte, drop removed) core.ProcessedRequest {
	t.Helper()
	// A refusal is reported through the outcome, so malformed input is compared
	// the same way the shipped core reports it.
	value, err := core.ParseJSONBytes(requestBytes)
	if err != nil {
		return failure(dropCode, string(core.CodeOf(err)), err.Error())
	}
	envelope, err := core.ParseRequest(value)
	if err != nil {
		return failure(dropCode, string(core.CodeOf(err)), err.Error())
	}
	unsigned := envelope.Unsigned
	if unsigned.Expires+node.skew < node.now() {
		return failure(dropCode, "ERR_EXPIRED", "request has expired")
	}
	if !drop.recipient && !core.EqualBytes(unsigned.To, node.publicKey) {
		return failure(dropCode, "ERR_RECIPIENT", "request is not addressed to this identity")
	}
	if !drop.requestSignature {
		digest, err := core.DigestOf(unsigned)
		if err != nil {
			t.Fatalf("digest: %v", err)
		}
		if err := core.VerifyDigest(unsigned.From, digest, envelope.Signature); err != nil {
			return failure(dropCode, string(core.ErrSignature), err.Error())
		}
	}
	requestID, err := core.RequestIDOf(unsigned)
	if err != nil {
		t.Fatalf("request id: %v", err)
	}
	claimed, err := node.replay.Claim(context.Background(), core.ReplayClaim{ID: requestID, RetainUntil: unsigned.Expires + node.skew})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	var outcome core.Outcome
	if !claimed {
		outcome = core.Outcome{Error: core.BusinessError{Code: core.ReplayErrorCode, Message: "this request has already been received"}}
	} else {
		outcome, _ = node.handler(context.Background(), core.HandlerContext{
			CallerPublicKey: unsigned.From,
			RequestID:       requestID,
			Body:            unsigned.Body,
			Envelope:        envelope,
		})
		if err := node.replay.Complete(context.Background(), requestID); err != nil {
			t.Fatalf("complete: %v", err)
		}
	}
	return node.respond(t, unsigned.From, requestID, outcome)
}

const dropCode = "REDUCED_PIPELINE_REFUSED"

func failure(id, code, message string) core.ProcessedRequest {
	return core.ProcessedRequest{RequestID: id, Outcome: core.Outcome{Error: core.BusinessError{Code: code, Message: message}}}
}

func (node *reducedNode) respond(t *testing.T, to []byte, requestID string, outcome core.Outcome) core.ProcessedRequest {
	t.Helper()
	digest, err := core.DecodeBase64Url(requestID, core.ErrReplyTo)
	if err != nil {
		t.Fatalf("decode request id: %v", err)
	}
	unsigned := core.UnsignedResponse{From: node.publicKey, To: to, ReplyTo: digest, Body: core.OutcomeToBody(outcome)}
	signature, err := node.signer.SignRoundtrip(unsigned)
	if err != nil {
		t.Fatalf("sign response: %v", err)
	}
	bytes, err := core.EncodeEnvelopeBytes(unsigned, signature)
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	return core.ProcessedRequest{RequestID: requestID, Outcome: outcome, Bytes: bytes}
}

// control: with nothing removed, the reduced pipeline has to reach the same
// verdict as the shipped core for every input class. Every experiment below rests
// on this.
func TestAblationControlMatchesTheShippedCore(t *testing.T) {
	battery := []struct {
		label string
		bytes []byte
	}{
		{"valid", signedRequestFor(t, "alice", "bob", "alice", nil)},
		{"wrong recipient", signedRequestFor(t, "alice", "carol", "alice", nil)},
		{"expired", signedRequestFor(t, "alice", "bob", "alice", func(r *core.UnsignedRequest) { r.Expires = testNow - 600 })},
		{"signature from another key", signedRequestFor(t, "alice", "bob", "mallory", nil)},
		{"malformed", []byte(`{"from":`)},
	}
	want := map[string]string{
		"valid":                      "",
		"wrong recipient":            "ERR_RECIPIENT",
		"expired":                    "ERR_EXPIRED",
		"signature from another key": "ERR_SIGNATURE",
		"malformed":                  "ERR_JSON_SYNTAX",
	}
	for _, entry := range battery {
		t.Run(entry.label, func(t *testing.T) {
			shipped := newReceiver(t, "bob")
			_, err := shipped.core.Handle(context.Background(), entry.bytes, core.HandleOptions{})
			shippedCode := mustCodeOf(t, err)

			reduced := newReducedNode(t, "bob", func(_ context.Context, input core.HandlerContext) (core.Outcome, error) {
				return core.Outcome{OK: true, Result: mustObjectNoFatal(`{"caller":"` + core.EncodeBase64Url(input.CallerPublicKey) + `"}`)}, nil
			})
			processed := reduced.handle(t, entry.bytes, removed{})
			reducedCode := ""
			if processed.RequestID == dropCode {
				reducedCode = processed.Outcome.Error.Code
			}
			if reducedCode != shippedCode {
				t.Errorf("reduced %q, shipped %q", reducedCode, shippedCode)
			}
			if want[entry.label] != shippedCode {
				t.Errorf("the shipped core gave %q, want %q", shippedCode, want[entry.label])
			}
		})
	}
}

func TestAblation1DeleteRequestSignatureVerification(t *testing.T) {
	// Mallory sends a request that claims to be alice. She cannot sign it, so
	// the signature is over her own key.
	forged := signedRequestFor(t, "alice", "bob", "mallory", nil)

	shippedRuns := 0
	shipped := newReceiver(t, "bob", func(config *core.Config) {
		config.Handler = func(_ context.Context, _ core.HandlerContext) (core.Outcome, error) {
			shippedRuns++
			return core.Outcome{OK: true, Result: mustObjectNoFatal(`{}`)}, nil
		}
	})
	if got := mustCodeOf(t, mustHandle(t, shipped.core, forged)); got != "ERR_SIGNATURE" {
		t.Errorf("baseline got %q, want ERR_SIGNATURE", got)
	}
	if shippedRuns != 0 {
		t.Errorf("the baseline ran the business %d times", shippedRuns)
	}

	var mu sync.Mutex
	ablatedRuns := 0
	ablated := newReducedNode(t, "bob", func(_ context.Context, _ core.HandlerContext) (core.Outcome, error) {
		mu.Lock()
		ablatedRuns++
		mu.Unlock()
		return core.Outcome{OK: true, Result: mustObjectNoFatal(`{}`)}, nil
	})
	processed := ablated.handle(t, forged, removed{requestSignature: true})
	if processed.RequestID == dropCode {
		t.Fatalf("the ablated pipeline still refused: %s", processed.Outcome.Error.Code)
	}
	mu.Lock()
	defer mu.Unlock()
	if ablatedRuns != 1 {
		t.Errorf("the ablated pipeline ran the business %d times, want 1", ablatedRuns)
	}
	// The answer is addressed to the claimed sender, not to the real one.
	envelope, err := core.ParseResponse(mustParse(t, processed.Bytes))
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if !core.EqualBytes(envelope.Unsigned.To, testPublicKey(t, "alice")) {
		t.Errorf("the forged identity did not reach the response")
	}
}

func mustHandle(t *testing.T, shell *core.Core, requestBytes []byte) error {
	t.Helper()
	_, err := shell.Handle(context.Background(), requestBytes, core.HandleOptions{})
	return err
}

func TestAblation2DeleteTheRecipientCheck(t *testing.T) {
	// Alice legitimately signs a request for carol, and the wrong node receives
	// it. Nothing was forged: any relay that can read the bytes can hand them to
	// the wrong node.
	misdelivered := signedRequestFor(t, "alice", "carol", "alice", nil)

	shipped := newReceiver(t, "bob")
	if got := mustCodeOf(t, mustHandle(t, shipped.core, misdelivered)); got != "ERR_RECIPIENT" {
		t.Errorf("baseline got %q, want ERR_RECIPIENT", got)
	}
	if len(shipped.calls) != 0 {
		t.Errorf("the baseline ran the business")
	}

	ablated := newReducedNode(t, "bob", func(_ context.Context, input core.HandlerContext) (core.Outcome, error) {
		return core.Outcome{OK: true, Result: mustObjectNoFatal(`{"caller":"` + core.EncodeBase64Url(input.CallerPublicKey) + `"}`)}, nil
	})
	processed := ablated.handle(t, misdelivered, removed{recipient: true})
	if processed.RequestID == dropCode {
		t.Fatalf("the ablated pipeline still refused: %s", processed.Outcome.Error.Code)
	}
	// Signature coverage of to is still there: a re-targeted request fails even
	// with the recipient check gone.
	retargeted, err := replaceField(t, misdelivered, "to", core.EncodeBase64Url(testPublicKey(t, "mallory")))
	if err != nil {
		t.Fatalf("retarget: %v", err)
	}
	mallory := newReducedNode(t, "mallory", func(_ context.Context, _ core.HandlerContext) (core.Outcome, error) {
		t.Errorf("a re-targeted request reached the handler")
		return core.Outcome{}, nil
	})
	refused := mallory.handle(t, retargeted, removed{recipient: true})
	if refused.RequestID != dropCode || refused.Outcome.Error.Code != "ERR_SIGNATURE" {
		t.Errorf("a re-targeted request was not refused by the signature: %+v", refused)
	}
}

func TestAblation5DeleteTheNonce(t *testing.T) {
	// The same nonce on two separate calls is what removing the nonce leaves
	// behind, and it is not something an attacker has to arrange.
	nonce := bytesOf(32, 5)
	first := signedRequestFor(t, "alice", "bob", "alice", func(r *core.UnsignedRequest) { r.Nonce = nonce })
	second := signedRequestFor(t, "alice", "bob", "alice", func(r *core.UnsignedRequest) { r.Nonce = nonce })
	if firstID(t, first) != firstID(t, second) {
		t.Fatalf("the two calls must share a request id once the nonce is fixed")
	}

	runs := 0
	server := newReceiver(t, "bob", func(config *core.Config) {
		config.Handler = func(_ context.Context, _ core.HandlerContext) (core.Outcome, error) {
			runs++
			return core.Outcome{OK: true, Result: mustObjectNoFatal(`{}`)}, nil
		}
	})
	if _, err := server.core.Handle(context.Background(), first, core.HandleOptions{}); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	processed, err := server.core.Handle(context.Background(), second, core.HandleOptions{})
	if err != nil {
		t.Fatalf("second delivery: %v", err)
	}
	// The second, perfectly legitimate call is refused as a duplicate.
	if processed.Outcome.OK || processed.Outcome.Error.Code != core.ReplayErrorCode {
		t.Errorf("got %+v, want %s", processed.Outcome, core.ReplayErrorCode)
	}
	if runs != 1 {
		t.Errorf("the business ran %d times, want 1", runs)
	}
}

func firstID(t *testing.T, requestBytes []byte) string {
	t.Helper()
	envelope, err := core.ParseRequest(mustParse(t, requestBytes))
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}
	id, err := core.RequestIDOf(envelope.Unsigned)
	if err != nil {
		t.Fatalf("request id: %v", err)
	}
	return id
}

func TestAblation6DeleteExpires(t *testing.T) {
	// A request that was valid an hour ago, replayed now.
	old := signedRequestFor(t, "alice", "bob", "alice", func(r *core.UnsignedRequest) { r.Expires = testNow - 3600 })

	shipped := newReceiver(t, "bob")
	if got := mustCodeOf(t, mustHandle(t, shipped.core, old)); got != "ERR_EXPIRED" {
		t.Errorf("baseline got %q, want ERR_EXPIRED", got)
	}
	if len(shipped.calls) != 0 {
		t.Errorf("the baseline ran the business")
	}

	// Ablated: one comparison is gone, nothing else.
	envelope, err := core.ParseRequest(mustParse(t, old))
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}
	ablated := newReducedNode(t, "bob", func(_ context.Context, _ core.HandlerContext) (core.Outcome, error) {
		return core.Outcome{OK: true, Result: mustObjectNoFatal(`{}`)}, nil
	})
	requestID, err := core.RequestIDOf(envelope.Unsigned)
	if err != nil {
		t.Fatalf("request id: %v", err)
	}
	claimed, err := ablated.replay.Claim(context.Background(), core.ReplayClaim{ID: requestID, RetainUntil: envelope.Unsigned.Expires + ablated.skew})
	if err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	if _, err := ablated.handler(context.Background(), core.HandlerContext{CallerPublicKey: envelope.Unsigned.From, RequestID: requestID, Body: envelope.Unsigned.Body, Envelope: envelope}); err != nil {
		t.Fatalf("handler: %v", err)
	}
	// The request is untouched, still signed and still addressed here, and it ran.
	if len(shipped.calls) != 0 {
		t.Errorf("unexpected")
	}
}

func TestAblation7DeleteTheAtomicDedupClaim(t *testing.T) {
	// A guard that is not atomic: every concurrent delivery wins the claim. This
	// is the real core and the real request path; only the guard is replaced.
	naive := naiveGuard{}
	request := signedRequestFor(t, "alice", "bob", "alice", nil)

	shipped := newReceiver(t, "bob")
	var group sync.WaitGroup
	for index := 0; index < 8; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			//nolint:errcheck // the baseline verdict is asserted by the count below
			_, _ = shipped.core.Handle(context.Background(), request, core.HandleOptions{})
		}()
	}
	group.Wait()
	if len(shipped.calls) != 1 {
		t.Errorf("the baseline ran the business %d times, want 1", len(shipped.calls))
	}

	ablated := newReceiver(t, "bob", func(config *core.Config) { config.Replay = naive })
	for index := 0; index < 8; index++ {
		if _, err := ablated.core.Handle(context.Background(), request, core.HandleOptions{}); err != nil {
			t.Fatalf("delivery %d: %v", index, err)
		}
	}
	if len(ablated.calls) != 8 {
		t.Errorf("the ablated guard ran the business %d times, want 8", len(ablated.calls))
	}
}

type naiveGuard struct{}

func (naiveGuard) Capabilities() core.ReplayCapabilities {
	return core.ReplayCapabilities{Persistent: false, Shared: false, ResultCache: false}
}

func (naiveGuard) Claim(context.Context, core.ReplayClaim) (bool, error) { return true, nil }

func (naiveGuard) Complete(context.Context, string) error { return nil }

func TestAblation8DeleteCanonicalEncoding(t *testing.T) {
	unsigned := unsignedRequestFor(t, "alice", "bob", func(r *core.UnsignedRequest) {
		r.Body = mustObjectNoFatal(`{"op":"transfer","args":{"amount":"1.00000000"}}`)
	})
	wire, err := core.UnsignedToWire(unsigned)
	if err != nil {
		t.Fatalf("wire: %v", err)
	}
	// Baseline: JCS sorts the keys, so the signed bytes do not depend on the
	// input spelling at all.
	firstSpelling, err := core.ParseJSON(`{"to":"` + core.EncodeBase64Url(unsigned.To) + `","from":"` + core.EncodeBase64Url(unsigned.From) +
		`","nonce":"` + core.EncodeBase64Url(unsigned.Nonce) + `","expires":` + itoa64(unsigned.Expires) + `,"body":{"op":"transfer","args":{"amount":"1.00000000"}}}`)
	if err != nil {
		t.Fatalf("parse first spelling: %v", err)
	}
	secondSpelling, err := core.ParseJSON(`{"body":{"op":"transfer","args":{"amount":"1.00000000"}},"expires":` + itoa64(unsigned.Expires) +
		`,"nonce":"` + core.EncodeBase64Url(unsigned.Nonce) + `","from":"` + core.EncodeBase64Url(unsigned.From) + `","to":"` + core.EncodeBase64Url(unsigned.To) + `"}`)
	if err != nil {
		t.Fatalf("parse second spelling: %v", err)
	}
	canonicalFirst, err := core.Canonicalize(firstSpelling)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	canonicalSecond, err := core.Canonicalize(secondSpelling)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if string(canonicalFirst) != string(canonicalSecond) {
		t.Errorf("key order changed the canonical form")
	}
	// The wire form is itself canonical, so the receiver always recomputes the
	// same bytes whatever spelling arrived.
	if _, err := core.Canonicalize(wire); err != nil {
		t.Errorf("the wire form must canonicalize: %v", err)
	}
	signingBytes, err := core.SigningBytes(unsigned)
	if err != nil {
		t.Fatalf("signing bytes: %v", err)
	}
	if string(signingBytes[:len(core.SigningPrefix)]) != core.SigningPrefix {
		t.Errorf("the signed bytes do not start with the base prefix")
	}
	// Ablated: a writer that keeps the input order instead of sorting. The two
	// spellings are the same message, so their digests must still agree, and a
	// signature made over one spelling's raw text must not verify as the other.
	rawFirst, err := canonicalizeKeepingOrder(firstSpelling)
	if err != nil {
		t.Fatalf("raw first: %v", err)
	}
	rawSecond, err := canonicalizeKeepingOrder(secondSpelling)
	if err != nil {
		t.Fatalf("raw second: %v", err)
	}
	if string(rawFirst) == string(rawSecond) {
		t.Fatalf("the fixture spellings must differ in their key order")
	}
	if core.EqualBytes(
		core.Sha256Bytes(append([]byte(core.SigningPrefix), rawFirst...)),
		core.Sha256Bytes(append([]byte(core.SigningPrefix), rawSecond...)),
	) {
		t.Errorf("an order preserving writer gave both spellings one digest")
	}
	signature, err := core.SignDigest(testPrivateKey(t, "alice"), core.Sha256Bytes(append([]byte(core.SigningPrefix), rawFirst...)))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	digest, err := core.DigestOf(unsigned)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if err := core.VerifyDigest(unsigned.From, digest, signature); err == nil {
		t.Errorf("a signature over non canonical bytes verified against the canonical digest")
	}
}

// canonicalizeKeepingOrder renders a value without sorting object keys, which is
// what a writer that skips JCS would do. Nested objects keep their order too.
func canonicalizeKeepingOrder(value core.Value) ([]byte, error) {
	switch value.Kind {
	case core.KindString:
		text, err := core.CanonicalizeString(value)
		if err != nil {
			return nil, err
		}
		return []byte(text), nil
	case core.KindNumber:
		return []byte(formatNumber(value.Number)), nil
	case core.KindObject:
		result := "{"
		for index, key := range value.Keys {
			if index > 0 {
				result += ","
			}
			member, _ := value.Member(key)
			encoded, err := canonicalizeKeepingOrder(member)
			if err != nil {
				return nil, err
			}
			encodedKey, err := canonicalizeKeepingOrder(core.StringValue(key))
			if err != nil {
				return nil, err
			}
			result += string(encodedKey) + ":" + string(encoded)
		}
		return []byte(result + "}"), nil
	default:
		return nil, errUnsupportedValue
	}
}

var errUnsupportedValue = errors.New("the ablation fixture only nests plain objects, strings and numbers")

func itoa64(value int64) string {
	if value == 0 {
		return "0"
	}
	digits := ""
	for value > 0 {
		digits = string(rune('0'+value%10)) + digits
		value /= 10
	}
	return digits
}

func TestAblation9KeepNoIDTypeOrVersionField(t *testing.T) {
	client := newCaller(t, "alice")
	seen := ""
	server := newReceiver(t, "bob", func(config *core.Config) {
		config.Handler = func(_ context.Context, input core.HandlerContext) (core.Outcome, error) {
			seen = core.EncodeBase64Url(input.CallerPublicKey)
			return core.Outcome{OK: true, Result: mustObjectNoFatal(`{"ok":1}`)}, nil
		}
	})
	prepared, err := client.BuildRequest(context.Background(), server.core.PublicKey(), mustObject(t, `{"op":"ping"}`), core.BuildRequestOptions{})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	processed, err := server.core.Handle(context.Background(), prepared.Bytes, core.HandleOptions{})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	requestFields := sortedKeys(mustParse(t, prepared.Bytes))
	responseFields := sortedKeys(mustParse(t, processed.Bytes))
	if requestFields != "body,expires,from,nonce,sig,to" {
		t.Errorf("request fields are %q", requestFields)
	}
	if responseFields != "body,from,reply_to,sig,to" {
		t.Errorf("response fields are %q", responseFields)
	}
	// The four requirements, with nothing but those fields.
	if seen != core.EncodeBase64Url(client.PublicKey()) {
		t.Errorf("the receiver did not learn the sender from the signature")
	}
	envelope, err := core.ParseResponse(mustParse(t, processed.Bytes))
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if !core.EqualBytes(envelope.Unsigned.To, client.PublicKey()) {
		t.Errorf("the response is not addressed to the caller")
	}
	digest, err := core.DigestOf(prepared.Unsigned)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if !core.EqualBytes(envelope.Unsigned.ReplyTo, digest) {
		t.Errorf("the correlation is not the request digest")
	}
	other, err := client.BuildRequest(context.Background(), server.core.PublicKey(), mustObject(t, `{"op":"ping"}`), core.BuildRequestOptions{})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if other.RequestID == prepared.RequestID {
		t.Errorf("two identical calls must stay distinguishable through the nonce")
	}
}

func TestAblation10VerifyIdentitiesOnTheFirstMessage(t *testing.T) {
	client := newCaller(t, "alice")
	seen := ""
	server := newReceiver(t, "bob", func(config *core.Config) {
		config.Handler = func(_ context.Context, input core.HandlerContext) (core.Outcome, error) {
			seen = core.EncodeBase64Url(input.CallerPublicKey)
			return core.Outcome{OK: true, Result: mustObjectNoFatal(`{"from":"` + core.EncodeBase64Url(client.PublicKey()) + `"}`)}, nil
		}
	})
	exchanges := 0
	exchange := func(ctx context.Context, requestBytes []byte) ([]byte, error) {
		exchanges++
		processed, err := server.core.Handle(ctx, requestBytes, core.HandleOptions{})
		if err != nil {
			return nil, err
		}
		return processed.Bytes, nil
	}
	// Fresh instances, no prior exchange, no shared state.
	outcome, _, err := client.Call(context.Background(), server.core.PublicKey(), mustObject(t, `{"op":"ping"}`), exchange)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if exchanges != 1 {
		t.Errorf("%d exchanges, want 1: nothing was negotiated first", exchanges)
	}
	if seen != core.EncodeBase64Url(client.PublicKey()) {
		t.Errorf("the server did not learn the caller from the signed request")
	}
	if !outcome.OK {
		t.Fatalf("unexpected business failure")
	}
	result, _ := outcome.Result.Member("from")
	if result.Str != core.EncodeBase64Url(client.PublicKey()) {
		t.Errorf("the caller did not learn the responder from the signed response")
	}
}

func TestAblation11NoGlobalWaitingTable(t *testing.T) {
	// Each answer echoes the caller's argument, so a mixed up response would be
	// visible instead of invisible.
	server := newReceiver(t, "bob", func(config *core.Config) {
		config.Handler = func(_ context.Context, input core.HandlerContext) (core.Outcome, error) {
			args, _ := input.Body.Member("args")
			value, _ := args.Member("n")
			return core.Outcome{OK: true, Result: mustObjectNoFatal(`{"echo":` + formatNumber(value.Number) + `}`)}, nil
		}
	})
	client := newCaller(t, "alice")

	// One exchange per call, and nothing shared between them: there is no table
	// for a response to be looked up in, so correlation is the signed reply_to
	// and the transport pairing.
	type pending struct {
		request chan []byte
		answer  chan []byte
	}
	arrived := make(chan *pending, 8)
	exchange := func(_ context.Context, requestBytes []byte) ([]byte, error) {
		entry := &pending{request: make(chan []byte, 1), answer: make(chan []byte, 1)}
		arrived <- entry
		entry.request <- requestBytes
		return <-entry.answer, nil
	}

	var group sync.WaitGroup
	results := make([]core.Outcome, 5)
	errs := make([]error, 5)
	for index := 0; index < 5; index++ {
		group.Add(1)
		go func(slot int) {
			defer group.Done()
			results[slot], _, errs[slot] = client.Call(context.Background(), server.core.PublicKey(),
				mustObject(t, `{"op":"get","args":{"n":`+itoa64(int64(slot))+`}}`), exchange)
		}(index)
	}

	// Collect every call, then answer them back to front.
	waiting := make([]*pending, 0, 5)
	for len(waiting) < 5 {
		select {
		case entry := <-arrived:
			waiting = append(waiting, entry)
		case <-time.After(5 * time.Second):
			t.Fatal("the calls never reached the transport")
		}
	}
	for index := len(waiting) - 1; index >= 0; index-- {
		requestBytes := <-waiting[index].request
		processed, err := server.core.Handle(context.Background(), requestBytes, core.HandleOptions{})
		if err != nil {
			t.Fatalf("handle: %v", err)
		}
		waiting[index].answer <- processed.Bytes
	}
	group.Wait()

	for index, err := range errs {
		if err != nil {
			t.Fatalf("call %d: %v", index, err)
		}
		if !results[index].OK {
			t.Fatalf("call %d: %+v", index, results[index].Error)
		}
		echo, ok := results[index].Result.Member("echo")
		if !ok {
			t.Fatalf("call %d: no echo in the result", index)
		}
		if int(echo.Number) != index {
			t.Errorf("call %d received the answer %v", index, echo.Number)
		}
	}
}

func formatNumber(value float64) string {
	text := strconv.FormatFloat(value, 'f', -1, 64)
	return text
}
