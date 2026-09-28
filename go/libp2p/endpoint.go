// Package libp2p adapts the shell to an authenticated libp2p stream.
//
// One request and one response per stream, framed with the upstream uvarint
// tool. WebSocket and WebRTC Direct are two different libp2p transports
// underneath; the same signed shell has to work over both, and this package does
// not know which one it is running on.
package libp2p

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/bsv8/bitcoin-libp2p/golibp2p"
	"github.com/bsv8/bitcoin-libp2p/identity"
	"github.com/bsv8/bitcoin-libp2p/streamio"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/bsv8/roundtrip/go/core"
)

// Protocol is the fixed application protocol. roundtrip registers exactly this
// one and opens a stream per call.
const Protocol = "/roundtrip/1"

// DefaultMaxFrameBytes is the local inbound frame limit. The core applies the
// message limit as well, so this only has to be a little larger than it.
const DefaultMaxFrameBytes = 1024*1024 + 16

// DefaultTimeout bounds how long one inbound request may take to arrive
// complete, and how long one call waits.
const DefaultTimeout = 15 * time.Second

// Options configures both directions.
type Options struct {
	// Protocol overrides the fixed application protocol.
	Protocol string
	// MaxFrameBytes is the local inbound frame limit.
	MaxFrameBytes int
	// Timeout bounds one exchange in either direction.
	Timeout time.Duration
}

func (o Options) protocol() string {
	if o.Protocol == "" {
		return Protocol
	}
	return o.Protocol
}

func (o Options) maxFrameBytes() int {
	if o.MaxFrameBytes <= 0 {
		return DefaultMaxFrameBytes
	}
	return o.MaxFrameBytes
}

func (o Options) timeout() time.Duration {
	if o.Timeout <= 0 {
		return DefaultTimeout
	}
	return o.Timeout
}

// Service is a registered protocol handler.
type Service struct {
	host     host.Host
	protocol protocol.ID
}

// Unregister stops serving the protocol. Streams already open are unaffected.
func (s *Service) Unregister() error {
	s.host.RemoveStreamHandler(s.protocol)
	return nil
}

// Serve registers the handler: open stream, read one frame, answer with one
// frame, close the stream.
//
// The stream is not reused for a second call, and a second frame on the same
// stream is a protocol error rather than a new request. Reading to the end of
// the caller's write side is what makes a second frame detectable, so a caller
// that never half closes is bounded by the timeout instead of hanging here.
func Serve(h host.Host, shell *core.Core, options Options) (*Service, error) {
	if h == nil {
		return nil, errors.New("host must not be nil")
	}
	if shell == nil {
		return nil, errors.New("core must not be nil")
	}
	id := protocol.ID(options.protocol())
	maxFrame := options.maxFrameBytes()
	timeout := options.timeout()
	h.SetStreamHandler(id, func(stream network.Stream) {
		go serveStream(stream, shell, maxFrame, timeout)
	})
	return &Service{host: h, protocol: id}, nil
}

func serveStream(stream network.Stream, shell *core.Core, maxFrame int, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// A context cannot interrupt a read that is already parked in the muxer, so
	// the deadline is pushed into the stream itself. Without this a peer that
	// keeps the stream open and sends nothing would hold the stream forever.
	defer boundStream(ctx, stream)()

	// Connection authentication is not message verification: the core still
	// verifies the signature, and it also requires that the request From is
	// exactly this authenticated peer.
	peer, err := golibp2p.AuthenticatedPeerFromConn(stream.Conn(), nil)
	if err != nil {
		abortQuietly(stream, err)
		return
	}
	framer, err := streamio.NewUvarintFramer(stream, streamio.WithMaxInboundFrameBytes(maxFrame))
	if err != nil {
		abortQuietly(stream, err)
		return
	}
	first, err := framer.ReadFrame()
	if err != nil {
		// A clean EOF before any frame is a truncated call, not an answer, and a
		// deadline means the peer never finished sending. Both release the stream.
		abortQuietly(stream, err)
		return
	}
	// A second frame on one stream is a protocol error, not a new request.
	if _, err := framer.ReadFrame(); !errors.Is(err, io.EOF) {
		abortQuietly(stream, errors.New("a stream must carry exactly one request and one response"))
		return
	}
	processed, err := shell.Handle(ctx, first, core.HandleOptions{CallerPublicKey: peer.PublicKey})
	if err != nil {
		abortQuietly(stream, err)
		return
	}
	if err := framer.WriteFrame(processed.Bytes); err != nil {
		abortQuietly(stream, err)
		return
	}
	_ = stream.Close()
}

// Exchange builds the one-shot exchange for one peer.
//
// The target is the 33-byte business public key. The PeerId used for dialling is
// derived with the upstream native helper, never hand assembled. Before the call
// the authenticated remote public key of the connection must equal the target,
// so a relayed or wrong connection cannot answer a call addressed to someone
// else.
func Exchange(h host.Host, to []byte, options Options) (core.Exchange, error) {
	if h == nil {
		return nil, errors.New("host must not be nil")
	}
	if err := core.ValidatePublicKey(to); err != nil {
		return nil, err
	}
	peerID, err := identity.PeerIDFromPublicKey(to)
	if err != nil {
		return nil, err
	}
	pin, err := golibp2p.NewPin(to, peerID)
	if err != nil {
		return nil, err
	}
	id := protocol.ID(options.protocol())
	maxFrame := options.maxFrameBytes()
	timeout := options.timeout()

	return func(parent context.Context, requestBytes []byte) ([]byte, error) {
		ctx, cancel := context.WithTimeout(parent, timeout)
		defer cancel()

		if err := h.Connect(ctx, peer.AddrInfo{ID: peerID}); err != nil {
			return nil, &core.Error{Code: core.ErrTransport, Err: err}
		}
		stream, err := h.NewStream(ctx, peerID, id)
		if err != nil {
			return nil, &core.Error{Code: core.ErrTransport, Err: err}
		}
		defer stream.Close()
		// The response read below parks in the muxer, where a context cannot
		// reach it, so the deadline goes into the stream and an early cancellation
		// resets it. Otherwise a peer that accepts the request and never answers
		// would hold the stream and the call for ever.
		defer boundStream(ctx, stream)()
		// A connection authenticated as somebody else must never answer a call
		// addressed to the target identity. The check runs on the connection that
		// actually carries this stream, not on one guessed beforehand.
		if _, err := golibp2p.AuthenticatedPeerFromConn(stream.Conn(), &pin); err != nil {
			_ = stream.Reset()
			return nil, &core.Error{Code: core.ErrTransport, Err: err}
		}
		framer, err := streamio.NewUvarintFramer(stream, streamio.WithMaxInboundFrameBytes(maxFrame))
		if err != nil {
			return nil, &core.Error{Code: core.ErrTransport, Err: err}
		}
		if err := framer.WriteFrame(requestBytes); err != nil {
			return nil, &core.Error{Code: core.ErrTransport, Err: err}
		}
		// Half close after the one request frame. The read side stays open for
		// the response, and the responder now knows the request is complete.
		if err := stream.CloseWrite(); err != nil {
			return nil, &core.Error{Code: core.ErrTransport, Err: err}
		}
		response, err := framer.ReadFrame()
		if err != nil {
			switch {
			case timedOut(ctx, err):
				// The call deadline passed with no response frame. The stream is
				// reset by the deferred cleanup.
				return nil, &core.Error{Code: core.ErrCallTimeout, Err: err}
			case errors.Is(err, io.EOF), errors.Is(err, streamio.ErrFrameTruncated):
				return nil, &core.Error{Code: core.ErrFrame, Err: errors.New("stream closed before a response frame arrived")}
			default:
				return nil, &core.Error{Code: core.ErrTransport, Err: err}
			}
		}
		return response, nil
	}, nil
}

// boundStream makes a blocking read or write obey ctx.
//
// A cancelled context does not interrupt a read that is already parked in the
// muxer, so the deadline is pushed into the stream. A cancellation without a
// deadline is covered by resetting the stream, which unblocks the reader. The
// returned function stops the watcher.
func boundStream(ctx context.Context, stream network.Stream) (stop func()) {
	if deadline, ok := ctx.Deadline(); ok {
		//nolint:errcheck // a transport that cannot carry a deadline still gets the reset path below
		stream.SetDeadline(deadline)
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = stream.Reset()
		case <-done:
		}
	}()
	var once bool
	return func() {
		if once {
			return
		}
		once = true
		close(done)
	}
}

// timedOut reports whether a stream failure was the bound deadline rather than
// the peer.
//
// The context is the authority: a read is bound to it, so a read that fails while
// the context is already done failed because of the deadline. The error checks
// are a fallback for a transport that reports the deadline itself, because the
// muxer is not obliged to use any particular error type.
func timedOut(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx.Err() != nil {
		return true
	}
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func abortQuietly(stream network.Stream, cause error) {
	if cause == nil {
		cause = errors.New("stream aborted")
	}
	_ = stream.Reset()
}
