package libp2p_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/bsv8/bitcoin-libp2p/golibp2p"
	"github.com/bsv8/bitcoin-libp2p/identity"
	"github.com/bsv8/bitcoin-libp2p/signer"
	"github.com/bsv8/bitcoin-libp2p/streamio"
	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/connmgr"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/pnet"
	libp2ptransport "github.com/libp2p/go-libp2p/core/transport"
	libp2pwebrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	libp2pwebsocket "github.com/libp2p/go-libp2p/p2p/transport/websocket"
	ma "github.com/multiformats/go-multiaddr"

	roundtriplibp2p "github.com/bsv8/roundtrip/go/libp2p"

	"github.com/bsv8/roundtrip/go/core"
)

// Stage 4 on real transports. WebSocket and WebRTC Direct are two different
// libp2p transports underneath, and the same signed shell has to work over both.
// Nothing here is simulated: every test opens a real TCP socket or a real local
// UDP port.

const testTimeout = 60 * time.Second

const (
	testExpires = 1790000000
	testNow     = testExpires - 5
)

var testKeyHex = map[string]string{
	"alice": "1111111111111111111111111111111111111111111111111111111111111111",
	"bob":   "2222222222222222222222222222222222222222222222222222222222222222",
	"carol": "3333333333333333333333333333333333333333333333333333333333333333",
}

func testPrivateKey(name string) []byte {
	return core.MustHexToBytes(testKeyHex[name])
}

func testPublicKey(t *testing.T, name string) []byte {
	t.Helper()
	publicKey, err := core.PublicKeyFromPrivateKey(testPrivateKey(name))
	if err != nil {
		t.Fatalf("public key for %s: %v", name, err)
	}
	return publicKey
}

type harness struct {
	serverHost  host.Host
	clientHost  host.Host
	server      *core.Core
	caller      *core.Core
	transport   string
	timeout     time.Duration
	calls       int
	mu          sync.Mutex
	stopServing func()
}

// newHarness wires one pair of nodes the way the construction order requires: the
// application holds the key and configures both the upstream identity and the
// roundtrip signer with it.
func newHarness(t *testing.T, transportName string, options ...func(*harnessConfig)) *harness {
	t.Helper()
	config := harnessConfig{serverName: "bob", clientName: "alice", clientTransportName: "alice", timeout: 10 * time.Second}
	for _, option := range options {
		option(&config)
	}
	result := &harness{transport: transportName, timeout: config.timeout}

	serverShell, err := core.New(core.Config{
		Signer: mustSigner(t, config.serverName),
		Now:    func() int64 { return testNow },
		Handler: func(_ context.Context, input core.HandlerContext) (core.Outcome, error) {
			result.mu.Lock()
			result.calls++
			result.mu.Unlock()
			return core.Outcome{OK: true, Result: input.Body}, nil
		},
	})
	if err != nil {
		t.Fatalf("server core: %v", err)
	}
	result.server = serverShell
	result.caller, err = core.New(core.Config{
		Signer:      mustSigner(t, config.clientName),
		Now:         func() int64 { return testNow },
		RandomBytes: func(length int) ([]byte, error) { return make([]byte, length), nil },
	})
	if err != nil {
		t.Fatalf("caller core: %v", err)
	}

	// The roundtrip business identity has to be derivable from the same key the
	// upstream host is configured with, otherwise the two identities disagree.
	probe, err := signer.NewLocalSigner(testPrivateKey(config.serverName))
	if err != nil {
		t.Fatalf("upstream signer: %v", err)
	}
	if core.EncodeBase64Url(probe.PublicKey()) != core.EncodeBase64Url(serverShell.PublicKey()) {
		t.Fatalf("the transport identity and the business identity must be the same key")
	}

	// The host is built by the upstream SDK, which owns the identity adapter,
	// Noise, Yamux and Identify. This test only chooses the transport, so the
	// raw private key never reaches go-libp2p.
	serverUpstreamSigner, err := signer.NewLocalSigner(testPrivateKey(config.serverName))
	if err != nil {
		t.Fatalf("upstream signer: %v", err)
	}
	clientUpstreamSigner, err := signer.NewLocalSigner(testPrivateKey(config.clientTransportName))
	if err != nil {
		t.Fatalf("upstream signer: %v", err)
	}
	listen, transports, err := transportOptions(transportName)
	if err != nil {
		t.Fatalf("transport options: %v", err)
	}
	serverHost, err := golibp2p.NewHost(golibp2p.HostConfig{
		Signer:           serverUpstreamSigner,
		ListenAddrs:      []ma.Multiaddr{listen},
		TransportOptions: transports,
	})
	if err != nil {
		t.Fatalf("server host: %v", err)
	}
	t.Cleanup(func() { _ = serverHost.Close() })
	result.serverHost = serverHost

	clientHost, err := golibp2p.NewHost(golibp2p.HostConfig{
		Signer:           clientUpstreamSigner,
		TransportOptions: transports,
	})
	if err != nil {
		t.Fatalf("client host: %v", err)
	}
	t.Cleanup(func() { _ = clientHost.Close() })
	result.clientHost = clientHost

	service, err := roundtriplibp2p.Serve(serverHost, serverShell, roundtriplibp2p.Options{Timeout: config.timeout})
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	result.stopServing = func() { _ = service.Unregister() }

	// The adapter dials by business public key, so the address of the node that
	// owns that key has to be discoverable. In production that comes from a
	// directory, a peer record, or a peer seen before.
	peerID, err := peerIDOf(serverShell.PublicKey())
	if err != nil {
		t.Fatalf("peer id: %v", err)
	}
	for _, address := range serverHost.Addrs() {
		clientHost.Peerstore().AddAddrs(peerID, []ma.Multiaddr{address}, time.Hour)
	}
	return result
}

type harnessConfig struct {
	serverName          string
	clientName          string
	clientTransportName string
	maxMessageBytes     int
	// timeout bounds one exchange in either direction, so a stall can be tested
	// without waiting for the default.
	timeout time.Duration
}

func mustSigner(t *testing.T, name string) core.Signer {
	t.Helper()
	signer, err := core.NewLocalSigner(testPrivateKey(name))
	if err != nil {
		t.Fatalf("signer for %s: %v", name, err)
	}
	return signer
}

// transportOptions picks the libp2p transport. Everything else about the host is
// the upstream SDK's business.
func transportOptions(transportName string) (ma.Multiaddr, []libp2p.Option, error) {
	switch transportName {
	case "websocket":
		listen, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/0/ws")
		if err != nil {
			return nil, nil, err
		}
		return listen, []libp2p.Option{libp2p.Transport(libp2pwebsocket.New)}, nil
	case "webrtc-direct":
		listen, err := ma.NewMultiaddr("/ip4/127.0.0.1/udp/0/webrtc-direct")
		if err != nil {
			return nil, nil, err
		}
		// go-libp2p's WebRTC constructor derives its DTLS certificate from
		// PrivKey.Raw(), which the upstream identity adapter deliberately refuses
		// to return. The upstream requirements document therefore assigns Go
		// WebRTC Direct transport assembly to the application, and this is that
		// arrangement: the host, the Noise identity, Yamux and Identify still
		// come from the SDK, and only Raw() is replaced so the certificate is
		// bound to throwaway material instead of the business key.
		return listen, []libp2p.Option{libp2p.Transport(webRTCTransportWithThrowawayCertificate)}, nil
	default:
		return nil, nil, errUnsupportedTransport(transportName)
	}
}

func (h *harness) exchange(t *testing.T) core.Exchange {
	t.Helper()
	exchange, err := h.exchangeWith(t, h.server.PublicKey(), roundtriplibp2p.Options{Timeout: h.timeout})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return exchange
}

// exchangeWith dials an arbitrary business identity, used by the tests that need
// a peer other than the harness responder.
func (h *harness) exchangeWith(t *testing.T, to []byte, options roundtriplibp2p.Options) (core.Exchange, error) {
	t.Helper()
	return roundtriplibp2p.Exchange(h.clientHost, to, options)
}

func (h *harness) handlerCalls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

var transports = []string{"websocket", "webrtc-direct"}

func TestLibp2pRoundTrip(t *testing.T) {
	for _, transportName := range transports {
		t.Run(transportName, func(t *testing.T) {
			h := newHarness(t, transportName)
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			outcome, _, err := h.caller.Call(ctx, h.server.PublicKey(), mustObject(t, `{"op":"get_balance","args":{"asset":"BSV"}}`), h.exchange(t))
			if err != nil {
				t.Fatalf("call: %v", err)
			}
			if !outcome.OK {
				t.Fatalf("unexpected business failure: %+v", outcome.Error)
			}
			if h.handlerCalls() != 1 {
				t.Errorf("the handler ran %d times, want 1", h.handlerCalls())
			}
		})
	}
}

func TestLibp2pConcurrentCallsUseSeparateStreams(t *testing.T) {
	for _, transportName := range transports {
		t.Run(transportName, func(t *testing.T) {
			h := newHarness(t, transportName)
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			exchange := h.exchange(t)
			var group sync.WaitGroup
			errs := make([]error, 4)
			ids := make([]string, 4)
			for index := 0; index < 4; index++ {
				group.Add(1)
				go func(slot int) {
					defer group.Done()
					prepared, err := h.caller.BuildRequest(ctx, h.server.PublicKey(), mustObject(t, `{"op":"op_`+string(rune('0'+slot))+`"}`), core.BuildRequestOptions{})
					if err != nil {
						errs[slot] = err
						return
					}
					ids[slot] = prepared.RequestID
					outcome, err := h.caller.Send(ctx, prepared, exchange)
					if err != nil {
						errs[slot] = err
						return
					}
					if !outcome.OK {
						errs[slot] = errNotOK
					}
				}(index)
			}
			group.Wait()
			for index, err := range errs {
				if err != nil {
					t.Fatalf("call %d: %v", index, err)
				}
			}
			unique := map[string]bool{}
			for _, id := range ids {
				if unique[id] {
					t.Fatalf("two calls shared the request id %s", id)
				}
				unique[id] = true
			}
			if h.handlerCalls() != 4 {
				t.Errorf("the handler ran %d times, want 4", h.handlerCalls())
			}
		})
	}
}

func TestLibp2pDuplicateDeliveryRunsTheBusinessOnce(t *testing.T) {
	for _, transportName := range transports {
		t.Run(transportName, func(t *testing.T) {
			h := newHarness(t, transportName)
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			prepared, err := h.caller.BuildRequest(ctx, h.server.PublicKey(), mustObject(t, `{"op":"transfer","args":{"amount":"1.00000000"}}`), core.BuildRequestOptions{})
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			exchange := h.exchange(t)
			first, err := h.caller.Send(ctx, prepared, exchange)
			if err != nil || !first.OK {
				t.Fatalf("first delivery: %v %+v", err, first)
			}
			// The same bytes again: a retransmission, not a new call.
			second, err := h.caller.Send(ctx, prepared, exchange)
			if err != nil {
				t.Fatalf("second delivery: %v", err)
			}
			if second.OK || second.Error.Code != core.ReplayErrorCode {
				t.Errorf("got %+v, want %s", second, core.ReplayErrorCode)
			}
			if h.handlerCalls() != 1 {
				t.Errorf("the business ran %d times, want 1", h.handlerCalls())
			}
		})
	}
}

func TestLibp2pRefusesAForgedTransportIdentity(t *testing.T) {
	for _, transportName := range transports {
		t.Run(transportName, func(t *testing.T) {
			// The client speaks as alice at the transport layer but claims to be
			// carol in the message. Connection authentication is not message
			// identity, and the adapter requires both to agree.
			h := newHarness(t, transportName, func(config *harnessConfig) { config.clientName = "carol" })
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			exchange, err := roundtriplibp2p.Exchange(h.clientHost, h.server.PublicKey(), roundtriplibp2p.Options{})
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}
			_, _, err = h.caller.Call(ctx, h.server.PublicKey(), mustObject(t, `{"op":"get_balance"}`), exchange)
			if err == nil {
				t.Fatal("a request whose from is not the authenticated peer was answered")
			}
			if h.handlerCalls() != 0 {
				t.Errorf("the handler ran %d times, want 0", h.handlerCalls())
			}
		})
	}
}

func TestLibp2pRefusesARecipientItCannotAuthenticate(t *testing.T) {
	for _, transportName := range transports {
		t.Run(transportName, func(t *testing.T) {
			// The target is carol's business key, but the node being dialled is
			// bob. A connection authenticated as somebody else must never answer a
			// call addressed to someone else.
			h := newHarness(t, transportName)
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			exchange, err := roundtriplibp2p.Exchange(h.clientHost, testPublicKey(t, "carol"), roundtriplibp2p.Options{})
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}
			_, _, err = h.caller.Call(ctx, testPublicKey(t, "carol"), mustObject(t, `{"op":"get_balance"}`), exchange)
			if err == nil {
				t.Fatal("a call addressed to an unauthenticated peer was answered")
			}
			if h.handlerCalls() != 0 {
				t.Errorf("the handler ran %d times, want 0", h.handlerCalls())
			}
		})
	}
}

func TestLibp2pReleasesTheStreamAfterEveryCall(t *testing.T) {
	for _, transportName := range transports {
		t.Run(transportName, func(t *testing.T) {
			h := newHarness(t, transportName)
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			exchange := h.exchange(t)
			for index := 0; index < 2; index++ {
				if _, _, err := h.caller.Call(ctx, h.server.PublicKey(), mustObject(t, `{"op":"ping"}`), exchange); err != nil {
					t.Fatalf("call %d: %v", index, err)
				}
			}
			// One stream per call, and every one of them closed.
			peerID, err := peerIDOf(h.server.PublicKey())
			if err != nil {
				t.Fatalf("peer id: %v", err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				open := 0
				for _, connection := range h.clientHost.Network().ConnsToPeer(peerID) {
					for _, stream := range connection.GetStreams() {
						if stream.Stat().Direction == network.DirOutbound {
							open++
						}
					}
				}
				if open == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("%d streams are still open", open)
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}

func TestLibp2pStopsAnsweringAfterUnregister(t *testing.T) {
	h := newHarness(t, "websocket")
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	exchange := h.exchange(t)
	if _, _, err := h.caller.Call(ctx, h.server.PublicKey(), mustObject(t, `{"op":"ping"}`), exchange); err != nil {
		t.Fatalf("first call: %v", err)
	}
	h.stopServing()
	if _, _, err := h.caller.Call(ctx, h.server.PublicKey(), mustObject(t, `{"op":"ping"}`), exchange); err == nil {
		t.Fatal("the service still answered after unregistering")
	}
}

var errNotOK = errTest("a call returned a business failure")

type errTest string

func (e errTest) Error() string { return string(e) }

func errUnsupportedTransport(name string) error {
	return errTest("unsupported transport: " + name)
}

func mustObject(t *testing.T, text string) core.Value {
	t.Helper()
	value, err := core.ParseJSON(text)
	if err != nil {
		t.Fatalf("parse %s: %v", text, err)
	}
	return value
}

// peerIDOf derives the PeerId with the upstream helper, never by hand.
func peerIDOf(publicKey []byte) (peer.ID, error) {
	return identity.PeerIDFromPublicKey(publicKey)
}

// certificateOnlyKey replaces only Raw, which go-libp2p WebRTC uses to derive
// its DTLS certificate. Sign and GetPublic still delegate to the host identity,
// so the PeerId and the Noise identity are unchanged.
type certificateOnlyKey struct {
	libp2pcrypto.PrivKey
	raw []byte
}

func (key *certificateOnlyKey) Raw() ([]byte, error) {
	return append([]byte(nil), key.raw...), nil
}

// webRTCTransportWithThrowawayCertificate is the upstream sanctioned assembly for
// Go WebRTC Direct. The certificate key is a fixed test scalar and is never the
// business identity.
func webRTCTransportWithThrowawayCertificate(
	privKey libp2pcrypto.PrivKey,
	psk pnet.PSK,
	gater connmgr.ConnectionGater,
	rcmgr network.ResourceManager,
	listenUDP libp2pwebrtc.ListenUDPFn,
) (libp2ptransport.Transport, error) {
	certificateRaw := make([]byte, 32)
	certificateRaw[31] = 2
	return libp2pwebrtc.New(&certificateOnlyKey{PrivKey: privKey, raw: certificateRaw}, psk, gater, rcmgr, listenUDP)
}

// A peer that keeps a stream open and never finishes sending must not be able to
// hold the responder's stream for ever. This is the server side of the deadline.
func TestLibp2pServerTimeoutWhenTheRequestIsNeverFinished(t *testing.T) {
	const stallTimeout = 400 * time.Millisecond
	h := newHarness(t, "websocket", func(config *harnessConfig) { config.timeout = stallTimeout })

	peerID, err := peerIDOf(h.server.PublicKey())
	if err != nil {
		t.Fatalf("peer id: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	stream, err := h.clientHost.NewStream(ctx, peerID, roundtriplibp2p.Protocol)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()

	// A uvarint that promises 64 bytes, followed by only 8 of them, and then
	// nothing. The write side stays open, so a reader cannot see an EOF either.
	var prefix [1]byte
	prefix[0] = 64 // one byte uvarint
	if _, err := stream.Write(prefix[:]); err != nil {
		t.Fatalf("write prefix: %v", err)
	}
	if _, err := stream.Write(bytesOf(8, 0x41)); err != nil {
		t.Fatalf("write partial payload: %v", err)
	}

	// The responder has to give up on its own, without the caller closing
	// anything.
	started := time.Now()
	framer, err := streamio.NewUvarintFramer(stream)
	if err != nil {
		t.Fatalf("framer: %v", err)
	}
	_, err = framer.ReadFrame()
	if err == nil {
		t.Fatal("a frame arrived from a request that was never finished")
	}
	elapsed := time.Since(started)
	if elapsed > 10*stallTimeout {
		t.Errorf("the responder waited %s for an unfinished request", elapsed)
	}
	if h.handlerCalls() != 0 {
		t.Errorf("an unfinished request reached the handler %d times", h.handlerCalls())
	}
	// The stream is released rather than parked: reading again fails at once.
	if _, err := framer.ReadFrame(); err == nil {
		t.Errorf("the stream stayed open after the deadline")
	}
}

// A peer that accepts the request and never answers must not be able to hold the
// call for ever. This is the client side of the deadline.
func TestLibp2pClientTimeoutWhenTheResponseNeverArrives(t *testing.T) {
	const stallTimeout = 400 * time.Millisecond
	h := newHarness(t, "websocket")

	// A host with its own identity, so the connection check genuinely passes, and
	// which never writes a response frame.
	stalling, stallingKey, err := newStallingHost(t, "carol", "/ip4/127.0.0.1/tcp/0/ws")
	if err != nil {
		t.Fatalf("stalling host: %v", err)
	}
	defer stalling.Close()
	stallingID, err := peerIDOf(stallingKey)
	if err != nil {
		t.Fatalf("peer id: %v", err)
	}
	for _, address := range stalling.Addrs() {
		h.clientHost.Peerstore().AddAddrs(stallingID, []ma.Multiaddr{address}, time.Hour)
	}

	exchange, err := h.exchangeWith(t, stallingKey, roundtriplibp2p.Options{Timeout: stallTimeout})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	started := time.Now()
	_, _, err = h.caller.Call(context.Background(), stallingKey, mustObject(t, `{"op":"ping"}`), exchange)
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("a peer that never answered completed the call")
	}
	if code := core.CodeOf(err); code != core.ErrCallTimeout {
		t.Errorf("got %q, want ERR_CALL_TIMEOUT", code)
	}
	if elapsed > 10*stallTimeout {
		t.Errorf("the call waited %s past its %s deadline", elapsed, stallTimeout)
	}
	if h.handlerCalls() != 0 {
		t.Errorf("the real responder ran for a call addressed to somebody else")
	}
	// The stalled stream is released, not left open on the caller side.
	open := 0
	for _, connection := range h.clientHost.Network().ConnsToPeer(stallingID) {
		for _, stream := range connection.GetStreams() {
			if stream.Stat().Direction == network.DirOutbound {
				open++
			}
		}
	}
	if open != 0 {
		t.Errorf("%d streams are still open after the call timed out", open)
	}
}

// newStallingHost is a host that answers the protocol by reading one request frame
// and then never writing anything.
func newStallingHost(t *testing.T, keyName, listen string) (host.Host, []byte, error) {
	t.Helper()
	upstream, err := signer.NewLocalSigner(testPrivateKey(keyName))
	if err != nil {
		return nil, nil, err
	}
	address, err := ma.NewMultiaddr(listen)
	if err != nil {
		return nil, nil, err
	}
	h, err := golibp2p.NewHost(golibp2p.HostConfig{
		Signer:           upstream,
		ListenAddrs:      []ma.Multiaddr{address},
		TransportOptions: []libp2p.Option{libp2p.Transport(libp2pwebsocket.New)},
	})
	if err != nil {
		return nil, nil, err
	}
	h.SetStreamHandler(roundtriplibp2p.Protocol, func(stream network.Stream) {
		go func() {
			defer stream.Close()
			framer, err := streamio.NewUvarintFramer(stream)
			if err != nil {
				return
			}
			// Read the request, then hold the stream open without answering.
			//nolint:errcheck // the stall is the point of this host
			_, _ = framer.ReadFrame()
			select {}
		}()
	})
	return h, upstream.PublicKey(), nil
}

func bytesOf(length int, fill byte) []byte {
	buffer := make([]byte, length)
	for index := range buffer {
		buffer[index] = fill
	}
	return buffer
}
