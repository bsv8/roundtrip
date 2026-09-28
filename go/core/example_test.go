package core_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"time"

	"github.com/bsv8/bitcoin-libp2p/golibp2p"
	"github.com/bsv8/bitcoin-libp2p/identity"
	"github.com/bsv8/bitcoin-libp2p/signer"
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

	"github.com/bsv8/roundtrip/go/core"
	roundtriphttp "github.com/bsv8/roundtrip/go/http"
	roundtriplibp2p "github.com/bsv8/roundtrip/go/libp2p"
)

// The Go counterparts of ../../typescript/examples. They are Example functions so
// they run as tests and their printed output is checked, rather than being prose
// that can rot.
//
// Every key here is generated for the run and thrown away when it exits. Nothing
// in this file is a production key.

// ephemeralKey returns a throw away identity for a demo.
func ephemeralKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	// Keep the scalar in 1..n-1.
	key[0] = key[0]%0x7f + 1
	return key
}

func shortKey(publicKey []byte) string {
	return base64.RawURLEncoding.EncodeToString(publicKey)[:12]
}

// Example_overHTTP is the smallest useful deployment: one service and one client
// over plain HTTP. The application holds the key, and only the signer ever sees
// it.
func Example_overHTTP() {
	serviceKey := ephemeralKey()
	callerKey := ephemeralKey()

	// The application decides what a call means and who may make it.
	handle := func(_ context.Context, input core.HandlerContext) (core.Outcome, error) {
		op, _ := input.Body.Member("op")
		switch op.Str {
		case "get_balance":
			return core.Outcome{OK: true, Result: mustObjectNoFatal(`{"confirmed":42,"satoshis":"1050000000"}`)}, nil
		case "transfer":
			return core.Outcome{Error: core.BusinessError{Code: "INSUFFICIENT_FUNDS", Message: "cannot send that much"}}, nil
		default:
			// Unknown operations are a business answer, signed like any other.
			return core.Outcome{Error: core.BusinessError{Code: "UNKNOWN_OP", Message: "no such operation: " + op.Str}}, nil
		}
	}

	serviceSigner, err := core.NewLocalSigner(serviceKey)
	if err != nil {
		panic(err)
	}
	service, err := core.New(core.Config{Signer: serviceSigner, Handler: handle})
	if err != nil {
		panic(err)
	}
	server := httptest.NewServer(roundtriphttp.Handler(roundtriphttp.NewEndpoint(service, roundtriphttp.Options{}), roundtriphttp.DefaultMaxBodyBytes))
	defer server.Close()

	callerSigner, err := core.NewLocalSigner(callerKey)
	if err != nil {
		panic(err)
	}
	caller, err := core.New(core.Config{Signer: callerSigner})
	if err != nil {
		panic(err)
	}
	exchange := roundtriphttp.Exchange(server.URL+roundtriphttp.Path, roundtriphttp.ExchangeOptions{})

	report := func(label, body string) {
		outcome, _, err := caller.Call(context.Background(), service.PublicKey(), mustObjectNoFatal(body), exchange)
		switch {
		case err != nil:
			fmt.Printf("%s -> transport failure %s\n", label, core.CodeOf(err))
		case outcome.OK:
			fmt.Printf("%s -> ok %s\n", label, resultText(outcome.Result))
		default:
			fmt.Printf("%s -> business error %s\n", label, outcome.Error.Code)
		}
	}
	report("get_balance", `{"op":"get_balance","args":{"asset":"BSV"}}`)
	report("transfer   ", `{"op":"transfer","args":{"amount":"2.00000000"}}`)
	report("drop_tables", `{"op":"drop_tables"}`)

	// A retransmission keeps its request id, so the business does not run twice.
	prepared, err := caller.BuildRequest(context.Background(), service.PublicKey(), mustObjectNoFatal(`{"op":"get_balance"}`), core.BuildRequestOptions{})
	if err != nil {
		panic(err)
	}
	first, err := caller.Send(context.Background(), prepared, exchange)
	if err != nil {
		panic(err)
	}
	second, err := caller.Send(context.Background(), prepared, exchange)
	if err != nil {
		panic(err)
	}
	fmt.Printf("delivered twice -> first executed %v, second %s\n", first.OK, second.Error.Code)

	// Output:
	// get_balance -> ok {"confirmed":42,"satoshis":"1050000000"}
	// transfer    -> business error INSUFFICIENT_FUNDS
	// drop_tables -> business error UNKNOWN_OP
	// delivered twice -> first executed true, second REQUEST_ALREADY_SEEN
}

func resultText(value core.Value) string {
	text, err := core.CanonicalizeString(value)
	if err != nil {
		return ""
	}
	return text
}

// Example_overLibp2p runs the same shell over both libp2p transports. The host,
// its Noise identity, Yamux and Identify come from bitcoin-libp2p; this file only
// chooses the transport.
func Example_overLibp2p() {
	run := func(label string, listen string, transports []libp2p.Option, expect int) {
		serviceKey := ephemeralKey()
		callerKey := ephemeralKey()

		serviceSigner, err := core.NewLocalSigner(serviceKey)
		if err != nil {
			panic(err)
		}
		service, err := core.New(core.Config{
			Signer: serviceSigner,
			Handler: func(_ context.Context, input core.HandlerContext) (core.Outcome, error) {
				return core.Outcome{OK: true, Result: input.Body}, nil
			},
		})
		if err != nil {
			panic(err)
		}
		upstreamService, err := signer.NewLocalSigner(serviceKey)
		if err != nil {
			panic(err)
		}
		upstreamCaller, err := signer.NewLocalSigner(callerKey)
		if err != nil {
			panic(err)
		}
		// The transport identity and the business identity are the same key.
		sameIdentity := shortKey(upstreamService.PublicKey()) == shortKey(service.PublicKey())

		serverHost, err := newHost(upstreamService, listen, transports)
		if err != nil {
			fmt.Printf("%s -> host unavailable: %v\n", label, err)
			return
		}
		defer serverHost.Close()
		clientHost, err := newHost(upstreamCaller, "", transports)
		if err != nil {
			fmt.Printf("%s -> host unavailable: %v\n", label, err)
			return
		}
		defer clientHost.Close()

		serving, err := roundtriplibp2p.Serve(serverHost, service, roundtriplibp2p.Options{})
		if err != nil {
			panic(err)
		}
		defer serving.Unregister()

		// The adapter dials by business public key, so the address that belongs
		// to that key has to be known. A deployment gets it from a directory, a
		// peer record or a peer seen before.
		exchange, err := roundtriplibp2p.Exchange(clientHost, service.PublicKey(), roundtriplibp2p.Options{})
		if err != nil {
			panic(err)
		}
		peerID, err := peerIDFor(clientHost, service.PublicKey())
		if err != nil {
			panic(err)
		}
		for _, address := range serverHost.Addrs() {
			clientHost.Peerstore().AddAddrs(peerID, []ma.Multiaddr{address}, time.Hour)
		}

		callerSigner, err := core.NewLocalSigner(callerKey)
		if err != nil {
			panic(err)
		}
		caller, err := core.New(core.Config{Signer: callerSigner})
		if err != nil {
			panic(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		outcome, _, err := caller.Call(ctx, service.PublicKey(), mustObjectNoFatal(`{"op":"get_balance"}`), exchange)
		if err != nil {
			fmt.Printf("%s -> call failed: %v\n", label, core.CodeOf(err))
			return
		}
		if !outcome.OK {
			fmt.Printf("%s -> business error %s\n", label, outcome.Error.Code)
			return
		}
		op, _ := outcome.Result.Member("op")
		fmt.Printf("%s -> ok op=%s same identity=%v\n", label, op.Str, sameIdentity)
		_ = expect
	}

	run("websocket     ", "/ip4/127.0.0.1/tcp/0/ws", []libp2p.Option{libp2p.Transport(libp2pwebsocket.New)}, 0)
	run("webrtc-direct ", "/ip4/127.0.0.1/udp/0/webrtc-direct", []libp2p.Option{libp2p.Transport(webRTCTransportWithThrowawayCertificate)}, 0)

	// Output:
	// websocket      -> ok op=get_balance same identity=true
	// webrtc-direct  -> ok op=get_balance same identity=true
}

// newHost builds a host through the upstream SDK, which owns the identity
// adapter, Noise, Yamux and Identify. This file only chooses the transport.
func newHost(upstream signer.Signer, listen string, transports []libp2p.Option) (host.Host, error) {
	config := golibp2p.HostConfig{Signer: upstream, TransportOptions: transports}
	if listen != "" {
		address, err := ma.NewMultiaddr(listen)
		if err != nil {
			return nil, err
		}
		config.ListenAddrs = []ma.Multiaddr{address}
	}
	return golibp2p.NewHost(config)
}

func peerIDFor(h host.Host, publicKey []byte) (peer.ID, error) {
	peerID, err := identity.PeerIDFromPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	return peerID, nil
}

// certificateOnlyKey replaces only Raw, which go-libp2p WebRTC uses to derive its
// DTLS certificate. The upstream requirements document assigns Go WebRTC Direct
// transport assembly to the application for exactly this reason: the SDK's
// identity adapter is deliberately non-extractable.
type certificateOnlyKey struct {
	libp2pcrypto.PrivKey
	raw []byte
}

func (key *certificateOnlyKey) Raw() ([]byte, error) {
	return append([]byte(nil), key.raw...), nil
}

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
