package http_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	roundtriphttp "github.com/bsv8/roundtrip/go/http"

	"github.com/bsv8/roundtrip/go/core"
)

// Stage 5 over a real socket. The TypeScript suite runs the same cases against
// node:http, and both languages use the shared test identities.

const (
	testExpires = 1790000000
	testNow     = testExpires - 5
)

var testKeyHex = map[string]string{
	"alice":   "1111111111111111111111111111111111111111111111111111111111111111",
	"bob":     "2222222222222222222222222222222222222222222222222222222222222222",
	"carol":   "3333333333333333333333333333333333333333333333333333333333333333",
	"mallory": "4444444444444444444444444444444444444444444444444444444444444444",
}

func testPrivateKey(t *testing.T, name string) []byte {
	t.Helper()
	hex, ok := testKeyHex[name]
	if !ok {
		t.Fatalf("unknown test key: %s", name)
	}
	return core.MustHexToBytes(hex)
}

func testPublicKey(t *testing.T, name string) []byte {
	t.Helper()
	publicKey, err := core.PublicKeyFromPrivateKey(testPrivateKey(t, name))
	if err != nil {
		t.Fatalf("public key for %s: %v", name, err)
	}
	return publicKey
}

func testSigner(t *testing.T, name string) core.Signer {
	t.Helper()
	signer, err := core.NewLocalSigner(testPrivateKey(t, name))
	if err != nil {
		t.Fatalf("signer for %s: %v", name, err)
	}
	return signer
}

func mustObject(t *testing.T, text string) core.Value {
	t.Helper()
	value, err := core.ParseJSON(text)
	if err != nil {
		t.Fatalf("parse %s: %v", text, err)
	}
	return value
}

type service struct {
	core  *core.Core
	url   string
	guard *core.MemoryReplayGuard
}

// newService starts a real HTTP server in front of a real core.
func newService(t *testing.T, name string, options ...func(*serviceConfig)) *service {
	t.Helper()
	result := &service{guard: core.NewMemoryReplayGuard(func() int64 { return testNow })}
	config := serviceConfig{
		handler: func(_ context.Context, input core.HandlerContext) (core.Outcome, error) {
			return core.Outcome{OK: true, Result: input.Body}, nil
		},
	}
	for _, option := range options {
		option(&config)
	}
	protocol, err := core.New(core.Config{
		Signer:  testSigner(t, name),
		Now:     func() int64 { return testNow },
		Replay:  result.guard,
		Handler: config.handler,
	})
	if err != nil {
		t.Fatalf("new core: %v", err)
	}
	result.core = protocol
	server := httptest.NewServer(roundtriphttp.Handler(roundtriphttp.NewEndpoint(protocol, roundtriphttp.Options{}), roundtriphttp.DefaultMaxBodyBytes))
	result.url = server.URL + roundtriphttp.Path
	t.Cleanup(server.Close)
	return result
}

type serviceConfig struct {
	handler core.Handler
}

func newCaller(t *testing.T, name string) *core.Core {
	t.Helper()
	built, err := core.New(core.Config{
		Signer:      testSigner(t, name),
		Now:         func() int64 { return testNow },
		RandomBytes: func(length int) ([]byte, error) { return make([]byte, length), nil },
	})
	if err != nil {
		t.Fatalf("new caller: %v", err)
	}
	return built
}

func signedRequestFor(t *testing.T, from, to, signerName string, mutate func(*core.UnsignedRequest)) []byte {
	t.Helper()
	unsigned := core.UnsignedRequest{
		From:    testPublicKey(t, from),
		To:      testPublicKey(t, to),
		Nonce:   bytesOf(32, 9),
		Expires: testExpires,
		Body:    mustObject(t, `{"op":"get_balance","args":{}}`),
	}
	if mutate != nil {
		mutate(&unsigned)
	}
	digest, err := core.DigestOf(unsigned)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	signature, err := core.SignDigest(testPrivateKey(t, signerName), digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	bytes, err := core.EncodeEnvelopeBytes(unsigned, signature)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return bytes
}

func bytesOf(length int, fill byte) []byte {
	buffer := make([]byte, length)
	for index := range buffer {
		buffer[index] = fill
	}
	return buffer
}

func postRaw(t *testing.T, url string, body []byte, headers map[string]string) (int, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return response.StatusCode, string(raw)
}

func TestHTTPRoundTrip(t *testing.T) {
	server := newService(t, "bob")
	caller := newCaller(t, "alice")
	prepared, err := caller.BuildRequest(context.Background(), server.core.PublicKey(), mustObject(t, `{"op":"get_balance"}`), core.BuildRequestOptions{})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	outcome, _, err := caller.Call(context.Background(), server.core.PublicKey(), mustObject(t, `{"op":"get_balance"}`), roundtriphttp.Exchange(server.url, roundtriphttp.ExchangeOptions{}))
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !outcome.OK {
		t.Fatalf("unexpected business failure: %+v", outcome.Error)
	}
	// The answer is signed and correlated with this call.
	response, err := roundtriphttp.Exchange(server.url, roundtriphttp.ExchangeOptions{})(context.Background(), prepared.Bytes)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	envelope, err := core.ParseResponse(mustParseBytes(t, response))
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	digest, err := core.DigestOf(prepared.Unsigned)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if !core.EqualBytes(envelope.Unsigned.ReplyTo, digest) {
		t.Errorf("the response does not quote this request")
	}
}

func TestHTTPBusinessFailureIsASignedTwoHundred(t *testing.T) {
	server := newService(t, "bob", func(config *serviceConfig) {
		config.handler = func(_ context.Context, _ core.HandlerContext) (core.Outcome, error) {
			return core.Outcome{Error: core.BusinessError{Code: "UNKNOWN_ASSET", Message: "没有这个资产"}}, nil
		}
	})
	caller := newCaller(t, "alice")
	outcome, _, err := caller.Call(context.Background(), server.core.PublicKey(), mustObject(t, `{"op":"get_balance"}`), roundtriphttp.Exchange(server.url, roundtriphttp.ExchangeOptions{}))
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if outcome.OK {
		t.Fatalf("expected a business failure")
	}
	if outcome.Error.Code != "UNKNOWN_ASSET" {
		t.Errorf("got %q, want UNKNOWN_ASSET", outcome.Error.Code)
	}
}

func TestHTTPEntryErrorsAreUnsigned(t *testing.T) {
	server := newService(t, "bob")
	request := signedRequestFor(t, "alice", "bob", "alice", nil)

	if status, _ := postRaw(t, server.url+"x", request, map[string]string{"Content-Type": "application/json"}); status != 404 {
		t.Errorf("got %d, want 404", status)
	}
	response, err := http.Get(server.url)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	//nolint:errcheck // test cleanup
	response.Body.Close()
	if response.StatusCode != 405 {
		t.Errorf("got %d, want 405", response.StatusCode)
	}
	if status, _ := postRaw(t, server.url, request, map[string]string{"Content-Type": "text/plain"}); status != 415 {
		t.Errorf("got %d, want 415", status)
	}
	if status, _ := postRaw(t, server.url, []byte(`{"from":`), map[string]string{"Content-Type": "application/json"}); status != 400 {
		t.Errorf("got %d, want 400", status)
	}
	// A body that was changed after signing is an entry error too.
	tampered, err := replaceField(t, request, "body", `{"op":"transfer","args":{"amount":"1000.00000000"}}`)
	if err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if status, _ := postRaw(t, server.url, tampered, map[string]string{"Content-Type": "application/json"}); status != 400 {
		t.Errorf("got %d, want 400", status)
	}
	// A request for another identity is refused with 403 and never runs.
	if status, _ := postRaw(t, server.url, signedRequestFor(t, "alice", "carol", "alice", nil), map[string]string{"Content-Type": "application/json"}); status != 403 {
		t.Errorf("got %d, want 403", status)
	}
}

func replaceField(t *testing.T, envelope []byte, field, value string) ([]byte, error) {
	t.Helper()
	parsed, err := core.ParseJSONBytes(envelope)
	if err != nil {
		return nil, err
	}
	parsed.Set(field, mustObject(t, value))
	return core.Canonicalize(parsed)
}

func TestHTTPNonSuccessStatusIsATransportFailure(t *testing.T) {
	server := newService(t, "bob")
	caller := newCaller(t, "alice")
	// A request for another identity comes back as an unsigned 403. The client
	// has to report a transport failure, because a status code is not a signed
	// business result.
	exchange := roundtriphttp.Exchange(server.url, roundtriphttp.ExchangeOptions{})
	_, _, err := caller.Call(context.Background(), testPublicKey(t, "carol"), mustObject(t, `{"op":"ping"}`), exchange)
	if core.CodeOf(err) != core.ErrHTTPStatus {
		t.Errorf("got %q, want ERR_HTTP_STATUS", core.CodeOf(err))
	}
}

func TestHTTPRejectsAnOlderValidlySignedResponse(t *testing.T) {
	server := newService(t, "bob")
	caller := newCaller(t, "alice")
	exchange := roundtriphttp.Exchange(server.url, roundtriphttp.ExchangeOptions{})

	// An earlier call, answered honestly, with the answer kept.
	earlier, err := caller.BuildRequest(context.Background(), server.core.PublicKey(), mustObject(t, `{"op":"op_first"}`), core.BuildRequestOptions{})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	saved, err := exchange(context.Background(), earlier.Bytes)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	// A later call, for something else, is waiting.
	later, err := caller.BuildRequest(context.Background(), server.core.PublicKey(), mustObject(t, `{"op":"op_second"}`), core.BuildRequestOptions{})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if earlier.RequestID == later.RequestID {
		t.Fatalf("the two calls must have different request ids")
	}
	// The stale answer is perfectly signed and comes from the right peer, so
	// only reply_to can refuse it.
	if _, err := caller.VerifyResponse(saved, later); core.CodeOf(err) != core.ErrResponseReplyTo {
		t.Errorf("got %q, want ERR_RESPONSE_REPLY_TO", core.CodeOf(err))
	}
}

func TestHTTPTakesTheOperationFromTheSignedBodyOnly(t *testing.T) {
	var mu sync.Mutex
	ops := []string{}
	server := newService(t, "bob", func(config *serviceConfig) {
		config.handler = func(_ context.Context, input core.HandlerContext) (core.Outcome, error) {
			op, _ := input.Body.Member("op")
			mu.Lock()
			ops = append(ops, op.Str)
			mu.Unlock()
			return core.Outcome{OK: true, Result: input.Body}, nil
		}
	})
	// A query string and unsigned headers are transport decoration. The signed
	// body decides what runs, so neither can switch the operation.
	status, _ := postRaw(t, server.url+"?op=delete_everything", signedRequestFor(t, "alice", "bob", "alice", nil), map[string]string{
		"Content-Type": "application/json",
		"X-Op":         "delete_everything",
	})
	if status != 200 {
		t.Errorf("got %d, want 200", status)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(ops) != 1 || ops[0] != "get_balance" {
		t.Errorf("the handler saw %v, want only get_balance", ops)
	}
}

func TestHTTPDuplicateIsRecognisedAcrossTransports(t *testing.T) {
	// The application shares one handler and one guard, so a message captured
	// from one path and delivered over the other is still the same request.
	server := newService(t, "bob")
	caller := newCaller(t, "alice")
	prepared, err := caller.BuildRequest(context.Background(), server.core.PublicKey(), mustObject(t, `{"op":"transfer","args":{"amount":"1.00000000"}}`), core.BuildRequestOptions{})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	exchange := roundtriphttp.Exchange(server.url, roundtriphttp.ExchangeOptions{})
	if outcome, err := caller.Send(context.Background(), prepared, exchange); err != nil || !outcome.OK {
		t.Fatalf("first delivery: %v %+v", err, outcome)
	}
	// The same bytes again over the same endpoint.
	second, err := exchange(context.Background(), prepared.Bytes)
	if err != nil {
		t.Fatalf("second delivery: %v", err)
	}
	if code := responseErrorCode(t, second); code != core.ReplayErrorCode {
		t.Errorf("got %q, want %s", code, core.ReplayErrorCode)
	}
	// And straight into the core, the way the libp2p adapter delivers.
	third, err := server.core.Handle(context.Background(), prepared.Bytes, core.HandleOptions{})
	if err != nil {
		t.Fatalf("direct delivery: %v", err)
	}
	// A duplicate is refused, so the outcome is a signed business failure.
	if third.Outcome.OK || third.Outcome.Error.Code != core.ReplayErrorCode {
		t.Errorf("got %+v, want %s", third.Outcome, core.ReplayErrorCode)
	}
}

func responseErrorCode(t *testing.T, responseBytes []byte) string {
	t.Helper()
	envelope, err := core.ParseResponse(mustParseBytes(t, responseBytes))
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	outcome, err := core.BodyToOutcome(envelope.Unsigned.Body)
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	if outcome.OK {
		return ""
	}
	return outcome.Error.Code
}

func mustParseBytes(t *testing.T, raw []byte) core.Value {
	t.Helper()
	value, err := core.ParseJSONBytes(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return value
}

func TestHTTPTimeoutIsNotAStatementAboutTheBusiness(t *testing.T) {
	finished := make(chan struct{})
	var deliveries int
	var mu sync.Mutex
	server := newService(t, "bob", func(config *serviceConfig) {
		config.handler = func(_ context.Context, _ core.HandlerContext) (core.Outcome, error) {
			mu.Lock()
			deliveries++
			mu.Unlock()
			time.Sleep(250 * time.Millisecond)
			close(finished)
			return core.Outcome{OK: true, Result: mustObject(t, `{"done":true}`)}, nil
		}
	})
	caller, err := core.New(core.Config{
		Signer:      testSigner(t, "alice"),
		Now:         func() int64 { return testNow },
		CallTimeout: 40 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new caller: %v", err)
	}
	_, _, err = caller.Call(context.Background(), server.core.PublicKey(), mustObject(t, `{"op":"slow"}`), roundtriphttp.Exchange(server.url, roundtriphttp.ExchangeOptions{}))
	if core.CodeOf(err) != core.ErrCallTimeout {
		t.Errorf("got %q, want ERR_CALL_TIMEOUT", core.CodeOf(err))
	}
	// The business still runs to completion, exactly once: a timeout must not
	// turn into an automatic retry, which would be a second call pretending to be
	// the first.
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("the business never finished")
	}
	mu.Lock()
	defer mu.Unlock()
	if deliveries != 1 {
		t.Errorf("the request was delivered %d times, want 1", deliveries)
	}
}

func TestHTTPMaxBodyBytesIsEnforcedLocally(t *testing.T) {
	protocol, err := core.New(core.Config{
		Signer: testSigner(t, "bob"),
		Now:    func() int64 { return testNow },
		Handler: func(_ context.Context, _ core.HandlerContext) (core.Outcome, error) {
			return core.Outcome{OK: true, Result: mustObject(t, `{}`)}, nil
		},
	})
	if err != nil {
		t.Fatalf("new core: %v", err)
	}
	server := httptest.NewServer(roundtriphttp.Handler(roundtriphttp.NewEndpoint(protocol, roundtriphttp.Options{}), 512))
	defer server.Close()
	big := signedRequestFor(t, "alice", "bob", "alice", func(r *core.UnsignedRequest) {
		r.Body = mustObject(t, `{"op":"upload","args":{"blob":"`+strings.Repeat("x", 4096)+`"}}`)
	})
	status, _ := postRaw(t, server.URL+roundtriphttp.Path, big, map[string]string{"Content-Type": "application/json"})
	if status != 413 && status != 400 {
		t.Errorf("got %d, want 413", status)
	}
}

func TestHTTPExchangeReportsMissingServerAsTransportFailure(t *testing.T) {
	exchange := roundtriphttp.Exchange("http://127.0.0.1:1/roundtrip", roundtriphttp.ExchangeOptions{
		Client: &http.Client{Timeout: 2 * time.Second},
	})
	_, err := exchange(context.Background(), []byte("{}"))
	if err == nil {
		t.Fatal("expected a failure")
	}
	if code := core.CodeOf(err); code != core.ErrTransport && code != core.ErrCallAborted {
		t.Errorf("got %q, want ERR_TRANSPORT", code)
	}
}
