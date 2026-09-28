package core_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/bsv8/roundtrip/go/core"
)

// The same throw away identities the TypeScript suite and the shared vectors
// use, so a failure in one language can be compared with the other directly.
var testKeyHex = map[string]string{
	"alice":         "1111111111111111111111111111111111111111111111111111111111111111",
	"bob":           "2222222222222222222222222222222222222222222222222222222222222222",
	"carol":         "3333333333333333333333333333333333333333333333333333333333333333",
	"mallory":       "4444444444444444444444444444444444444444444444444444444444444444",
	"one":           "0000000000000000000000000000000000000000000000000000000000000001",
	"orderMinusOne": "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
}

const (
	testExpires = 1790000000
	// testNow is pinned to the vector instant, so expiry is a test decision and
	// not a function of the day the suite runs.
	testNow = testExpires - 5
)

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

// unsignedRequestFor is a well formed request with every field overridable, so a
// test can change one field and sign the result normally.
func unsignedRequestFor(t *testing.T, from, to string, mutate func(*core.UnsignedRequest)) core.UnsignedRequest {
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
	return unsigned
}

// signedBytesFor signs an unsigned message with the named test identity and
// returns complete envelope bytes. The signer is passed explicitly and is not
// required to be the owner of From, so a test can also build a message whose
// signature does not verify.
func signedBytesFor(t *testing.T, unsigned any, signerName string) []byte {
	t.Helper()
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

func signedRequestFor(t *testing.T, from, to, signerName string, mutate func(*core.UnsignedRequest)) []byte {
	t.Helper()
	return signedBytesFor(t, unsignedRequestFor(t, from, to, mutate), signerName)
}

func bytesOf(length int, fill byte) []byte {
	buffer := make([]byte, length)
	for index := range buffer {
		buffer[index] = fill
	}
	return buffer
}

func mustObject(t *testing.T, text string) core.Value {
	t.Helper()
	value, err := core.ParseJSON(text)
	if err != nil {
		t.Fatalf("parse %s: %v", text, err)
	}
	return value
}

func mustCode(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		return ""
	}
	code := core.CodeOf(err)
	if code == "" {
		return "NOT_A_ROUNDTRIP_ERROR"
	}
	return string(code)
}

// receiver is a Core that records every handler invocation.
type receiver struct {
	core  *core.Core
	calls []handlerCall
	guard *core.MemoryReplayGuard
}

type handlerCall struct {
	from      string
	requestID string
	op        string
}

func newReceiver(t *testing.T, name string, options ...func(*core.Config)) *receiver {
	t.Helper()
	result := &receiver{guard: core.NewMemoryReplayGuard(func() int64 { return testNow })}
	config := core.Config{
		Signer: testSigner(t, name),
		Now:    func() int64 { return testNow },
		Handler: func(_ context.Context, input core.HandlerContext) (core.Outcome, error) {
			op := ""
			if body, ok := input.Body.Member("op"); ok && body.Kind == core.KindString {
				op = body.Str
			}
			result.calls = append(result.calls, handlerCall{
				from:      core.EncodeBase64Url(input.CallerPublicKey),
				requestID: input.RequestID,
				op:        op,
			})
			return core.Outcome{OK: true, Result: mustObject(t, `{"accepted":true}`)}, nil
		},
	}
	for _, option := range options {
		option(&config)
	}
	built, err := core.New(config)
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}
	result.core = built
	return result
}

func newCaller(t *testing.T, name string, options ...func(*core.Config)) *core.Core {
	t.Helper()
	config := core.Config{
		Signer:      testSigner(t, name),
		Now:         func() int64 { return testNow },
		RandomBytes: deterministicRandom(3),
	}
	for _, option := range options {
		option(&config)
	}
	built, err := core.New(config)
	if err != nil {
		t.Fatalf("new caller: %v", err)
	}
	return built
}

// deterministicRandom keeps tests off the entropy source; xorshift32, same as the
// TypeScript fixture.
func deterministicRandom(seed uint32) func(int) ([]byte, error) {
	state := seed
	return func(length int) ([]byte, error) {
		buffer := make([]byte, length)
		for index := range buffer {
			state ^= state << 13
			state ^= state >> 17
			state ^= state << 5
			buffer[index] = byte(state)
		}
		return buffer, nil
	}
}

func TestRoundTripAnswersOneSignedRequest(t *testing.T) {
	server := newReceiver(t, "bob")
	client := newCaller(t, "alice")
	prepared, err := client.BuildRequest(context.Background(), server.core.PublicKey(), mustObject(t, `{"op":"get_balance"}`), core.BuildRequestOptions{})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	processed, err := server.core.Handle(context.Background(), prepared.Bytes, core.HandleOptions{})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if processed.RequestID != prepared.RequestID {
		t.Errorf("request id mismatch: got %s, want %s", processed.RequestID, prepared.RequestID)
	}
	outcome, err := client.VerifyResponse(processed.Bytes, prepared)
	if err != nil {
		t.Fatalf("verify response: %v", err)
	}
	if !outcome.OK {
		t.Fatalf("unexpected business failure: %+v", outcome.Error)
	}
	if len(server.calls) != 1 {
		t.Fatalf("handler ran %d times, want 1", len(server.calls))
	}
	if server.calls[0].from != core.EncodeBase64Url(client.PublicKey()) {
		t.Errorf("caller identity mismatch")
	}
}

func TestTamperedFieldBreaksTheRequest(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*core.UnsignedRequest)
	}{
		{"from", func(r *core.UnsignedRequest) { r.From = testPublicKeyNoFatal("mallory") }},
		{"to", func(r *core.UnsignedRequest) { r.To = testPublicKeyNoFatal("carol") }},
		{"nonce", func(r *core.UnsignedRequest) { r.Nonce = bytesOf(32, 8) }},
		{"expires", func(r *core.UnsignedRequest) { r.Expires = testExpires + 1 }},
		{"body", func(r *core.UnsignedRequest) { r.Body = mustObjectNoFatal(`{"op":"transfer","args":{"amount":"1"}}`) }},
	}
	for _, entry := range cases {
		t.Run(entry.name, func(t *testing.T) {
			server := newReceiver(t, "bob")
			// Change the field after signing, leaving the signature in place.
			unsigned := unsignedRequestFor(t, "alice", "bob", entry.mutate)
			digest, err := core.DigestOf(core.UnsignedRequest{
				From: testPublicKey(t, "alice"), To: testPublicKey(t, "bob"),
				Nonce: bytesOf(32, 9), Expires: testExpires,
				Body: mustObjectNoFatal(`{"op":"get_balance","args":{}}`),
			})
			if err != nil {
				t.Fatalf("digest: %v", err)
			}
			signature, err := core.SignDigest(testPrivateKey(t, "alice"), digest)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			bytes, err := core.EncodeEnvelopeBytes(unsigned, signature)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			_, err = server.core.Handle(context.Background(), bytes, core.HandleOptions{})
			if err == nil {
				t.Fatalf("a changed %s was accepted", entry.name)
			}
			if len(server.calls) != 0 {
				t.Errorf("a changed %s reached the handler", entry.name)
			}
		})
	}
}

func testPublicKeyNoFatal(name string) []byte {
	publicKey, err := core.PublicKeyFromPrivateKey(core.MustHexToBytes(testKeyHex[name]))
	if err != nil {
		panic(err)
	}
	return publicKey
}

func mustObjectNoFatal(text string) core.Value {
	value, err := core.ParseJSON(text)
	if err != nil {
		panic(err)
	}
	return value
}

func TestSignatureFromAnotherIdentityIsRefused(t *testing.T) {
	server := newReceiver(t, "bob")
	// Correctly formed, correctly canonical, but signed by mallory while
	// claiming to be alice.
	bytes := signedRequestFor(t, "alice", "bob", "mallory", nil)
	_, err := server.core.Handle(context.Background(), bytes, core.HandleOptions{})
	if got := mustCode(t, err); got != "ERR_SIGNATURE" {
		t.Errorf("got %q, want ERR_SIGNATURE", got)
	}
	if len(server.calls) != 0 {
		t.Errorf("a forged request reached the handler")
	}
}

func TestWrongRecipientNeverRuns(t *testing.T) {
	bob := newReceiver(t, "bob")
	// Alice legitimately signs a request for carol. Delivering it to bob must
	// not execute it, even though the signature is valid.
	bytes := signedRequestFor(t, "alice", "carol", "alice", nil)
	_, err := bob.core.Handle(context.Background(), bytes, core.HandleOptions{})
	if got := mustCode(t, err); got != "ERR_RECIPIENT" {
		t.Errorf("got %q, want ERR_RECIPIENT", got)
	}
	if len(bob.calls) != 0 {
		t.Errorf("a request for another identity reached the handler")
	}
	// The same bytes are accepted by the intended recipient.
	carol := newReceiver(t, "carol")
	if _, err := carol.core.Handle(context.Background(), bytes, core.HandleOptions{}); err != nil {
		t.Fatalf("carol refused a request addressed to her: %v", err)
	}
	if len(carol.calls) != 1 {
		t.Errorf("carol ran the handler %d times, want 1", len(carol.calls))
	}
}

func TestRetargetedRequestFails(t *testing.T) {
	mallory := newReceiver(t, "mallory")
	// Alice signed a request for carol; the recipient field is rewritten to
	// mallory and the message is delivered to mallory.
	retargeted, err := replaceField(t, signedRequestFor(t, "alice", "carol", "alice", nil), "to", core.EncodeBase64Url(testPublicKey(t, "mallory")))
	if err != nil {
		t.Fatalf("retarget: %v", err)
	}
	_, err = mallory.core.Handle(context.Background(), retargeted, core.HandleOptions{})
	if got := mustCode(t, err); got != "ERR_SIGNATURE" {
		t.Errorf("got %q, want ERR_SIGNATURE: to must be covered by the signature", got)
	}
	if len(mallory.calls) != 0 {
		t.Errorf("a re-targeted request reached the handler")
	}
}

func TestTransportIdentityMustMatchMessageIdentity(t *testing.T) {
	server := newReceiver(t, "bob")
	bytes := signedRequestFor(t, "alice", "bob", "alice", nil)
	// A transport that authenticated carol cannot forward alice's request as if
	// it came from carol.
	_, err := server.core.Handle(context.Background(), bytes, core.HandleOptions{CallerPublicKey: testPublicKey(t, "carol")})
	if got := mustCode(t, err); got != "ERR_CALLER_IDENTITY" {
		t.Errorf("got %q, want ERR_CALLER_IDENTITY", got)
	}
	if len(server.calls) != 0 {
		t.Errorf("a forwarded request reached the handler")
	}
	if _, err := server.core.Handle(context.Background(), bytes, core.HandleOptions{CallerPublicKey: testPublicKey(t, "alice")}); err != nil {
		t.Fatalf("the honest delivery was refused: %v", err)
	}
}

func TestExpiryAndWindow(t *testing.T) {
	var now int64 = testNow + 10
	server := newReceiver(t, "bob", func(config *core.Config) { config.Now = func() int64 { return now } })
	expired := signedRequestFor(t, "alice", "bob", "alice", func(r *core.UnsignedRequest) { r.Expires = now - 100 })
	if _, err := server.core.Handle(context.Background(), expired, core.HandleOptions{}); mustCode(t, err) != "ERR_EXPIRED" {
		t.Errorf("got %q, want ERR_EXPIRED", mustCode(t, err))
	}
	// Inside the allowed clock skew it is still accepted.
	insideSkew := signedRequestFor(t, "alice", "bob", "alice", func(r *core.UnsignedRequest) { r.Expires = now - 3 })
	if _, err := server.core.Handle(context.Background(), insideSkew, core.HandleOptions{}); err != nil {
		t.Errorf("a request inside the clock skew was refused: %v", err)
	}
	// Too far in the future is refused even though it has not expired.
	strict := newReceiver(t, "bob", func(config *core.Config) {
		config.Now = func() int64 { return now }
		config.MaxRequestTTL = 30
	})
	far := signedRequestFor(t, "alice", "bob", "alice", func(r *core.UnsignedRequest) { r.Expires = now + 3600 })
	if _, err := strict.core.Handle(context.Background(), far, core.HandleOptions{}); mustCode(t, err) != "ERR_EXPIRY_WINDOW" {
		t.Errorf("got %q, want ERR_EXPIRY_WINDOW", mustCode(t, err))
	}
}

func TestResponseIsAcceptedOnlyFromTheRightPeer(t *testing.T) {
	client := newCaller(t, "alice")
	prepared, err := client.BuildRequest(context.Background(), testPublicKey(t, "bob"), mustObject(t, `{"op":"get_balance"}`), core.BuildRequestOptions{})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	replyTo, err := core.DigestOf(prepared.Unsigned)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	t.Run("honest response", func(t *testing.T) {
		bytes := signedBytesFor(t, core.UnsignedResponse{
			From: testPublicKey(t, "bob"), To: testPublicKey(t, "alice"), ReplyTo: replyTo,
			Body: mustObject(t, `{"ok":true,"result":{"satoshis":"42"}}`),
		}, "bob")
		outcome, err := client.VerifyResponse(bytes, prepared)
		if err != nil || !outcome.OK {
			t.Fatalf("the honest response was refused: %v", err)
		}
	})
	t.Run("forged result", func(t *testing.T) {
		bytes := signedBytesFor(t, core.UnsignedResponse{
			From: testPublicKey(t, "bob"), To: testPublicKey(t, "alice"), ReplyTo: replyTo,
			Body: mustObject(t, `{"ok":true,"result":{"satoshis":"999999999"}}`),
		}, "mallory")
		if got := mustCode(t, mustVerify(client, bytes, prepared)); got != "ERR_RESPONSE_SIGNATURE" {
			t.Errorf("got %q, want ERR_RESPONSE_SIGNATURE", got)
		}
	})
	t.Run("wrong peer", func(t *testing.T) {
		bytes := signedBytesFor(t, core.UnsignedResponse{
			From: testPublicKey(t, "mallory"), To: testPublicKey(t, "alice"), ReplyTo: replyTo,
			Body: mustObject(t, `{"ok":true,"result":{"satoshis":"999999999"}}`),
		}, "mallory")
		if got := mustCode(t, mustVerify(client, bytes, prepared)); got != "ERR_RESPONSE_FROM" {
			t.Errorf("got %q, want ERR_RESPONSE_FROM", got)
		}
	})
	t.Run("wrong recipient", func(t *testing.T) {
		bytes := signedBytesFor(t, core.UnsignedResponse{
			From: testPublicKey(t, "bob"), To: testPublicKey(t, "carol"), ReplyTo: replyTo,
			Body: mustObject(t, `{"ok":true,"result":1}`),
		}, "bob")
		if got := mustCode(t, mustVerify(client, bytes, prepared)); got != "ERR_RESPONSE_TO" {
			t.Errorf("got %q, want ERR_RESPONSE_TO", got)
		}
	})
	t.Run("answers another request", func(t *testing.T) {
		other, err := client.BuildRequest(context.Background(), testPublicKey(t, "bob"), mustObject(t, `{"op":"get_balance","args":{"account":"B"}}`), core.BuildRequestOptions{})
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		otherDigest, err := core.DigestOf(other.Unsigned)
		if err != nil {
			t.Fatalf("digest: %v", err)
		}
		bytes := signedBytesFor(t, core.UnsignedResponse{
			From: testPublicKey(t, "bob"), To: testPublicKey(t, "alice"), ReplyTo: otherDigest,
			Body: mustObject(t, `{"ok":true,"result":{"account":"B"}}`),
		}, "bob")
		if got := mustCode(t, mustVerify(client, bytes, prepared)); got != "ERR_RESPONSE_REPLY_TO" {
			t.Errorf("got %q, want ERR_RESPONSE_REPLY_TO", got)
		}
	})
	t.Run("trimmed response cannot complete a call", func(t *testing.T) {
		bytes := signedBytesFor(t, core.UnsignedTrimmedResponse{
			From: testPublicKey(t, "bob"), To: testPublicKey(t, "alice"),
			Body: mustObject(t, `{"ok":true,"result":{"stolen":true}}`),
		}, "bob")
		if got := mustCode(t, mustVerify(client, bytes, prepared)); got != "ERR_ENVELOPE_FIELD_MISSING" {
			t.Errorf("got %q, want ERR_ENVELOPE_FIELD_MISSING", got)
		}
	})
}

func mustVerify(client *core.Core, bytes []byte, prepared core.PreparedRequest) error {
	_, err := client.VerifyResponse(bytes, prepared)
	return err
}

func TestConcurrentDuplicateRunsTheBusinessOnce(t *testing.T) {
	var mu sync.Mutex
	runs := 0
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	server := newReceiver(t, "bob", func(config *core.Config) {
		config.Handler = func(_ context.Context, _ core.HandlerContext) (core.Outcome, error) {
			mu.Lock()
			runs++
			mu.Unlock()
			entered <- struct{}{}
			// Hold the business open, so a non atomic claim would let a second
			// delivery in while the first one is still running.
			<-release
			return core.Outcome{OK: true, Result: mustObjectNoFatal(`{"moved":1}`)}, nil
		}
	})
	bytes := signedRequestFor(t, "alice", "bob", "alice", nil)

	// The first delivery enters the business and stays there.
	first := make(chan error, 1)
	go func() {
		_, err := server.core.Handle(context.Background(), bytes, core.HandleOptions{})
		first <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first delivery never reached the handler")
	}

	// Seven concurrent duplicates arrive while the first is still inside the
	// business. All of them have to be refused before it is allowed to finish.
	var group sync.WaitGroup
	duplicates := make([]error, 7)
	for index := 0; index < 7; index++ {
		group.Add(1)
		go func(slot int) {
			defer group.Done()
			_, duplicates[slot] = server.core.Handle(context.Background(), bytes, core.HandleOptions{})
		}(index)
	}
	answered := make(chan struct{})
	go func() {
		group.Wait()
		close(answered)
	}()
	select {
	case <-answered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("a duplicate blocked behind the running business instead of being refused")
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("the first delivery failed: %v", err)
	}

	mu.Lock()
	executed := runs
	mu.Unlock()
	if executed != 1 {
		t.Errorf("the business ran %d times, want 1", executed)
	}
	// The duplicates were each answered, with a signed refusal rather than silence.
	for index, err := range duplicates {
		if err != nil {
			t.Errorf("duplicate %d failed instead of being refused: %v", index, err)
		}
	}
}

func TestDuplicateAfterCompletionIsRefused(t *testing.T) {
	server := newReceiver(t, "bob")
	bytes := signedRequestFor(t, "alice", "bob", "alice", nil)
	if _, err := server.core.Handle(context.Background(), bytes, core.HandleOptions{}); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	processed, err := server.core.Handle(context.Background(), bytes, core.HandleOptions{})
	if err != nil {
		t.Fatalf("second delivery: %v", err)
	}
	if processed.Outcome.OK || processed.Outcome.Error.Code != core.ReplayErrorCode {
		t.Errorf("got %+v, want %s", processed.Outcome, core.ReplayErrorCode)
	}
	if len(server.calls) != 1 {
		t.Errorf("the business ran %d times, want 1", len(server.calls))
	}
}

func TestHandlerFailureDoesNotReleaseTheClaim(t *testing.T) {
	runs := 0
	server := newReceiver(t, "bob", func(config *core.Config) {
		config.Handler = func(_ context.Context, _ core.HandlerContext) (core.Outcome, error) {
			runs++
			return core.Outcome{}, context.DeadlineExceeded
		}
	})
	bytes := signedRequestFor(t, "alice", "bob", "alice", nil)
	if _, err := server.core.Handle(context.Background(), bytes, core.HandleOptions{}); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if _, err := server.core.Handle(context.Background(), bytes, core.HandleOptions{}); err != nil {
		t.Fatalf("second delivery: %v", err)
	}
	// A retry of the same request must not run the business again, even though
	// the first attempt failed after it started.
	if runs != 1 {
		t.Errorf("the business ran %d times, want 1", runs)
	}
}

func TestMemoryGuardCapabilitiesAreDeclared(t *testing.T) {
	guard := core.NewMemoryReplayGuard(func() int64 { return testNow })
	capabilities := guard.Capabilities()
	if capabilities.Persistent || capabilities.Shared || capabilities.ResultCache {
		t.Errorf("the in memory guard must not claim %+v", capabilities)
	}
	claim := core.ReplayClaim{ID: "x", RetainUntil: testNow + 60}
	if claimed, err := guard.Claim(context.Background(), claim); err != nil || !claimed {
		t.Fatalf("first claim: %v %v", claimed, err)
	}
	if claimed, err := guard.Claim(context.Background(), claim); err != nil || claimed {
		t.Fatalf("second claim: %v %v", claimed, err)
	}
	if state := guard.StateOf("x"); state != "claimed" {
		t.Errorf("state is %q, want claimed", state)
	}
	if err := guard.Complete(context.Background(), "x"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if state := guard.StateOf("x"); state != "completed" {
		t.Errorf("state is %q, want completed", state)
	}
}

func TestMemoryGuardRetentionFollowsTheCoreClock(t *testing.T) {
	// The guard has to run on the same clock as the core, or a record can be
	// dropped while the request is still inside its window.
	var now int64 = testNow
	server := newReceiver(t, "bob", func(config *core.Config) {
		config.Now = func() int64 { return now }
		config.Replay = core.NewMemoryReplayGuard(func() int64 { return now })
	})
	bytes := signedRequestFor(t, "alice", "bob", "alice", nil)
	if _, err := server.core.Handle(context.Background(), bytes, core.HandleOptions{}); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	// Just before the record may be dropped, a duplicate is still refused.
	now = testExpires + 4
	if _, err := server.core.Handle(context.Background(), bytes, core.HandleOptions{}); err != nil {
		t.Fatalf("duplicate inside the window: %v", err)
	}
	if len(server.calls) != 1 {
		t.Errorf("the business ran %d times inside the window", len(server.calls))
	}
	// Past the retention deadline the record is swept, and the guard is readable
	// about it.
	if state := server.guard.StateOf(recordID(t, bytes)); state != "absent" {
		t.Errorf("state is %q, want absent after the window", state)
	}
}

// recordID is the request id of envelope bytes.
func recordID(t *testing.T, requestBytes []byte) string {
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

// replaceField rewrites one top level string field of an envelope, leaving the
// signature in place. It is how a test produces a tampered message.
func replaceField(t *testing.T, envelope []byte, field, value string) ([]byte, error) {
	t.Helper()
	parsed, err := core.ParseJSONBytes(envelope)
	if err != nil {
		return nil, err
	}
	parsed.Set(field, core.StringValue(value))
	encoded, err := core.Canonicalize(parsed)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
