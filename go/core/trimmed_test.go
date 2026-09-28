package core_test

import (
	"context"
	"testing"

	"github.com/bsv8/roundtrip/go/core"
)

// The message layer for the optional trusted HTTPS response.
//
// No transport in this version speaks it. What has to exist anyway is the
// packing and the parsing, so an application that decides to use it has one
// canonical encoding and one strict reader, exactly like the base messages.
// The base readers keep refusing this shape: a trimmed response is a separate
// message with a separate signing prefix, not a base response with a field
// removed.

func TestTrimmedResponseCarriesExactlyFourFields(t *testing.T) {
	unsigned := core.UnsignedTrimmedResponse{
		From: testPublicKey(t, "bob"),
		To:   testPublicKey(t, "alice"),
		Body: mustObject(t, `{"ok":true,"result":{"confirmed":42}}`),
	}
	bytes := signedBytesFor(t, unsigned, "bob")
	parsed := mustParse(t, bytes)
	for _, field := range parsed.Keys {
		switch field {
		case "from", "to", "body", "sig":
		default:
			t.Errorf("a trimmed response must not carry %q", field)
		}
	}
	if len(parsed.Keys) != 4 {
		t.Errorf("got %d fields, want 4: %v", len(parsed.Keys), parsed.Keys)
	}
	envelope, err := core.ParseTrimmedResponse(parsed)
	if err != nil {
		t.Fatalf("parse trimmed response: %v", err)
	}
	if !core.EqualBytes(envelope.Unsigned.From, unsigned.From) {
		t.Errorf("from mismatch")
	}
}

func TestTrimmedResponseUsesItsOwnSigningPrefix(t *testing.T) {
	trimmed := core.UnsignedTrimmedResponse{
		From: testPublicKey(t, "bob"),
		To:   testPublicKey(t, "alice"),
		Body: mustObject(t, `{"ok":true,"result":1}`),
	}
	prefix, err := core.SigningPrefixOf(trimmed)
	if err != nil {
		t.Fatalf("prefix: %v", err)
	}
	if prefix != core.TrimmedResponsePrefix {
		t.Errorf("got %q, want %q", prefix, core.TrimmedResponsePrefix)
	}
	if core.TrimmedResponsePrefix != "roundtrip/http-response/v1\n" {
		t.Errorf("the trimmed prefix is %q", core.TrimmedResponsePrefix)
	}
	if requestPrefix, err := core.SigningPrefixOf(unsignedRequestFor(t, "alice", "bob", nil)); err != nil || requestPrefix != core.SigningPrefix {
		t.Errorf("a request must use the base prefix, got %q %v", requestPrefix, err)
	}
	signingBytes, err := core.SigningBytes(trimmed)
	if err != nil {
		t.Fatalf("signing bytes: %v", err)
	}
	if string(signingBytes[:len(core.TrimmedResponsePrefix)]) != core.TrimmedResponsePrefix {
		t.Errorf("the signed bytes do not start with the trimmed prefix")
	}

	// The same fields as a base response must produce a different digest.
	base := core.UnsignedResponse{
		From: trimmed.From, To: trimmed.To, ReplyTo: bytesOf(32, 1), Body: trimmed.Body,
	}
	trimmedDigest, err := core.DigestOf(trimmed)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	baseDigest, err := core.DigestOf(base)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if core.EqualBytes(trimmedDigest, baseDigest) {
		t.Errorf("a trimmed response and a base response must not share a digest")
	}

	// And a signature cannot be moved between the two.
	trimmedSignature, err := core.SignDigest(testPrivateKey(t, "bob"), trimmedDigest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := core.VerifyDigest(base.From, baseDigest, trimmedSignature); err == nil {
		t.Errorf("a trimmed signature verified as a base response signature")
	}
	baseSignature, err := core.SignDigest(testPrivateKey(t, "bob"), baseDigest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := core.VerifyDigest(trimmed.From, trimmedDigest, baseSignature); err == nil {
		t.Errorf("a base signature verified as a trimmed response signature")
	}
}

func TestBaseReadersRefuseTheTrimmedShape(t *testing.T) {
	trimmedBytes := signedBytesFor(t, core.UnsignedTrimmedResponse{
		From: testPublicKey(t, "bob"),
		To:   testPublicKey(t, "alice"),
		Body: mustObject(t, `{"ok":true,"result":1}`),
	}, "bob")
	parsed := mustParse(t, trimmedBytes)
	if _, err := core.ParseResponse(parsed); mustCode(t, err) != "ERR_ENVELOPE_FIELD_MISSING" {
		t.Errorf("the base reader accepted a trimmed response: %q", mustCode(t, err))
	}
	if _, err := core.ParseRequest(parsed); mustCode(t, err) != "ERR_ENVELOPE_FIELD_MISSING" {
		t.Errorf("the request reader accepted a trimmed response: %q", mustCode(t, err))
	}
	baseBytes := signedBytesFor(t, core.UnsignedResponse{
		From: testPublicKey(t, "bob"), To: testPublicKey(t, "alice"), ReplyTo: bytesOf(32, 1),
		Body: mustObject(t, `{"ok":true,"result":1}`),
	}, "bob")
	if _, err := core.ParseTrimmedResponse(mustParse(t, baseBytes)); mustCode(t, err) != "ERR_ENVELOPE_FIELD_UNKNOWN" {
		t.Errorf("the trimmed reader accepted a base response: %q", mustCode(t, err))
	}
}

func TestVerifyTrimmedResponseChecksIdentitiesAndSignature(t *testing.T) {
	unsigned := core.UnsignedTrimmedResponse{
		From: testPublicKey(t, "bob"),
		To:   testPublicKey(t, "alice"),
		Body: mustObject(t, `{"ok":true,"result":{"confirmed":42}}`),
	}
	bytes := signedBytesFor(t, unsigned, "bob")
	expected := core.TrimmedResponseExpectation{To: testPublicKey(t, "alice"), From: testPublicKey(t, "bob")}

	body, err := core.VerifyTrimmedResponse(mustParse(t, bytes), expected)
	if err != nil {
		t.Fatalf("a correct trimmed response was refused: %v", err)
	}
	confirmed, _ := body.Member("result")
	if confirmed.Kind != core.KindObject {
		t.Fatalf("unexpected body: %+v", body)
	}

	wrongTo := core.TrimmedResponseExpectation{To: testPublicKey(t, "carol"), From: testPublicKey(t, "bob")}
	if _, err := core.VerifyTrimmedResponse(mustParse(t, bytes), wrongTo); mustCode(t, err) != "ERR_RESPONSE_TO" {
		t.Errorf("got %q, want ERR_RESPONSE_TO", mustCode(t, err))
	}
	wrongFrom := core.TrimmedResponseExpectation{To: testPublicKey(t, "alice"), From: testPublicKey(t, "carol")}
	if _, err := core.VerifyTrimmedResponse(mustParse(t, bytes), wrongFrom); mustCode(t, err) != "ERR_RESPONSE_FROM" {
		t.Errorf("got %q, want ERR_RESPONSE_FROM", mustCode(t, err))
	}
	forged := signedBytesFor(t, unsigned, "mallory")
	if _, err := core.VerifyTrimmedResponse(mustParse(t, forged), expected); mustCode(t, err) != "ERR_RESPONSE_SIGNATURE" {
		t.Errorf("got %q, want ERR_RESPONSE_SIGNATURE", mustCode(t, err))
	}
	tampered, err := replaceField(t, bytes, "to", core.EncodeBase64Url(testPublicKey(t, "bob")))
	if err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, err := core.VerifyTrimmedResponse(mustParse(t, tampered), expected); err == nil {
		t.Errorf("a rewritten recipient was accepted")
	}
}

func TestTrimmedResponseCannotProveWhichRequestItAnswers(t *testing.T) {
	// The trade off of dropping reply_to, written as a test rather than a claim:
	// the same bytes satisfy any request between the same two identities.
	unsigned := core.UnsignedTrimmedResponse{
		From: testPublicKey(t, "bob"),
		To:   testPublicKey(t, "alice"),
		Body: mustObject(t, `{"ok":true,"result":{"account":"A"}}`),
	}
	bytes := mustParse(t, signedBytesFor(t, unsigned, "bob"))
	expected := core.TrimmedResponseExpectation{To: testPublicKey(t, "alice"), From: testPublicKey(t, "bob")}

	client := newCaller(t, "alice")
	first, err := client.BuildRequest(context.Background(), testPublicKey(t, "bob"), mustObject(t, `{"op":"get_balance","args":{"account":"A"}}`), core.BuildRequestOptions{})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	second, err := client.BuildRequest(context.Background(), testPublicKey(t, "bob"), mustObject(t, `{"op":"get_balance","args":{"account":"B"}}`), core.BuildRequestOptions{})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if first.RequestID == second.RequestID {
		t.Fatalf("the two calls must have different request ids")
	}
	// Both waiting calls would accept the same verified response.
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := core.VerifyTrimmedResponse(bytes, expected); err != nil {
			t.Errorf("attempt %d: %v", attempt, err)
		}
	}
}

func TestTheCoreNeverProducesATrimmedResponse(t *testing.T) {
	server := newReceiver(t, "bob")
	client := newCaller(t, "alice")
	prepared, err := client.BuildRequest(context.Background(), server.core.PublicKey(), mustObject(t, `{"op":"ping"}`), core.BuildRequestOptions{})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	processed, err := server.core.Handle(context.Background(), prepared.Bytes, core.HandleOptions{})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if got := sortedKeys(mustParse(t, processed.Bytes)); got != "body,from,reply_to,sig,to" {
		t.Errorf("the core answered with %q, want a base response", got)
	}
	// A trimmed response cannot complete a call, because the core has no mode
	// for it.
	trimmed := signedBytesFor(t, core.UnsignedTrimmedResponse{
		From: testPublicKey(t, "bob"), To: testPublicKey(t, "alice"),
		Body: mustObject(t, `{"ok":true,"result":{"stolen":true}}`),
	}, "bob")
	if got := mustCode(t, mustVerify(client, trimmed, prepared)); got != "ERR_ENVELOPE_FIELD_MISSING" {
		t.Errorf("got %q, want ERR_ENVELOPE_FIELD_MISSING", got)
	}
	if _, err := client.VerifyResponse(processed.Bytes, prepared); err != nil {
		t.Errorf("the honest base response was refused: %v", err)
	}
}

func sortedKeys(value core.Value) string {
	keys := append([]string(nil), value.Keys...)
	for index := 0; index < len(keys); index++ {
		for inner := index + 1; inner < len(keys); inner++ {
			if keys[inner] < keys[index] {
				keys[index], keys[inner] = keys[inner], keys[index]
			}
		}
	}
	result := ""
	for index, key := range keys {
		if index > 0 {
			result += ","
		}
		result += key
	}
	return result
}
