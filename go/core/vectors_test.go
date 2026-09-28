package core_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bsv8/roundtrip/go/core"
	"github.com/bsv8/roundtrip/go/internal/testvectors"
)

// TestSharedVectors pins this implementation to the same bytes as the
// TypeScript suite: same JCS output, same signing bytes, same digest, same
// request id, same signature and same envelope.
func TestSharedVectors(t *testing.T) {
	vectors := testvectors.MustLoad()
	if vectors.Version != "roundtrip-vectors-v1" {
		t.Fatalf("unexpected vector version %q", vectors.Version)
	}
	if vectors.ProtocolPrefix != core.SigningPrefix {
		t.Fatalf("prefix mismatch: %q", vectors.ProtocolPrefix)
	}

	for _, key := range vectors.Keys {
		privateKey := core.MustHexToBytes(key.PrivateKeyHex)
		publicKey, err := core.PublicKeyFromPrivateKey(privateKey)
		if err != nil {
			t.Fatalf("key %s: %v", key.Name, err)
		}
		if got := core.BytesToHex(publicKey); got != key.PublicKeyHex {
			t.Errorf("key %s public key: got %s, want %s", key.Name, got, key.PublicKeyHex)
		}
		if got := core.EncodeBase64Url(publicKey); got != key.PublicKeyBase64Url {
			t.Errorf("key %s base64url: got %s, want %s", key.Name, got, key.PublicKeyBase64Url)
		}
		if err := core.VerifyDigest(publicKey, core.Sha256Bytes([]byte("roundtrip")), mustSign(t, privateKey, core.Sha256Bytes([]byte("roundtrip")))); err != nil {
			t.Errorf("key %s self verify: %v", key.Name, err)
		}
	}

	t.Run("rfc8785 example", func(t *testing.T) {
		value, err := core.ParseJSON(vectors.Rfc8785.Input)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		got, err := core.CanonicalizeString(value)
		if err != nil {
			t.Fatalf("canonicalize: %v", err)
		}
		if got != vectors.Rfc8785.Expected {
			t.Errorf("canonical form mismatch\n got: %s\nwant: %s", got, vectors.Rfc8785.Expected)
		}
	})

	t.Run("number serialization", func(t *testing.T) {
		for _, entry := range vectors.Numbers {
			value, err := core.ParseJSON(entry.Value)
			if err != nil {
				t.Fatalf("%s (%s): parse: %v", entry.Value, entry.Ieee754Hex, err)
			}
			got, err := core.CanonicalizeString(value)
			if err != nil {
				t.Fatalf("%s: canonicalize: %v", entry.Value, err)
			}
			if got != entry.Expected {
				t.Errorf("number %s (%s): got %s, want %s", entry.Value, entry.Ieee754Hex, got, entry.Expected)
			}
		}
	})

	t.Run("jcs cases", func(t *testing.T) {
		for _, entry := range vectors.Jcs {
			value, err := core.ParseJSON(entry.Input)
			if err != nil {
				t.Fatalf("%s: parse: %v", entry.Name, err)
			}
			got, err := core.CanonicalizeString(value)
			if err != nil {
				t.Fatalf("%s: canonicalize: %v", entry.Name, err)
			}
			if got != entry.Expected {
				t.Errorf("%s: got %s, want %s", entry.Name, got, entry.Expected)
			}
		}
	})

	t.Run("requests", func(t *testing.T) {
		for _, entry := range vectors.Requests {
			unsigned := core.UnsignedRequest{
				From:    mustDecode(t, entry.Unsigned.From),
				To:      mustDecode(t, entry.Unsigned.To),
				Nonce:   mustDecode(t, entry.Unsigned.Nonce),
				Expires: int64(entry.Unsigned.Expires),
				Body:    mustParse(t, entry.Unsigned.Body),
			}
			checkMessage(t, vectors, entry, unsigned)
			signerKey, ok := vectors.KeyByPublicKeyBase64Url(entry.Unsigned.From)
			if !ok {
				t.Fatalf("%s: unknown signer key %s", entry.Name, entry.Unsigned.From)
			}
			message := mustDecode(t, entry.MessageBase64Url)
			if !bytes.Equal(message, []byte(entry.Envelope)) {
				t.Errorf("%s: message base64url does not decode to the envelope text", entry.Name)
			}
			envelope, err := core.ParseRequest(mustParse(t, []byte(entry.Envelope)))
			if err != nil {
				t.Fatalf("%s: parse request: %v", entry.Name, err)
			}
			if !core.EqualBytes(envelope.Signature, mustDecode(t, entry.SignatureBase64Url)) {
				t.Errorf("%s: signature mismatch after round trip", entry.Name)
			}
			if !core.EqualBytes(envelope.Unsigned.From, unsigned.From) {
				t.Errorf("%s: from mismatch after round trip", entry.Name)
			}
			digest, err := core.DigestOf(envelope.Unsigned)
			if err != nil {
				t.Fatalf("%s: digest: %v", entry.Name, err)
			}
			if err := core.VerifyDigest(envelope.Unsigned.From, digest, envelope.Signature); err != nil {
				t.Errorf("%s: signature does not verify: %v", entry.Name, err)
			}
			_ = signerKey
		}
	})

	t.Run("responses", func(t *testing.T) {
		for _, entry := range vectors.Responses {
			unsigned := core.UnsignedResponse{
				From:    mustDecode(t, entry.Unsigned.From),
				To:      mustDecode(t, entry.Unsigned.To),
				ReplyTo: mustDecode(t, entry.Unsigned.ReplyTo),
				Body:    mustParse(t, entry.Unsigned.Body),
			}
			checkMessage(t, vectors, entry, unsigned)
			envelope, err := core.ParseResponse(mustParse(t, []byte(entry.Envelope)))
			if err != nil {
				t.Fatalf("%s: parse response: %v", entry.Name, err)
			}
			digest, err := core.DigestOf(envelope.Unsigned)
			if err != nil {
				t.Fatalf("%s: digest: %v", entry.Name, err)
			}
			if err := core.VerifyDigest(envelope.Unsigned.From, digest, envelope.Signature); err != nil {
				t.Errorf("%s: signature does not verify: %v", entry.Name, err)
			}
		}
	})

	t.Run("trimmed responses", func(t *testing.T) {
		if vectors.TrimmedResponsePrefix != core.TrimmedResponsePrefix {
			t.Fatalf("trimmed prefix mismatch: %q", vectors.TrimmedResponsePrefix)
		}
		for _, entry := range vectors.TrimmedResponses {
			if entry.Kind != "trimmed-response" {
				t.Fatalf("%s: kind is %q", entry.Name, entry.Kind)
			}
			unsigned := core.UnsignedTrimmedResponse{
				From: mustDecode(t, entry.Unsigned.From),
				To:   mustDecode(t, entry.Unsigned.To),
				Body: mustParse(t, entry.Unsigned.Body),
			}
			checkMessage(t, vectors, entry, unsigned)
			// A trimmed vector carries no request id, so there is nothing to
			// compare it against; the absence is part of what is pinned.
			if entry.RequestID != "" {
				t.Errorf("%s: a trimmed response must not carry a request id", entry.Name)
			}
			if entry.Unsigned.ReplyTo != "" {
				t.Errorf("%s: a trimmed response must not carry reply_to", entry.Name)
			}
			envelope, err := core.ParseTrimmedResponse(mustParse(t, []byte(entry.Envelope)))
			if err != nil {
				t.Fatalf("%s: parse trimmed response: %v", entry.Name, err)
			}
			digest, err := core.DigestOf(envelope.Unsigned)
			if err != nil {
				t.Fatalf("%s: digest: %v", entry.Name, err)
			}
			if err := core.VerifyDigest(envelope.Unsigned.From, digest, envelope.Signature); err != nil {
				t.Errorf("%s: signature does not verify: %v", entry.Name, err)
			}
			// The base readers must keep refusing this shape, or the two
			// implementations could disagree about which message this is.
			baseWire := mustParse(t, []byte(entry.Envelope))
			if _, err := core.ParseResponse(baseWire); err == nil {
				t.Errorf("%s: the base reader accepted a trimmed response", entry.Name)
			}
			if _, err := core.ParseRequest(baseWire); err == nil {
				t.Errorf("%s: the request reader accepted a trimmed response", entry.Name)
			}
		}
	})

	t.Run("a base response is not a trimmed one", func(t *testing.T) {
		for _, entry := range vectors.Responses {
			trimmed, err := core.ParseTrimmedResponse(mustParse(t, []byte(entry.Envelope)))
			if err == nil {
				t.Errorf("%s: the trimmed reader accepted a base response: %+v", entry.Name, trimmed.Unsigned)
			}
		}
	})

	t.Run("strict reading refusals", func(t *testing.T) {
		// The same inputs, and the same reasons, in both languages.
		for _, entry := range vectors.Reject {
			_, err := core.ParseJSON(entry.Input)
			if err == nil {
				t.Errorf("%s: input was accepted: %s", entry.Name, entry.Input)
				continue
			}
			if got := core.CodeOf(err); string(got) != entry.Code {
				t.Errorf("%s: got code %q, want %q", entry.Name, got, entry.Code)
			}
		}
	})

	t.Run("response reply_to matches a request id", func(t *testing.T) {
		requestIDs := map[string]string{}
		for _, entry := range vectors.Requests {
			requestIDs[entry.RequestID] = entry.Name
		}
		for _, entry := range vectors.Responses {
			// reply_to is the digest of the request bytes, so it is the request
			// id of the request this response answers.
			if _, ok := requestIDs[entry.Unsigned.ReplyTo]; !ok {
				t.Errorf("%s: reply_to %s does not match any request id", entry.Name, entry.Unsigned.ReplyTo)
			}
		}
	})
}

func checkMessage(t *testing.T, vectors testvectors.Vectors, entry testvectors.Message, unsigned any) {
	t.Helper()
	signingBytes, err := core.SigningBytes(unsigned)
	if err != nil {
		t.Fatalf("%s: signing bytes: %v", entry.Name, err)
	}
	if got := core.BytesToHex(signingBytes); got != entry.SigningBytesHex {
		t.Errorf("%s: signing bytes mismatch\n got: %s\nwant: %s", entry.Name, got, entry.SigningBytesHex)
	}
	wire, err := core.CanonicalizeString(mustUnsignedWire(t, unsigned))
	if err != nil {
		t.Fatalf("%s: wire: %v", entry.Name, err)
	}
	if wire != entry.Wire {
		t.Errorf("%s: wire mismatch\n got: %s\nwant: %s", entry.Name, wire, entry.Wire)
	}
	if !strings.HasPrefix(wire, "{") {
		t.Errorf("%s: wire is not an object", entry.Name)
	}
	digest := core.Sha256Bytes(signingBytes)
	if got := core.BytesToHex(digest); got != entry.DigestHex {
		t.Errorf("%s: digest mismatch\n got: %s\nwant: %s", entry.Name, got, entry.DigestHex)
	}
	if entry.RequestID != "" {
		request, ok := unsigned.(core.UnsignedRequest)
		if !ok {
			t.Fatalf("%s: a request id is only defined for requests, got %T", entry.Name, unsigned)
		}
		requestID, err := core.RequestIDOf(request)
		if err != nil {
			t.Fatalf("%s: request id: %v", entry.Name, err)
		}
		if requestID != entry.RequestID {
			t.Errorf("%s: request id mismatch: got %s, want %s", entry.Name, requestID, entry.RequestID)
		}
	}
	signerKey, ok := vectors.KeyByPublicKeyBase64Url(mustFromBase64Url(t, unsigned))
	if !ok {
		t.Fatalf("%s: no test key for the signer", entry.Name)
	}
	signature, err := core.SignDigest(core.MustHexToBytes(signerKey.PrivateKeyHex), digest)
	if err != nil {
		t.Fatalf("%s: sign: %v", entry.Name, err)
	}
	if got := core.BytesToHex(signature); got != entry.SignatureHex {
		t.Errorf("%s: signature mismatch\n got: %s\nwant: %s", entry.Name, got, entry.SignatureHex)
	}
	if got := core.EncodeBase64Url(signature); got != entry.SignatureBase64Url {
		t.Errorf("%s: signature base64url mismatch: got %s, want %s", entry.Name, got, entry.SignatureBase64Url)
	}
	envelope, err := core.EncodeEnvelopeBytes(unsigned, signature)
	if err != nil {
		t.Fatalf("%s: envelope: %v", entry.Name, err)
	}
	if got := string(envelope); got != entry.Envelope {
		t.Errorf("%s: envelope mismatch\n got: %s\nwant: %s", entry.Name, got, entry.Envelope)
	}
	if got := core.EncodeBase64Url(envelope); got != entry.MessageBase64Url {
		t.Errorf("%s: message base64url mismatch", entry.Name)
	}
}

func mustUnsignedWire(t *testing.T, unsigned any) core.Value {
	t.Helper()
	wire, err := core.UnsignedToWire(unsigned)
	if err != nil {
		t.Fatalf("unsigned wire: %v", err)
	}
	return wire
}

func mustFromBase64Url(t *testing.T, unsigned any) string {
	t.Helper()
	switch typed := unsigned.(type) {
	case core.UnsignedRequest:
		return core.EncodeBase64Url(typed.From)
	case core.UnsignedResponse:
		return core.EncodeBase64Url(typed.From)
	case core.UnsignedTrimmedResponse:
		return core.EncodeBase64Url(typed.From)
	default:
		t.Fatalf("unsupported type %T", unsigned)
		return ""
	}
}

func mustSign(t *testing.T, privateKey, digest []byte) []byte {
	t.Helper()
	signature, err := core.SignDigest(privateKey, digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signature
}

func mustDecode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := core.DecodeBase64Url(value, core.ErrJSONString)
	if err != nil {
		t.Fatalf("decode base64url: %v", err)
	}
	return decoded
}

func mustParse(t *testing.T, raw []byte) core.Value {
	t.Helper()
	value, err := core.ParseJSONBytes(raw)
	if err != nil {
		t.Fatalf("parse json %s: %v", string(raw), err)
	}
	return value
}
