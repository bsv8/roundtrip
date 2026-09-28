package core

import (
	"math"
	"sort"
	"strings"
)

// SigningPrefix isolates the protocol and its version. It never travels on the
// wire and there is no version negotiation.
const SigningPrefix = "roundtrip/v1\n"

// TrimmedResponsePrefix is the second, separate prefix for the optional trimmed
// HTTPS response.
//
// It exists so a trimmed response cannot be mistaken for a base request or a
// base response: the signed bytes differ, so a signature made for one is never
// valid for the other. It is a message layer concern only; no transport in this
// version produces or accepts it.
const TrimmedResponsePrefix = "roundtrip/http-response/v1\n"

// Nonce and digest size limits.
const (
	MinNonceBytes    = 16
	MaxNonceBytes    = 64
	DigestBytes      = 32
	RequestFields    = 6
	ResponseFields   = 5
	TrimmedFields    = 4
	requestFieldList = "from,to,nonce,expires,body,sig"
)

var (
	requestFieldSet  = map[string]bool{"from": true, "to": true, "nonce": true, "expires": true, "body": true, "sig": true}
	responseFieldSet = map[string]bool{"from": true, "to": true, "reply_to": true, "body": true, "sig": true}
	trimmedFieldSet  = map[string]bool{"from": true, "to": true, "body": true, "sig": true}
	trimmedFieldList = "from,to,body,sig"
)

// UnsignedRequest is a request without its signature.
type UnsignedRequest struct {
	From    []byte
	To      []byte
	Nonce   []byte
	Expires int64
	Body    Value
}

// UnsignedResponse is a base response without its signature.
type UnsignedResponse struct {
	From    []byte
	To      []byte
	ReplyTo []byte
	Body    Value
}

// UnsignedTrimmedResponse is the optional trusted HTTPS response: no ReplyTo,
// because the correlation is carried by the transport instead of the signature.
//
// Dropping the field also drops the proof that the response answers a
// particular request. That is the documented trade off, and it is why the base
// reader keeps refusing this shape.
type UnsignedTrimmedResponse struct {
	From []byte
	To   []byte
	Body Value
}

// RequestEnvelope is a parsed signed request.
type RequestEnvelope struct {
	Unsigned  UnsignedRequest
	Signature []byte
}

// ResponseEnvelope is a parsed signed base response.
type ResponseEnvelope struct {
	Unsigned  UnsignedResponse
	Signature []byte
}

// TrimmedResponseEnvelope is a parsed signed trimmed response.
type TrimmedResponseEnvelope struct {
	Unsigned  UnsignedTrimmedResponse
	Signature []byte
}

// SigningPrefixOf is the prefix that separates the message kinds in the signed
// bytes.
func SigningPrefixOf(unsigned any) (string, error) {
	switch unsigned.(type) {
	case UnsignedRequest, UnsignedResponse:
		return SigningPrefix, nil
	case UnsignedTrimmedResponse:
		return TrimmedResponsePrefix, nil
	default:
		return "", failf(ErrEnvelopeShape, "unsupported unsigned message type %T", unsigned)
	}
}

// UnsignedToWire is the exact object that gets canonicalized and hashed.
func UnsignedToWire(unsigned any) (Value, error) {
	switch typed := unsigned.(type) {
	case UnsignedRequest:
		object := NewObject()
		object.Set("from", StringValue(EncodeBase64Url(typed.From)))
		object.Set("to", StringValue(EncodeBase64Url(typed.To)))
		object.Set("nonce", StringValue(EncodeBase64Url(typed.Nonce)))
		object.Set("expires", NumberValue(float64(typed.Expires)))
		object.Set("body", typed.Body)
		return object, nil
	case UnsignedResponse:
		object := NewObject()
		object.Set("from", StringValue(EncodeBase64Url(typed.From)))
		object.Set("to", StringValue(EncodeBase64Url(typed.To)))
		object.Set("reply_to", StringValue(EncodeBase64Url(typed.ReplyTo)))
		object.Set("body", typed.Body)
		return object, nil
	case UnsignedTrimmedResponse:
		object := NewObject()
		object.Set("from", StringValue(EncodeBase64Url(typed.From)))
		object.Set("to", StringValue(EncodeBase64Url(typed.To)))
		object.Set("body", typed.Body)
		return object, nil
	default:
		return Value{}, failf(ErrEnvelopeShape, "unsupported unsigned message type %T", unsigned)
	}
}

// SignedToWire is the complete envelope object.
func SignedToWire(unsigned any, signature []byte) (Value, error) {
	if _, err := ParseDerSignature(signature); err != nil {
		return Value{}, err
	}
	object, err := UnsignedToWire(unsigned)
	if err != nil {
		return Value{}, err
	}
	object.Set("sig", StringValue(EncodeBase64Url(signature)))
	return object, nil
}

// SigningBytes is UTF8(prefix) || JCS(unsigned), where the prefix follows the
// message kind.
func SigningBytes(unsigned any) ([]byte, error) {
	prefix, err := SigningPrefixOf(unsigned)
	if err != nil {
		return nil, err
	}
	object, err := UnsignedToWire(unsigned)
	if err != nil {
		return nil, err
	}
	canonical, err := Canonicalize(object)
	if err != nil {
		return nil, err
	}
	return Concat([]byte(prefix), canonical), nil
}

// DigestOf is the single SHA-256 over the signing bytes.
func DigestOf(unsigned any) ([]byte, error) {
	bytes, err := SigningBytes(unsigned)
	if err != nil {
		return nil, err
	}
	return Sha256Bytes(bytes), nil
}

// RequestIDOf is base64url(SHA256(signing bytes)). It is the request id, and
// there is no second id field.
func RequestIDOf(unsigned UnsignedRequest) (string, error) {
	digest, err := DigestOf(unsigned)
	if err != nil {
		return "", err
	}
	return EncodeBase64Url(digest), nil
}

// EncodeEnvelopeBytes renders the signed envelope as canonical JSON bytes.
func EncodeEnvelopeBytes(unsigned any, signature []byte) ([]byte, error) {
	object, err := SignedToWire(unsigned, signature)
	if err != nil {
		return nil, err
	}
	return Canonicalize(object)
}

// ParseRequest is the strict reader for a signed request.
//
// The shape is fixed: exactly from, to, nonce, expires, body and sig. There is
// no reply_to, no type, no id and no version, and an unknown top level field is
// a protocol error rather than something to ignore.
func ParseRequest(value Value) (RequestEnvelope, error) {
	var result RequestEnvelope
	if value.Kind != KindObject {
		return result, failf(ErrEnvelopeNotObject, "envelope must be a JSON object")
	}
	if err := assertFields(value, requestFieldSet, requestFieldList); err != nil {
		return result, err
	}
	nonce, err := readBase64Field(value, "nonce", ErrNonce)
	if err != nil {
		return result, err
	}
	if len(nonce) < MinNonceBytes || len(nonce) > MaxNonceBytes {
		return result, failf(ErrNonce, "nonce must be %d..%d bytes", MinNonceBytes, MaxNonceBytes)
	}
	expiresValue, _ := value.Member("expires")
	if expiresValue.Kind != KindNumber {
		return result, failf(ErrExpires, "expires must be an integer number of unix seconds")
	}
	if math.IsNaN(expiresValue.Number) || math.IsInf(expiresValue.Number, 0) || expiresValue.Number != math.Trunc(expiresValue.Number) {
		return result, failf(ErrExpires, "expires must be an integer number of unix seconds")
	}
	if expiresValue.Number < 0 || expiresValue.Number > MaxSafeInteger {
		return result, failf(ErrExpires, "expires is out of range")
	}
	from, err := readPublicKeyField(value, "from")
	if err != nil {
		return result, err
	}
	to, err := readPublicKeyField(value, "to")
	if err != nil {
		return result, err
	}
	body, _ := value.Member("body")
	if err := checkRequestBody(body); err != nil {
		return result, err
	}
	signature, err := readSignatureField(value)
	if err != nil {
		return result, err
	}
	result.Unsigned = UnsignedRequest{From: from, To: to, Nonce: nonce, Expires: int64(expiresValue.Number), Body: body}
	result.Signature = signature
	return result, nil
}

// ParseResponse is the strict reader for a signed base response.
func ParseResponse(value Value) (ResponseEnvelope, error) {
	var result ResponseEnvelope
	if value.Kind != KindObject {
		return result, failf(ErrEnvelopeNotObject, "envelope must be a JSON object")
	}
	if err := assertFields(value, responseFieldSet, "from,to,reply_to,body,sig"); err != nil {
		return result, err
	}
	replyTo, err := readBase64Field(value, "reply_to", ErrReplyTo)
	if err != nil {
		return result, err
	}
	if len(replyTo) != DigestBytes {
		return result, failf(ErrReplyTo, "reply_to must be a %d byte digest", DigestBytes)
	}
	from, err := readPublicKeyField(value, "from")
	if err != nil {
		return result, err
	}
	to, err := readPublicKeyField(value, "to")
	if err != nil {
		return result, err
	}
	body, _ := value.Member("body")
	if err := CheckResponseBody(body); err != nil {
		return result, err
	}
	signature, err := readSignatureField(value)
	if err != nil {
		return result, err
	}
	result.Unsigned = UnsignedResponse{From: from, To: to, ReplyTo: replyTo, Body: body}
	result.Signature = signature
	return result, nil
}

// ParseTrimmedResponse is the strict reader for the optional trimmed response:
// exactly from, to, body and sig.
//
// It is a separate reader on purpose. reply_to is refused here, and this shape
// is refused by ParseRequest and ParseResponse, so a trimmed response can never
// be accepted as a base message or the other way round.
func ParseTrimmedResponse(value Value) (TrimmedResponseEnvelope, error) {
	var result TrimmedResponseEnvelope
	if value.Kind != KindObject {
		return result, failf(ErrEnvelopeNotObject, "envelope must be a JSON object")
	}
	if err := assertFields(value, trimmedFieldSet, trimmedFieldList); err != nil {
		return result, err
	}
	from, err := readPublicKeyField(value, "from")
	if err != nil {
		return result, err
	}
	to, err := readPublicKeyField(value, "to")
	if err != nil {
		return result, err
	}
	body, _ := value.Member("body")
	if err := CheckResponseBody(body); err != nil {
		return result, err
	}
	signature, err := readSignatureField(value)
	if err != nil {
		return result, err
	}
	result.Unsigned = UnsignedTrimmedResponse{From: from, To: to, Body: body}
	result.Signature = signature
	return result, nil
}

// TrimmedResponseExpectation names the two identities a trimmed response is
// allowed to be between.
type TrimmedResponseExpectation struct {
	// To is this node's own identity; the response must be addressed to it.
	To []byte
	// From is the peer the call was addressed to; the response must come from it.
	From []byte
}

// VerifyTrimmedResponse reads and verifies a trimmed response and returns its
// business body.
//
// There is deliberately no request id to check: with reply_to gone, the
// signature no longer proves which request this answers. The correlation belongs
// to the trusted transport, so the caller has to be sure the bytes came from the
// call it is completing. From and To are still enforced, because a signed
// identity substitutes for neither of them.
func VerifyTrimmedResponse(value Value, expected TrimmedResponseExpectation) (Value, error) {
	envelope, err := ParseTrimmedResponse(value)
	if err != nil {
		return Value{}, err
	}
	if !EqualBytes(envelope.Unsigned.To, expected.To) {
		return Value{}, failf(ErrResponseTo, "response is not addressed to this identity")
	}
	if !EqualBytes(envelope.Unsigned.From, expected.From) {
		return Value{}, failf(ErrResponseFrom, "response did not come from the requested peer")
	}
	digest, err := DigestOf(envelope.Unsigned)
	if err != nil {
		return Value{}, err
	}
	if err := VerifyDigest(envelope.Unsigned.From, digest, envelope.Signature); err != nil {
		return Value{}, &Error{Code: ErrResponseSignature, Err: err}
	}
	return envelope.Unsigned.Body, nil
}

func assertFields(value Value, allowed map[string]bool, list string) error {
	for field := range allowed {
		if _, ok := value.Member(field); !ok {
			return failf(ErrEnvelopeFieldMiss, "envelope is missing %s (expected exactly %s)", field, list)
		}
	}
	for _, key := range value.Keys {
		if !allowed[key] {
			return failf(ErrEnvelopeFieldUnk, "envelope has an unknown top level field: %s", key)
		}
	}
	return nil
}

func readStringField(value Value, field string) (string, error) {
	member, _ := value.Member(field)
	if member.Kind != KindString {
		return "", failf(ErrEnvelopeFieldType, "%s must be a string", field)
	}
	return member.Str, nil
}

func readBase64Field(value Value, field string, code Code) ([]byte, error) {
	text, err := readStringField(value, field)
	if err != nil {
		return nil, err
	}
	return DecodeBase64Url(text, code)
}

func readPublicKeyField(value Value, field string) ([]byte, error) {
	decoded, err := readBase64Field(value, field, ErrPublicKey)
	if err != nil {
		return nil, err
	}
	if len(decoded) != PublicKeyBytes {
		return nil, failf(ErrPublicKey, "%s must be a %d byte compressed SEC1 key", field, PublicKeyBytes)
	}
	if err := ValidatePublicKey(decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

func readSignatureField(value Value) ([]byte, error) {
	signature, err := readBase64Field(value, "sig", ErrSignatureFormat)
	if err != nil {
		return nil, err
	}
	if _, err := ParseDerSignature(signature); err != nil {
		return nil, err
	}
	return signature, nil
}

func checkRequestBody(body Value) error {
	if body.Kind != KindObject {
		return failf(ErrBody, "request body must be a JSON object")
	}
	op, ok := body.Member("op")
	if !ok || op.Kind != KindString || op.Str == "" {
		return failf(ErrBody, "request body must carry a non empty string op")
	}
	return nil
}

// BusinessError is the failure carried inside a signed response body.
type BusinessError struct {
	Code    string
	Message string
}

// Outcome is a handler result: a success result or a signed business error.
type Outcome struct {
	OK     bool
	Result Value
	Error  BusinessError
}

// CheckResponseBody validates the base response body.
//
// A successful response is {"ok":true,"result":...} and a failed one is
// {"ok":false,"error":{"code":"...","message":"..."}}. Nothing else: the caller
// must be able to tell a signed business failure from a transport error page.
func CheckResponseBody(body Value) error {
	if body.Kind != KindObject {
		return failf(ErrResponseShape, "response body must be a JSON object")
	}
	ok, present := body.Member("ok")
	if !present || ok.Kind != KindBool {
		return failf(ErrResponseShape, "response body must carry a boolean ok")
	}
	if ok.Bool {
		if _, present := body.Member("result"); !present {
			return failf(ErrResponseShape, "a successful response must carry result")
		}
		for _, key := range body.Keys {
			if key != "ok" && key != "result" {
				return failf(ErrResponseShape, "a successful response has an unexpected field: %s", key)
			}
		}
		return nil
	}
	if _, present := body.Member("result"); present {
		return failf(ErrResponseShape, "a failed response must not carry result")
	}
	errorValue, present := body.Member("error")
	if !present || errorValue.Kind != KindObject {
		return failf(ErrResponseShape, "a failed response must carry an error object")
	}
	for _, key := range errorValue.Keys {
		if key != "code" && key != "message" {
			return failf(ErrResponseShape, "error has an unexpected field: %s", key)
		}
	}
	code, codePresent := errorValue.Member("code")
	if !codePresent || code.Kind != KindString || code.Str == "" {
		return failf(ErrResponseShape, "error.code must be a non empty string")
	}
	message, messagePresent := errorValue.Member("message")
	if !messagePresent || message.Kind != KindString {
		return failf(ErrResponseShape, "error.message must be a string")
	}
	return nil
}

// OutcomeToBody renders an outcome as a response body.
func OutcomeToBody(outcome Outcome) Value {
	body := NewObject()
	if outcome.OK {
		body.Set("ok", Value{Kind: KindBool, Bool: true})
		body.Set("result", outcome.Result)
		return body
	}
	body.Set("ok", Value{Kind: KindBool, Bool: false})
	errorValue := NewObject()
	errorValue.Set("code", StringValue(outcome.Error.Code))
	errorValue.Set("message", StringValue(outcome.Error.Message))
	body.Set("error", errorValue)
	return body
}

// BodyToOutcome reads a validated response body.
func BodyToOutcome(body Value) (Outcome, error) {
	if err := CheckResponseBody(body); err != nil {
		return Outcome{}, err
	}
	ok, _ := body.Member("ok")
	if ok.Bool {
		result, _ := body.Member("result")
		return Outcome{OK: true, Result: result}, nil
	}
	errorValue, _ := body.Member("error")
	code, _ := errorValue.Member("code")
	message, _ := errorValue.Member("message")
	return Outcome{Error: BusinessError{Code: code.Str, Message: message.Str}}, nil
}

// SortedKeys is a diagnostic helper for tests.
func SortedKeys(value Value) []string {
	keys := append([]string(nil), value.Keys...)
	sort.Strings(keys)
	return keys
}

// JoinFields is a diagnostic helper.
func JoinFields(fields []string) string { return strings.Join(fields, ",") }
