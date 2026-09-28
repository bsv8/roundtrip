// Package core implements the minimal signed request/response shell described
// in docs/最简签名请求响应协议.md. Every rule in this package has a counterpart
// in ../typescript/src with the same error codes, and both implementations are
// checked against the shared vectors in ../testdata/vectors.json.
package core

import "fmt"

// Code is a stable failure classification. The TypeScript implementation uses
// the same strings, so a test can assert the same reason in both languages.
type Code string

const (
	ErrJSONInput         Code = "ERR_JSON_INPUT"
	ErrJSONSyntax        Code = "ERR_JSON_SYNTAX"
	ErrJSONDuplicateKey  Code = "ERR_JSON_DUPLICATE_KEY"
	ErrJSONString        Code = "ERR_JSON_STRING"
	ErrJSONNumber        Code = "ERR_JSON_NUMBER"
	ErrJSONDepth         Code = "ERR_JSON_DEPTH"
	ErrEnvelopeNotObject Code = "ERR_ENVELOPE_NOT_OBJECT"
	ErrEnvelopeFieldMiss Code = "ERR_ENVELOPE_FIELD_MISSING"
	ErrEnvelopeFieldUnk  Code = "ERR_ENVELOPE_FIELD_UNKNOWN"
	ErrEnvelopeFieldType Code = "ERR_ENVELOPE_FIELD_TYPE"
	ErrEnvelopeShape     Code = "ERR_ENVELOPE_SHAPE"
	ErrPublicKey         Code = "ERR_PUBLIC_KEY"
	ErrNonce             Code = "ERR_NONCE"
	ErrExpires           Code = "ERR_EXPIRES"
	ErrReplyTo           Code = "ERR_REPLY_TO"
	ErrSignatureFormat   Code = "ERR_SIGNATURE_FORMAT"
	ErrBody              Code = "ERR_BODY"
	ErrMessageTooLarge   Code = "ERR_MESSAGE_TOO_LARGE"
	ErrSignature         Code = "ERR_SIGNATURE"
	ErrRecipient         Code = "ERR_RECIPIENT"
	ErrExpired           Code = "ERR_EXPIRED"
	ErrExpiryWindow      Code = "ERR_EXPIRY_WINDOW"
	ErrReplayed          Code = "ERR_REPLAYED"
	ErrCallTimeout       Code = "ERR_CALL_TIMEOUT"
	ErrCallAborted       Code = "ERR_CALL_ABORTED"
	ErrTransport         Code = "ERR_TRANSPORT"
	ErrResponseSize      Code = "ERR_RESPONSE_SIZE"
	ErrResponseFrom      Code = "ERR_RESPONSE_FROM"
	ErrResponseTo        Code = "ERR_RESPONSE_TO"
	ErrResponseReplyTo   Code = "ERR_RESPONSE_REPLY_TO"
	ErrResponseSignature Code = "ERR_RESPONSE_SIGNATURE"
	ErrResponseShape     Code = "ERR_RESPONSE_SHAPE"
	ErrSignerKey         Code = "ERR_SIGNER_KEY"
	ErrSignerFailed      Code = "ERR_SIGNER_FAILED"
	ErrCallerIdentity    Code = "ERR_CALLER_IDENTITY"
	ErrNoHandler         Code = "ERR_NO_HANDLER"
	ErrFrame             Code = "ERR_FRAME"
	ErrHTTPStatus        Code = "ERR_HTTP_STATUS"
)

// Codes is the full list, mirrored by ROUNDTRIP_ERROR_CODES in TypeScript.
var Codes = []Code{
	ErrJSONInput, ErrJSONSyntax, ErrJSONDuplicateKey, ErrJSONString, ErrJSONNumber,
	ErrJSONDepth, ErrEnvelopeNotObject, ErrEnvelopeFieldMiss, ErrEnvelopeFieldUnk,
	ErrEnvelopeFieldType, ErrEnvelopeShape, ErrPublicKey, ErrNonce, ErrExpires,
	ErrReplyTo, ErrSignatureFormat, ErrBody, ErrMessageTooLarge, ErrSignature,
	ErrRecipient, ErrExpired, ErrExpiryWindow, ErrReplayed, ErrCallTimeout,
	ErrCallAborted, ErrTransport, ErrResponseSize, ErrResponseFrom, ErrResponseTo,
	ErrResponseReplyTo, ErrResponseSignature, ErrResponseShape, ErrSignerKey,
	ErrSignerFailed, ErrCallerIdentity, ErrNoHandler, ErrFrame, ErrHTTPStatus,
}

// Error carries a stable code plus a human readable reason.
type Error struct {
	Code Code
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Err.Error())
}

func (e *Error) Unwrap() error { return e.Err }

func failf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}

// CodeOf reports the stable code of an error, or an empty Code when the error
// did not come from this package.
func CodeOf(err error) Code {
	for err != nil {
		if typed, ok := err.(*Error); ok {
			return typed.Code
		}
		unwrapped, ok := err.(interface{ Unwrap() error })
		if !ok {
			return ""
		}
		err = unwrapped.Unwrap()
	}
	return ""
}
