package core

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
)

const base64UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// EncodeBase64Url is unpadded base64url, the only binary representation used on
// the wire.
func EncodeBase64Url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// DecodeBase64Url decodes unpadded base64url and rejects every non canonical
// spelling, so one byte string has exactly one identity string.
func DecodeBase64Url(value string, code Code) ([]byte, error) {
	if len(value)%4 == 1 {
		return nil, failf(code, "base64url length is impossible")
	}
	for index := 0; index < len(value); index++ {
		if !strings.ContainsRune(base64UrlAlphabet, rune(value[index])) {
			return nil, failf(code, "base64url contains a character outside the unpadded url-safe alphabet")
		}
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, failf(code, "base64url is not the canonical encoding of these bytes")
	}
	if EncodeBase64Url(decoded) != value {
		// Catches non zero padding bits, which DecodeString tolerates.
		return nil, failf(code, "base64url is not the canonical encoding of these bytes")
	}
	return decoded, nil
}

// BytesToHex renders lowercase hex.
func BytesToHex(data []byte) string { return hex.EncodeToString(data) }

// HexToBytes parses lowercase or uppercase hex.
func HexToBytes(value string) ([]byte, error) {
	if len(value)%2 != 0 {
		return nil, failf(ErrJSONString, "hex value is malformed")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, failf(ErrJSONString, "hex value is malformed")
	}
	return decoded, nil
}

// MustHexToBytes is HexToBytes for fixed test vectors.
func MustHexToBytes(value string) []byte {
	decoded, err := HexToBytes(value)
	if err != nil {
		panic(err)
	}
	return decoded
}

// EqualBytes compares two byte slices.
func EqualBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// Concat joins byte slices.
func Concat(parts ...[]byte) []byte {
	total := 0
	for _, part := range parts {
		total += len(part)
	}
	result := make([]byte, 0, total)
	for _, part := range parts {
		result = append(result, part...)
	}
	return result
}
