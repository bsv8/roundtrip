package core

import (
	"crypto/sha256"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// Secp256k1Order is the group order.
var Secp256k1Order = secp256k1.S256().N

// PublicKeyBytes is the compressed SEC1 length.
const PublicKeyBytes = 33

// Sha256Bytes is one SHA-256 over the signed bytes.
func Sha256Bytes(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:]
}

// ValidatePrivateKey checks the 32 byte secp256k1 scalar shape. The scalar must
// be in 1..n-1; SetByteSlice reports overflow, so an out of range value is
// rejected instead of being reduced modulo n.
func ValidatePrivateKey(privateKey []byte) error {
	if len(privateKey) != 32 {
		return failf(ErrSignerKey, "private key must be exactly 32 bytes")
	}
	var scalar secp256k1.ModNScalar
	if scalar.SetByteSlice(privateKey) {
		return failf(ErrSignerKey, "private key scalar is outside 1..n-1")
	}
	if scalar.IsZero() {
		return failf(ErrSignerKey, "private key scalar is outside 1..n-1")
	}
	return nil
}

// PublicKeyFromPrivateKey returns the compressed SEC1 point.
func PublicKeyFromPrivateKey(privateKey []byte) ([]byte, error) {
	if err := ValidatePrivateKey(privateKey); err != nil {
		return nil, err
	}
	return secp256k1.PrivKeyFromBytes(privateKey).PubKey().SerializeCompressed(), nil
}

// ValidatePublicKey requires a canonical 33 byte compressed point on the curve.
func ValidatePublicKey(publicKey []byte) error {
	if len(publicKey) != PublicKeyBytes || (publicKey[0] != 0x02 && publicKey[0] != 0x03) {
		return failf(ErrPublicKey, "public key must be a compressed 33-byte SEC1 point")
	}
	parsed, err := secp256k1.ParsePubKey(publicKey)
	if err != nil {
		return &Error{Code: ErrPublicKey, Err: err}
	}
	if !EqualBytes(parsed.SerializeCompressed(), publicKey) {
		return failf(ErrPublicKey, "public key is not the canonical compressed encoding of its point")
	}
	return nil
}

// DerSignature holds the parsed scalars.
type DerSignature struct {
	R *big.Int
	S *big.Int
}

// ParseDerSignature is a strict DER reader: minimal lengths, positive
// integers, in range scalars and low-S.
func ParseDerSignature(signature []byte) (DerSignature, error) {
	var result DerSignature
	fail := func(message string) (DerSignature, error) {
		return DerSignature{}, failf(ErrSignatureFormat, "%s", message)
	}
	if len(signature) < 8 || len(signature) > 72 {
		return fail("DER signature length is out of range")
	}
	if signature[0] != 0x30 {
		return fail("DER sequence tag is missing")
	}
	if int(signature[1]) != len(signature)-2 {
		return fail("DER sequence length is not strict")
	}
	offset := 2
	readInteger := func() (*big.Int, error) {
		if offset >= len(signature) || signature[offset] != 0x02 {
			return nil, failf(ErrSignatureFormat, "DER integer tag is missing")
		}
		offset++
		if offset >= len(signature) {
			return nil, failf(ErrSignatureFormat, "DER integer length is malformed")
		}
		length := int(signature[offset])
		offset++
		if length == 0 || length > 33 || offset+length > len(signature) {
			return nil, failf(ErrSignatureFormat, "DER integer length is malformed")
		}
		body := signature[offset : offset+length]
		if body[0]&0x80 != 0 {
			return nil, failf(ErrSignatureFormat, "DER integer is negative")
		}
		if body[0] == 0x00 && (length == 1 || body[1]&0x80 == 0) {
			return nil, failf(ErrSignatureFormat, "DER integer is not minimally encoded")
		}
		offset += length
		return new(big.Int).SetBytes(body), nil
	}
	var err error
	if result.R, err = readInteger(); err != nil {
		return DerSignature{}, err
	}
	if result.S, err = readInteger(); err != nil {
		return DerSignature{}, err
	}
	if offset != len(signature) {
		return fail("DER signature has trailing bytes")
	}
	order := Secp256k1Order
	halfOrder := new(big.Int).Rsh(order, 1)
	if result.R.Sign() <= 0 || result.R.Cmp(order) >= 0 {
		return fail("DER r scalar is out of range")
	}
	if result.S.Sign() <= 0 || result.S.Cmp(halfOrder) > 0 {
		return fail("DER s scalar is out of range or high-S")
	}
	return result, nil
}

// SignDigest is RFC 6979 deterministic ECDSA over one SHA-256 digest, emitted
// as strict DER with low-S.
//
// Both libraries in this repository derive the nonce the same way, so the same
// key and digest produce the same bytes; the shared vectors pin that down.
func SignDigest(privateKey, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, failf(ErrSignerFailed, "digest must be 32 bytes")
	}
	if err := ValidatePrivateKey(privateKey); err != nil {
		return nil, err
	}
	compact := ecdsa.SignCompact(secp256k1.PrivKeyFromBytes(privateKey), digest, true)
	var r, s secp256k1.ModNScalar
	r.SetByteSlice(compact[1:33])
	s.SetByteSlice(compact[33:65])
	if s.IsOverHalfOrder() {
		// Normalize to low-S so one message has exactly one accepted signature.
		s.Negate()
	}
	return ecdsa.NewSignature(&r, &s).Serialize(), nil
}

// VerifyDigest reports whether digest was signed by publicKey. It returns
// ErrSignature for every failure, so callers cannot tell a malformed encoding
// from a wrong key by timing the error type.
func VerifyDigest(publicKey, digest, signature []byte) error {
	if len(digest) != 32 {
		return failf(ErrSignature, "digest must be 32 bytes")
	}
	if _, err := ParseDerSignature(signature); err != nil {
		return &Error{Code: ErrSignature, Err: err}
	}
	if err := ValidatePublicKey(publicKey); err != nil {
		return err
	}
	parsed, err := ParseDerSignature(signature)
	if err != nil {
		return &Error{Code: ErrSignature, Err: err}
	}
	key, err := secp256k1.ParsePubKey(publicKey)
	if err != nil {
		return &Error{Code: ErrSignature, Err: err}
	}
	var r, s secp256k1.ModNScalar
	if overflow := r.SetByteSlice(parsed.R.Bytes()); overflow {
		return failf(ErrSignature, "signature verification failed")
	}
	if overflow := s.SetByteSlice(parsed.S.Bytes()); overflow {
		return failf(ErrSignature, "signature verification failed")
	}
	if !ecdsa.NewSignature(&r, &s).Verify(digest, key) {
		return failf(ErrSignature, "signature verification failed")
	}
	return nil
}
