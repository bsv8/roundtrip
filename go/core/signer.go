package core

// Signer is the only capability the core needs. The core never sees a private
// key, and it never accepts arbitrary bytes: a signer is handed a validated
// unsigned request or unsigned response and returns a signature over exactly
// those fields.
type Signer interface {
	PublicKey() []byte
	SignRoundtrip(unsigned any) ([]byte, error)
}

// LocalSigner signs in process.
//
// It is meant for tests, examples and single process deployments, and is
// deliberately not suitable for a browser or any untrusted environment. Keys
// created for tests and examples are throw away material.
type LocalSigner struct {
	privateKey []byte
	publicKey  []byte
}

// NewLocalSigner builds a signer from a 32 byte secp256k1 scalar.
func NewLocalSigner(privateKey []byte) (*LocalSigner, error) {
	publicKey, err := PublicKeyFromPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	stored := make([]byte, len(privateKey))
	copy(stored, privateKey)
	return &LocalSigner{privateKey: stored, publicKey: publicKey}, nil
}

// PublicKey returns a copy of the compressed SEC1 identity.
func (s *LocalSigner) PublicKey() []byte {
	result := make([]byte, len(s.publicKey))
	copy(result, s.publicKey)
	return result
}

// SignRoundtrip validates the message shape again inside the signer, then signs
// the canonical bytes over one SHA-256 digest.
func (s *LocalSigner) SignRoundtrip(unsigned any) ([]byte, error) {
	if err := assertSignable(unsigned); err != nil {
		return nil, err
	}
	digest, err := DigestOf(unsigned)
	if err != nil {
		return nil, err
	}
	return SignDigest(s.privateKey, digest)
}

func assertSignable(unsigned any) error {
	switch typed := unsigned.(type) {
	case UnsignedRequest:
		if len(typed.From) != PublicKeyBytes || len(typed.To) != PublicKeyBytes {
			return failf(ErrSignerFailed, "unsigned request must carry 33-byte public keys")
		}
		if len(typed.Nonce) < MinNonceBytes {
			return failf(ErrSignerFailed, "unsigned request must carry a nonce")
		}
		if typed.Body.Kind == 255 {
			return failf(ErrSignerFailed, "unsigned request must carry a body")
		}
	case UnsignedResponse:
		if len(typed.From) != PublicKeyBytes || len(typed.To) != PublicKeyBytes {
			return failf(ErrSignerFailed, "unsigned response must carry 33-byte public keys")
		}
		if len(typed.ReplyTo) != DigestBytes {
			return failf(ErrSignerFailed, "unsigned response must carry a reply_to digest")
		}
		if typed.Body.Kind == 255 {
			return failf(ErrSignerFailed, "unsigned response must carry a body")
		}
	case UnsignedTrimmedResponse:
		// Only a request carries a nonce. A base response quotes a request id
		// and a trimmed response quotes nothing, so neither has one to check.
		if len(typed.From) != PublicKeyBytes || len(typed.To) != PublicKeyBytes {
			return failf(ErrSignerFailed, "unsigned trimmed response must carry 33-byte public keys")
		}
		if typed.Body.Kind == 255 {
			return failf(ErrSignerFailed, "unsigned trimmed response must carry a body")
		}
	default:
		return failf(ErrSignerFailed, "signer only accepts a validated unsigned request, response or trimmed response")
	}
	return nil
}
