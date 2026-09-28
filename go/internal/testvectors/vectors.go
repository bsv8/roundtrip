// Package testvectors loads the shared cross language vectors from
// ../../testdata/vectors.json. The TypeScript suite reads the same file, so both
// implementations are pinned to one set of bytes.
package testvectors

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// Key is one throw away test identity.
type Key struct {
	Name               string `json:"name"`
	PrivateKeyHex      string `json:"privateKeyHex"`
	PublicKeyHex       string `json:"publicKeyHex"`
	PublicKeyBase64Url string `json:"publicKeyBase64Url"`
}

// Number is one RFC 8785 number serialization sample.
type Number struct {
	Ieee754Hex string `json:"ieee754Hex"`
	Value      string `json:"value"`
	Expected   string `json:"expected"`
	Comment    string `json:"comment"`
}

// Jcs is one canonicalization case.
type Jcs struct {
	Name     string `json:"name"`
	Input    string `json:"input"`
	Expected string `json:"expected"`
}

// Unsigned is the unsigned message as stored in the file.
type Unsigned struct {
	From    string          `json:"from"`
	To      string          `json:"to"`
	Nonce   string          `json:"nonce"`
	Expires float64         `json:"expires"`
	ReplyTo string          `json:"reply_to"`
	Body    json.RawMessage `json:"body"`
}

// Message is one signed request, response or trimmed response vector.
type Message struct {
	Name string `json:"name"`
	// Kind is which message the vector pins down, so a reader cannot treat a
	// trimmed response as a base one.
	Kind               string   `json:"kind"`
	Unsigned           Unsigned `json:"unsigned"`
	Wire               string   `json:"wire"`
	SigningBytesHex    string   `json:"signingBytesHex"`
	DigestHex          string   `json:"digestHex"`
	RequestID          string   `json:"requestId"`
	SignatureBase64Url string   `json:"signatureBase64Url"`
	SignatureHex       string   `json:"signatureHex"`
	Envelope           string   `json:"envelope"`
	MessageBase64Url   string   `json:"messageBase64Url"`
}

// Reject is one input both readers must refuse, with the shared error code.
type Reject struct {
	Name  string `json:"name"`
	Input string `json:"input"`
	Code  string `json:"code"`
}

// Rfc8785 is the worked example from the specification.
type Rfc8785 struct {
	Input    string `json:"input"`
	Expected string `json:"expected"`
}

// Vectors is the whole shared file.
type Vectors struct {
	Version               string    `json:"version"`
	ProtocolPrefix        string    `json:"protocolPrefix"`
	TrimmedResponsePrefix string    `json:"trimmedResponsePrefix"`
	Generator             string    `json:"generator"`
	Keys                  []Key     `json:"keys"`
	Rfc8785               Rfc8785   `json:"rfc8785"`
	Numbers               []Number  `json:"numbers"`
	Jcs                   []Jcs     `json:"jcs"`
	Reject                []Reject  `json:"reject"`
	Requests              []Message `json:"requests"`
	Responses             []Message `json:"responses"`
	TrimmedResponses      []Message `json:"trimmedResponses"`
}

// Load reads the shared vectors relative to this source file.
func Load() (Vectors, error) {
	_, thisFile, _, _ := runtime.Caller(0)
	target := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "testdata", "vectors.json")
	raw, err := os.ReadFile(target)
	if err != nil {
		return Vectors{}, err
	}
	var vectors Vectors
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&vectors); err != nil {
		return Vectors{}, err
	}
	return vectors, nil
}

// MustLoad is Load for tests.
func MustLoad() Vectors {
	vectors, err := Load()
	if err != nil {
		panic(err)
	}
	return vectors
}

// KeyByName finds a test key.
func (v Vectors) KeyByName(name string) (Key, bool) {
	for _, key := range v.Keys {
		if key.Name == name {
			return key, true
		}
	}
	return Key{}, false
}

// KeyByPublicKeyBase64Url finds the test key that owns a wire identity string.
func (v Vectors) KeyByPublicKeyBase64Url(value string) (Key, bool) {
	for _, key := range v.Keys {
		if key.PublicKeyBase64Url == value {
			return key, true
		}
	}
	return Key{}, false
}
