package core

import (
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Kind enumerates the JSON value types.
type Kind uint8

const (
	KindNull Kind = iota
	KindBool
	KindNumber
	KindString
	KindArray
	KindObject
)

// Value is a parsed JSON value. Object members keep their input order only so
// error messages can name the offending key; canonicalization sorts them.
type Value struct {
	Kind   Kind
	Bool   bool
	Number float64
	Str    string
	Array  []Value
	Object map[string]Value
	// Keys preserves the member order of the source text.
	Keys []string
}

// MaxSafeInteger is 2^53-1. RFC 8785 defers number output to the ECMAScript
// Number::toString algorithm, which is defined for every finite double, so JCS
// itself does not restrict the integer range. This constant is the sanity bound
// used for the expires timestamp; applications that need exact money or big
// integers must send them as strings.
const MaxSafeInteger = 9007199254740991

// MaxJSONDepth bounds nesting so a 1 MiB payload cannot become unbounded
// recursion.
const MaxJSONDepth = 64

// NewObject builds an empty object value.
func NewObject() Value {
	return Value{Kind: KindObject, Object: map[string]Value{}}
}

// Set adds or replaces an object member. Insertion order is preserved.
func (v *Value) Set(key string, member Value) {
	if v.Object == nil {
		v.Object = map[string]Value{}
	}
	if _, exists := v.Object[key]; !exists {
		v.Keys = append(v.Keys, key)
	}
	v.Object[key] = member
}

// Member returns an object member.
func (v Value) Member(key string) (Value, bool) {
	if v.Kind != KindObject {
		return Value{}, false
	}
	member, ok := v.Object[key]
	return member, ok
}

// StringValue builds a string value.
func StringValue(text string) Value { return Value{Kind: KindString, Str: text} }

// NumberValue builds a number value.
func NumberValue(number float64) Value { return Value{Kind: KindNumber, Number: number} }

// ParseJSONBytes is the entry point used for transport payloads. Invalid UTF-8
// is rejected before parsing.
func ParseJSONBytes(data []byte) (Value, error) {
	if !utf8.Valid(data) {
		return Value{}, failf(ErrJSONInput, "message is not valid UTF-8")
	}
	return ParseJSON(string(data))
}

// ParseJSON is a strict JSON reader.
//
// encoding/json is not used on purpose: it silently keeps the last value of a
// duplicated object key, and it accepts input that a second implementation
// would read differently. Two readers must never disagree about the bytes that
// get signed.
func ParseJSON(text string) (Value, error) {
	reader := jsonReader{text: text}
	reader.skipWhitespace()
	value, err := reader.readValue(0)
	if err != nil {
		return Value{}, err
	}
	reader.skipWhitespace()
	if !reader.atEnd() {
		return Value{}, failf(ErrJSONSyntax, "trailing bytes after the JSON value at offset %d", reader.index)
	}
	return value, nil
}

type jsonReader struct {
	text  string
	index int
}

func (r *jsonReader) atEnd() bool { return r.index >= len(r.text) }

func (r *jsonReader) fail(format string, args ...any) error {
	return failf(ErrJSONSyntax, format+" at offset %d", append(args, r.index)...)
}

func (r *jsonReader) skipWhitespace() {
	for r.index < len(r.text) {
		switch r.text[r.index] {
		case ' ', '\t', '\n', '\r':
			r.index++
		default:
			return
		}
	}
}

func (r *jsonReader) readValue(depth int) (Value, error) {
	if depth > MaxJSONDepth {
		return Value{}, failf(ErrJSONDepth, "JSON nesting exceeds %d", MaxJSONDepth)
	}
	if r.atEnd() {
		return Value{}, r.fail("expected a JSON value")
	}
	switch r.text[r.index] {
	case '{':
		return r.readObject(depth)
	case '[':
		return r.readArray(depth)
	case '"':
		text, err := r.readString()
		if err != nil {
			return Value{}, err
		}
		return StringValue(text), nil
	case 't':
		return r.readLiteral("true", Value{Kind: KindBool, Bool: true})
	case 'f':
		return r.readLiteral("false", Value{Kind: KindBool, Bool: false})
	case 'n':
		return r.readLiteral("null", Value{Kind: KindNull})
	default:
		return r.readNumber()
	}
}

func (r *jsonReader) readLiteral(word string, value Value) (Value, error) {
	if !strings.HasPrefix(r.text[r.index:], word) {
		return Value{}, r.fail("expected %s", word)
	}
	r.index += len(word)
	return value, nil
}

func (r *jsonReader) readObject(depth int) (Value, error) {
	r.index++
	result := NewObject()
	r.skipWhitespace()
	if r.index < len(r.text) && r.text[r.index] == '}' {
		r.index++
		return result, nil
	}
	for {
		r.skipWhitespace()
		if r.index >= len(r.text) || r.text[r.index] != '"' {
			return Value{}, r.fail("expected an object key")
		}
		key, err := r.readString()
		if err != nil {
			return Value{}, err
		}
		if _, exists := result.Object[key]; exists {
			return Value{}, failf(ErrJSONDuplicateKey, "duplicated object key: %s", key)
		}
		r.skipWhitespace()
		if r.index >= len(r.text) || r.text[r.index] != ':' {
			return Value{}, r.fail(`expected ":"`)
		}
		r.index++
		r.skipWhitespace()
		member, err := r.readValue(depth + 1)
		if err != nil {
			return Value{}, err
		}
		result.Set(key, member)
		r.skipWhitespace()
		if r.index >= len(r.text) {
			return Value{}, r.fail("unterminated object")
		}
		switch r.text[r.index] {
		case ',':
			r.index++
			continue
		case '}':
			r.index++
			return result, nil
		default:
			return Value{}, r.fail(`expected "," or "}"`)
		}
	}
}

func (r *jsonReader) readArray(depth int) (Value, error) {
	r.index++
	result := Value{Kind: KindArray, Array: []Value{}}
	r.skipWhitespace()
	if r.index < len(r.text) && r.text[r.index] == ']' {
		r.index++
		return result, nil
	}
	for {
		r.skipWhitespace()
		item, err := r.readValue(depth + 1)
		if err != nil {
			return Value{}, err
		}
		result.Array = append(result.Array, item)
		r.skipWhitespace()
		if r.index >= len(r.text) {
			return Value{}, r.fail("unterminated array")
		}
		switch r.text[r.index] {
		case ',':
			r.index++
			continue
		case ']':
			r.index++
			return result, nil
		default:
			return Value{}, r.fail(`expected "," or "]"`)
		}
	}
}

func (r *jsonReader) readString() (string, error) {
	r.index++
	var builder strings.Builder
	for {
		if r.atEnd() {
			return "", r.fail("unterminated string")
		}
		code := r.text[r.index]
		switch {
		case code == '"':
			r.index++
			return builder.String(), nil
		case code == '\\':
			r.index++
			decoded, err := r.readEscape()
			if err != nil {
				return "", err
			}
			builder.WriteString(decoded)
		case code < 0x20:
			return "", failf(ErrJSONString, "raw control character in string at offset %d", r.index)
		default:
			// The input was validated as UTF-8, so a single byte is one rune.
			_, size := utf8.DecodeRuneInString(r.text[r.index:])
			builder.WriteString(r.text[r.index : r.index+size])
			r.index += size
		}
	}
}

func (r *jsonReader) readEscape() (string, error) {
	if r.atEnd() {
		return "", r.fail("unterminated escape")
	}
	code := r.text[r.index]
	r.index++
	switch code {
	case '"':
		return `"`, nil
	case '\\':
		return `\`, nil
	case '/':
		return `/`, nil
	case 'b':
		return "\b", nil
	case 'f':
		return "\f", nil
	case 'n':
		return "\n", nil
	case 'r':
		return "\r", nil
	case 't':
		return "\t", nil
	case 'u':
		unit, err := r.readHex4()
		if err != nil {
			return "", err
		}
		switch {
		case unit >= 0xd800 && unit <= 0xdbff:
			if r.index+1 >= len(r.text) || r.text[r.index] != '\\' || r.text[r.index+1] != 'u' {
				return "", failf(ErrJSONString, "high surrogate without a low surrogate")
			}
			r.index += 2
			low, err := r.readHex4()
			if err != nil {
				return "", err
			}
			if low < 0xdc00 || low > 0xdfff {
				return "", failf(ErrJSONString, "high surrogate without a low surrogate")
			}
			return string(utf16.Decode([]uint16{unit, low})), nil
		case unit >= 0xdc00 && unit <= 0xdfff:
			return "", failf(ErrJSONString, "unpaired low surrogate")
		default:
			return string(rune(unit)), nil
		}
	default:
		return "", r.fail("unknown string escape")
	}
}

func (r *jsonReader) readHex4() (uint16, error) {
	if r.index+4 > len(r.text) {
		return 0, r.fail("truncated unicode escape")
	}
	slice := r.text[r.index : r.index+4]
	for index := 0; index < 4; index++ {
		if !isHexDigit(slice[index]) {
			return 0, r.fail("malformed unicode escape")
		}
	}
	r.index += 4
	parsed, err := strconv.ParseUint(slice, 16, 16)
	if err != nil {
		return 0, r.fail("malformed unicode escape")
	}
	return uint16(parsed), nil
}

func isHexDigit(code byte) bool {
	return (code >= '0' && code <= '9') || (code >= 'a' && code <= 'f') || (code >= 'A' && code <= 'F')
}

func (r *jsonReader) readNumber() (Value, error) {
	start := r.index
	if r.index < len(r.text) && r.text[r.index] == '-' {
		r.index++
	}
	if r.index >= len(r.text) {
		return Value{}, r.fail("truncated number")
	}
	if r.text[r.index] == '0' {
		r.index++
	} else {
		if !isDigit(r.text[r.index]) {
			return Value{}, r.fail("expected a JSON value")
		}
		for r.index < len(r.text) && isDigit(r.text[r.index]) {
			r.index++
		}
	}
	if r.index < len(r.text) && r.text[r.index] == '.' {
		r.index++
		if r.index >= len(r.text) || !isDigit(r.text[r.index]) {
			return Value{}, r.fail(`expected digits after "."`)
		}
		for r.index < len(r.text) && isDigit(r.text[r.index]) {
			r.index++
		}
	}
	if r.index < len(r.text) && (r.text[r.index] == 'e' || r.text[r.index] == 'E') {
		r.index++
		if r.index < len(r.text) && (r.text[r.index] == '+' || r.text[r.index] == '-') {
			r.index++
		}
		if r.index >= len(r.text) || !isDigit(r.text[r.index]) {
			return Value{}, r.fail("expected exponent digits")
		}
		for r.index < len(r.text) && isDigit(r.text[r.index]) {
			r.index++
		}
	}
	literal := r.text[start:r.index]
	// strconv is the same strtod based conversion the ECMAScript parser uses.
	number, err := strconv.ParseFloat(literal, 64)
	if err != nil || math.IsInf(number, 0) || math.IsNaN(number) {
		return Value{}, failf(ErrJSONNumber, "number is not a finite double: %s", literal)
	}
	return NumberValue(number), nil
}

func isDigit(code byte) bool { return code >= '0' && code <= '9' }
