package core

import (
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const hexDigits = "0123456789abcdef"

// Canonicalize renders a value as RFC 8785 JSON.
//
// Object members are sorted by their UTF-16 code unit sequence, arrays keep
// their order, numbers use the ECMAScript Number::toString algorithm and
// strings use the shortest JSON escape form. No whitespace is emitted.
func Canonicalize(value Value) ([]byte, error) {
	var builder strings.Builder
	if err := writeValue(&builder, value); err != nil {
		return nil, err
	}
	return []byte(builder.String()), nil
}

// CanonicalizeString is Canonicalize as a string.
func CanonicalizeString(value Value) (string, error) {
	data, err := Canonicalize(value)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func writeValue(builder *strings.Builder, value Value) error {
	switch value.Kind {
	case KindNull:
		builder.WriteString("null")
	case KindBool:
		if value.Bool {
			builder.WriteString("true")
		} else {
			builder.WriteString("false")
		}
	case KindNumber:
		text, err := FormatNumber(value.Number)
		if err != nil {
			return err
		}
		builder.WriteString(text)
	case KindString:
		return writeString(builder, value.Str)
	case KindArray:
		builder.WriteByte('[')
		for index, item := range value.Array {
			if index > 0 {
				builder.WriteByte(',')
			}
			if err := writeValue(builder, item); err != nil {
				return err
			}
		}
		builder.WriteByte(']')
	case KindObject:
		keys := append([]string(nil), value.Keys...)
		sortUTF16(keys)
		builder.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				builder.WriteByte(',')
			}
			if err := writeString(builder, key); err != nil {
				return err
			}
			builder.WriteByte(':')
			if err := writeValue(builder, value.Object[key]); err != nil {
				return err
			}
		}
		builder.WriteByte('}')
	default:
		return failf(ErrJSONNumber, "unknown JSON value kind")
	}
	return nil
}

// sortUTF16 orders member names the way RFC 8785 requires: as arrays of UTF-16
// code units compared as unsigned values. This is not the same as comparing
// code points, because an astral character starts with a surrogate in the
// 0xd800..0xdfff range and therefore sorts before U+E000..U+FFFF.
func sortUTF16(keys []string) {
	encoded := make([][]uint16, len(keys))
	for index, key := range keys {
		encoded[index] = utf16.Encode([]rune(key))
	}
	// Insertion sort keeps the comparison explicit and the input small.
	for index := 1; index < len(keys); index++ {
		current := keys[index]
		currentUnits := encoded[index]
		position := index - 1
		for position >= 0 && compareUTF16(encoded[position], currentUnits) > 0 {
			keys[position+1] = keys[position]
			encoded[position+1] = encoded[position]
			position--
		}
		keys[position+1] = current
		encoded[position+1] = currentUnits
	}
}

func compareUTF16(left, right []uint16) int {
	limit := len(left)
	if len(right) < limit {
		limit = len(right)
	}
	for index := 0; index < limit; index++ {
		if left[index] != right[index] {
			if left[index] < right[index] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(left) < len(right):
		return -1
	case len(left) > len(right):
		return 1
	default:
		return 0
	}
}

func writeString(builder *strings.Builder, text string) error {
	builder.WriteByte('"')
	for index := 0; index < len(text); {
		code := text[index]
		if code < utf8.RuneSelf {
			switch code {
			case '"':
				builder.WriteString(`\"`)
			case '\\':
				builder.WriteString(`\\`)
			case '\b':
				builder.WriteString(`\b`)
			case '\t':
				builder.WriteString(`\t`)
			case '\n':
				builder.WriteString(`\n`)
			case '\f':
				builder.WriteString(`\f`)
			case '\r':
				builder.WriteString(`\r`)
			default:
				if code < 0x20 {
					builder.WriteString(`\u00`)
					builder.WriteByte(hexDigits[code>>4])
					builder.WriteByte(hexDigits[code&0x0f])
				} else {
					builder.WriteByte(code)
				}
			}
			index++
			continue
		}
		runeValue, size := utf8.DecodeRuneInString(text[index:])
		if runeValue == utf8.RuneError && size == 1 {
			return failf(ErrJSONString, "string is not valid UTF-8")
		}
		if runeValue >= 0xd800 && runeValue <= 0xdfff {
			// A Go string can hold a lone surrogate through a \uD800 escape in
			// source. RFC 8785 requires an error instead of a broken signature.
			return failf(ErrJSONString, "cannot canonicalize a string with an unpaired surrogate")
		}
		builder.WriteString(text[index : index+size])
		index += size
	}
	builder.WriteByte('"')
	return nil
}

// FormatNumber implements the ECMAScript Number::toString algorithm that
// RFC 8785 requires, including the "Note 2" closest-even rounding.
//
// The shortest round trip digits come from strconv, which is what Ryu produces
// in every other implementation; the layout around those digits is the part
// that has to match the specification exactly.
func FormatNumber(number float64) (string, error) {
	if math.IsNaN(number) || math.IsInf(number, 0) {
		// RFC 8785: NaN and Infinity MUST cause an error.
		return "", failf(ErrJSONNumber, "cannot canonicalize a non-finite number")
	}
	if number == 0 {
		// Covers negative zero, which serializes as "0".
		return "0", nil
	}
	sign := ""
	if number < 0 {
		sign = "-"
		number = -number
	}

	// Shortest round trip form, e.g. "1.2345e+07".
	scientific := strconv.FormatFloat(number, 'e', -1, 64)
	mantissa, exponentText, found := strings.Cut(scientific, "e")
	if !found {
		return "", failf(ErrJSONNumber, "unexpected float formatting: %s", scientific)
	}
	exponent, err := strconv.Atoi(exponentText)
	if err != nil {
		return "", failf(ErrJSONNumber, "unexpected float exponent: %s", exponentText)
	}
	digits := strings.Replace(mantissa, ".", "", 1)
	// digits is d1..dk and value = 0.d1..dk * 10^n.
	digitCount := len(digits)
	n := exponent + 1

	switch {
	case digitCount <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-digitCount), nil
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:], nil
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits, nil
	default:
		var builder strings.Builder
		builder.WriteString(sign)
		builder.WriteString(digits[:1])
		if digitCount > 1 {
			builder.WriteByte('.')
			builder.WriteString(digits[1:])
		}
		builder.WriteByte('e')
		if n-1 >= 0 {
			builder.WriteByte('+')
		} else {
			builder.WriteByte('-')
		}
		builder.WriteString(strconv.Itoa(abs(n - 1)))
		return builder.String(), nil
	}
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
