import { RoundtripError } from './errors.js'
import type { JsonValue } from './types.js'

const encoder = new TextEncoder()

/**
 * RFC 8785 JSON Canonicalization Scheme.
 *
 * Object members are sorted by their UTF-16 code unit sequence, arrays keep
 * their order, numbers use the ECMAScript `Number::toString` algorithm and
 * strings use the shortest JSON escape form. No whitespace is emitted.
 */
export function canonicalizeToString (value: JsonValue): string {
  return writeValue(value)
}

export function canonicalize (value: JsonValue): Uint8Array {
  return encoder.encode(canonicalizeToString(value))
}

function writeValue (value: JsonValue): string {
  if (value === null) return 'null'
  switch (typeof value) {
    case 'boolean': return value ? 'true' : 'false'
    case 'number': return writeNumber(value)
    case 'string': return writeString(value)
    default: break
  }
  if (Array.isArray(value)) {
    return `[${value.map(entry => writeValue(entry)).join(',')}]`
  }
  const record = value as { [key: string]: JsonValue }
  // Array.prototype.sort compares UTF-16 code units, which is exactly the order
  // RFC 8785 requires.
  const keys = Object.keys(record).sort()
  const parts: string[] = []
  for (const key of keys) {
    parts.push(`${writeString(key)}:${writeValue(record[key])}`)
  }
  return `{${parts.join(',')}}`
}

function writeNumber (value: number): string {
  if (Number.isFinite(value) === false) {
    // RFC 8785: NaN and Infinity MUST cause an error.
    throw new RoundtripError('ERR_JSON_NUMBER', 'cannot canonicalize a non-finite number')
  }
  // String() is the ECMAScript Number::toString algorithm that RFC 8785 requires,
  // including the "Note 2" closest-even rounding, and String(-0) is "0".
  return String(value)
}

function writeString (value: string): string {
  let result = '"'
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index)
    if (code < 0x20 || code === 0x22 || code === 0x5c) {
      switch (code) {
        case 0x08: result += '\\b'; break
        case 0x09: result += '\\t'; break
        case 0x0a: result += '\\n'; break
        case 0x0c: result += '\\f'; break
        case 0x0d: result += '\\r'; break
        case 0x22: result += '\\"'; break
        case 0x5c: result += '\\\\'; break
        default: result += `\\u${code.toString(16).padStart(4, '0')}`; break
      }
      continue
    }
    if (code >= 0xd800 && code <= 0xdfff) {
      // The reader rejects unpaired surrogates, and a paired surrogate is
      // emitted verbatim below, so a bare surrogate here means the value did
      // not come from the strict reader.
      const isHigh = code <= 0xdbff
      const next = value.charCodeAt(index + 1)
      if (isHigh === false || next < 0xdc00 || next > 0xdfff) {
        throw new RoundtripError('ERR_JSON_STRING', 'cannot canonicalize a string with an unpaired surrogate')
      }
      result += value[index] + value[index + 1]
      index++
      continue
    }
    result += value[index]
  }
  return `${result}"`
}
