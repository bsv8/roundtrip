import { RoundtripError } from './errors.js'
import type { JsonValue } from './types.js'

/**
 * 2^53 - 1.
 *
 * RFC 8785 defers number output to the ECMAScript `Number::toString`
 * algorithm, which is defined for every finite IEEE-754 double, so JCS itself
 * does not restrict the integer range. This constant is the sanity bound used
 * for the `expires` timestamp, and the documented answer to applications that
 * need exact money or big integers: send them as strings.
 */
export const MAX_SAFE_INTEGER = 9007199254740991

/** Bound on nesting so a 1 MiB payload cannot turn into unbounded recursion. */
export const MAX_JSON_DEPTH = 64

const decoder = new TextDecoder('utf-8', { fatal: true })

export function decodeUtf8 (bytes: Uint8Array): string {
  try {
    return decoder.decode(bytes)
  } catch (cause) {
    throw new RoundtripError('ERR_JSON_INPUT', 'message is not valid UTF-8', { cause })
  }
}

/**
 * Strict JSON reader.
 *
 * `JSON.parse` is not used on purpose: it silently keeps the last value of a
 * duplicated object key and it accepts lone surrogates, both of which would let
 * two readers disagree about the bytes they sign.
 */
export function parseJsonBytes (bytes: Uint8Array): JsonValue {
  return parseJsonText(decodeUtf8(bytes))
}

export function parseJsonText (text: string): JsonValue {
  const reader = new Reader(text)
  reader.skipWhitespace()
  const value = reader.readValue(0)
  reader.skipWhitespace()
  if (!reader.atEnd()) {
    throw new RoundtripError('ERR_JSON_SYNTAX', 'trailing bytes after the JSON value')
  }
  return value
}

class Reader {
  #text: string
  #index = 0

  constructor (text: string) {
    this.#text = text
  }

  atEnd (): boolean {
    return this.#index >= this.#text.length
  }

  fail (message: string): never {
    throw new RoundtripError('ERR_JSON_SYNTAX', `${message} at offset ${this.#index}`)
  }

  skipWhitespace (): void {
    while (this.#index < this.#text.length) {
      const code = this.#text.charCodeAt(this.#index)
      if (code !== 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) return
      this.#index++
    }
  }

  expect (code: number, what: string): void {
    if (this.#text.charCodeAt(this.#index) !== code) this.fail(`expected ${what}`)
    this.#index++
  }

  readValue (depth: number): JsonValue {
    if (depth > MAX_JSON_DEPTH) {
      throw new RoundtripError('ERR_JSON_DEPTH', `JSON nesting exceeds ${MAX_JSON_DEPTH}`)
    }
    const code = this.#text.charCodeAt(this.#index)
    switch (code) {
      case 0x7b: return this.#readObject(depth)
      case 0x5b: return this.#readArray(depth)
      case 0x22: return this.#readString()
      case 0x74: return this.#readLiteral('true', true)
      case 0x66: return this.#readLiteral('false', false)
      case 0x6e: return this.#readLiteral('null', null)
      default: return this.#readNumber()
    }
  }

  #readLiteral<T extends JsonValue> (word: string, value: T): T {
    if (this.#text.startsWith(word, this.#index) === false) this.fail(`expected ${word}`)
    this.#index += word.length
    return value
  }

  #readObject (depth: number): JsonValue {
    this.#index++
    const result: { [key: string]: JsonValue } = Object.create(null)
    this.skipWhitespace()
    if (this.#text.charCodeAt(this.#index) === 0x7d) {
      this.#index++
      return result
    }
    while (true) {
      this.skipWhitespace()
      if (this.#text.charCodeAt(this.#index) !== 0x22) this.fail('expected an object key')
      const key = this.#readString()
      if (Object.prototype.hasOwnProperty.call(result, key)) {
        throw new RoundtripError('ERR_JSON_DUPLICATE_KEY', `duplicated object key: ${key}`)
      }
      this.skipWhitespace()
      this.expect(0x3a, '":"')
      this.skipWhitespace()
      result[key] = this.readValue(depth + 1)
      this.skipWhitespace()
      const next = this.#text.charCodeAt(this.#index)
      if (next === 0x2c) {
        this.#index++
        continue
      }
      if (next === 0x7d) {
        this.#index++
        return result
      }
      this.fail('expected "," or "}"')
    }
  }

  #readArray (depth: number): JsonValue {
    this.#index++
    const result: JsonValue[] = []
    this.skipWhitespace()
    if (this.#text.charCodeAt(this.#index) === 0x5d) {
      this.#index++
      return result
    }
    while (true) {
      this.skipWhitespace()
      result.push(this.readValue(depth + 1))
      this.skipWhitespace()
      const next = this.#text.charCodeAt(this.#index)
      if (next === 0x2c) {
        this.#index++
        continue
      }
      if (next === 0x5d) {
        this.#index++
        return result
      }
      this.fail('expected "," or "]"')
    }
  }

  #readString (): string {
    this.#index++
    let result = ''
    while (true) {
      if (this.atEnd()) this.fail('unterminated string')
      const code = this.#text.charCodeAt(this.#index)
      if (code === 0x22) {
        this.#index++
        return result
      }
      if (code === 0x5c) {
        this.#index++
        result += this.#readEscape()
        continue
      }
      if (code < 0x20) {
        throw new RoundtripError('ERR_JSON_STRING', 'raw control character in string')
      }
      result += this.#text[this.#index]
      this.#index++
    }
  }

  #readEscape (): string {
    const code = this.#text.charCodeAt(this.#index)
    this.#index++
    switch (code) {
      case 0x22: return '"'
      case 0x5c: return '\\'
      case 0x2f: return '/'
      case 0x62: return '\b'
      case 0x66: return '\f'
      case 0x6e: return '\n'
      case 0x72: return '\r'
      case 0x74: return '\t'
      case 0x75: {
        const unit = this.#readHex4()
        if (unit >= 0xd800 && unit <= 0xdbff) {
          if (this.#text.charCodeAt(this.#index) !== 0x5c || this.#text.charCodeAt(this.#index + 1) !== 0x75) {
            throw new RoundtripError('ERR_JSON_STRING', 'high surrogate without a low surrogate')
          }
          this.#index += 2
          const low = this.#readHex4()
          if (low < 0xdc00 || low > 0xdfff) {
            throw new RoundtripError('ERR_JSON_STRING', 'high surrogate without a low surrogate')
          }
          return String.fromCharCode(unit, low)
        }
        if (unit >= 0xdc00 && unit <= 0xdfff) {
          throw new RoundtripError('ERR_JSON_STRING', 'unpaired low surrogate')
        }
        return String.fromCharCode(unit)
      }
      default:
        this.fail('unknown string escape')
    }
  }

  #readHex4 (): number {
    if (this.#index + 4 > this.#text.length) this.fail('truncated \\u escape')
    const slice = this.#text.slice(this.#index, this.#index + 4)
    if (/^[0-9a-fA-F]{4}$/.test(slice) === false) this.fail('malformed \\u escape')
    this.#index += 4
    return Number.parseInt(slice, 16)
  }

  #readNumber (): number {
    const start = this.#index
    if (this.#text.charCodeAt(this.#index) === 0x2d) this.#index++
    if (this.#index >= this.#text.length) this.fail('truncated number')
    if (this.#text.charCodeAt(this.#index) === 0x30) {
      this.#index++
    } else {
      if (this.#isDigit(this.#text.charCodeAt(this.#index)) === false) this.fail('expected a JSON value')
      while (this.#isDigit(this.#text.charCodeAt(this.#index))) this.#index++
    }
    if (this.#text.charCodeAt(this.#index) === 0x2e) {
      this.#index++
      if (this.#isDigit(this.#text.charCodeAt(this.#index)) === false) this.fail('expected digits after "."')
      while (this.#isDigit(this.#text.charCodeAt(this.#index))) this.#index++
    }
    const exponent = this.#text.charCodeAt(this.#index)
    if (exponent === 0x65 || exponent === 0x45) {
      this.#index++
      const sign = this.#text.charCodeAt(this.#index)
      if (sign === 0x2b || sign === 0x2d) this.#index++
      if (this.#isDigit(this.#text.charCodeAt(this.#index)) === false) this.fail('expected exponent digits')
      while (this.#isDigit(this.#text.charCodeAt(this.#index))) this.#index++
    }
    const text = this.#text.slice(start, this.#index)
    const value = Number(text)
    if (Number.isFinite(value) === false) {
      // RFC 8785: NaN and Infinity are not permitted in JSON, and a literal that
      // overflows a double must not be silently turned into one.
      throw new RoundtripError('ERR_JSON_NUMBER', `number is not a finite double: ${text}`)
    }
    return value
  }

  #isDigit (code: number): boolean {
    return code >= 0x30 && code <= 0x39
  }
}
