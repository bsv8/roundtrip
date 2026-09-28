import { RoundtripError } from './errors.js'

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

const REVERSE: Record<string, number> = {}
for (let index = 0; index < ALPHABET.length; index++) {
  REVERSE[ALPHABET[index]] = index
}

/** Unpadded base64url, the only binary representation used on the wire. */
export function encodeBase64Url (bytes: Uint8Array): string {
  let result = ''
  let index = 0
  for (; index + 2 < bytes.length; index += 3) {
    const chunk = (bytes[index] << 16) | (bytes[index + 1] << 8) | bytes[index + 2]
    result += ALPHABET[(chunk >> 18) & 0x3f] + ALPHABET[(chunk >> 12) & 0x3f] +
      ALPHABET[(chunk >> 6) & 0x3f] + ALPHABET[chunk & 0x3f]
  }
  const remaining = bytes.length - index
  if (remaining === 1) {
    const chunk = bytes[index] << 16
    result += ALPHABET[(chunk >> 18) & 0x3f] + ALPHABET[(chunk >> 12) & 0x3f]
  } else if (remaining === 2) {
    const chunk = (bytes[index] << 16) | (bytes[index + 1] << 8)
    result += ALPHABET[(chunk >> 18) & 0x3f] + ALPHABET[(chunk >> 12) & 0x3f] + ALPHABET[(chunk >> 6) & 0x3f]
  }
  return result
}

/**
 * Decodes unpadded base64url and rejects every non canonical spelling, so one
 * byte string has exactly one identity string.
 */
export function decodeBase64Url (value: string, code: 'ERR_PUBLIC_KEY' | 'ERR_NONCE' | 'ERR_REPLY_TO' | 'ERR_SIGNATURE_FORMAT' | 'ERR_JSON_STRING' = 'ERR_JSON_STRING'): Uint8Array {
  if (value.length % 4 === 1) {
    throw new RoundtripError(code, 'base64url length is impossible')
  }
  const bytes = new Uint8Array(Math.floor((value.length * 3) / 4))
  let accumulator = 0
  let bits = 0
  let offset = 0
  for (let index = 0; index < value.length; index++) {
    const digit = REVERSE[value[index]]
    if (digit === undefined) {
      throw new RoundtripError(code, 'base64url contains a character outside the unpadded url-safe alphabet')
    }
    accumulator = (accumulator << 6) | digit
    bits += 6
    if (bits >= 8) {
      bits -= 8
      bytes[offset++] = (accumulator >> bits) & 0xff
    }
  }
  if (bits > 0 && (accumulator & ((1 << bits) - 1)) !== 0) {
    throw new RoundtripError(code, 'base64url has non zero padding bits')
  }
  if (encodeBase64Url(bytes) !== value) {
    throw new RoundtripError(code, 'base64url is not the canonical encoding of these bytes')
  }
  return bytes
}

export function bytesToHex (bytes: Uint8Array): string {
  let result = ''
  for (const byte of bytes) result += byte.toString(16).padStart(2, '0')
  return result
}

export function hexToBytes (value: string): Uint8Array {
  if (value.length % 2 !== 0 || /^[0-9a-fA-F]*$/.test(value) === false) {
    throw new RoundtripError('ERR_JSON_STRING', 'hex value is malformed')
  }
  const bytes = new Uint8Array(value.length / 2)
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

export function utf8 (value: string): Uint8Array {
  return new TextEncoder().encode(value)
}

export function concatBytes (...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((size, part) => size + part.length, 0)
  const result = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    result.set(part, offset)
    offset += part.length
  }
  return result
}

export function equalBytes (left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  for (let index = 0; index < left.length; index++) {
    if (left[index] !== right[index]) return false
  }
  return true
}
