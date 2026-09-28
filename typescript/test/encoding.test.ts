import { describe, expect, it } from 'vitest'
import {
  LocalRoundtripSigner,
  MAX_SAFE_INTEGER,
  RoundtripCore,
  canonicalize,
  canonicalizeToString,
  decodeBase64Url,
  encodeBase64Url,
  encodeEnvelopeBytes,
  equalBytes,
  isRoundtripError,
  parseJsonBytes,
  parseDerSignature,
  parseJsonText,
  parseRequest,
  parseResponse,
  publicKeyFromPrivateKey,
  requestIdOf,
  sha256Bytes,
  signDigest,
  signingBytes,
  SIGNING_PREFIX,
  unsignedToWire,
  validatePublicKey,
  verifyDigest
} from '../src/index.js'
import { REJECT_CASES } from '../scripts/vector-cases.js'
import {
  TEST_EXPIRES,
  testPrivateKey,
  testPublicKey,
  unsignedRequest,
  unsignedResponse,
  wireOf
} from './fixtures.js'

/** Runs `body` and returns the error code, or `''` when nothing was thrown. */
function codeOf (body: () => unknown): string {
  try {
    body()
    return ''
  } catch (error) {
    return isRoundtripError(error) ? error.code : 'NOT_A_ROUNDTRIP_ERROR'
  }
}

/** The same, for the async entry points. */
async function codeOfAsync (body: () => Promise<unknown>): Promise<string> {
  try {
    await body()
    return ''
  } catch (error) {
    return isRoundtripError(error) ? error.code : 'NOT_A_ROUNDTRIP_ERROR'
  }
}

const utf8 = new TextEncoder()
const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes)

describe('stage 1: strict reading', () => {
  it('refuses every input in the shared reject table', () => {
    for (const entry of REJECT_CASES) {
      expect(codeOf(() => parseJsonText(entry.input)), entry.name).toBe(entry.code)
    }
  })

  it('refuses bytes that are not valid UTF-8', () => {
    // 0xff never appears in valid UTF-8. A lenient decoder would turn it into
    // U+FFFD and the two readers would then disagree about the signed bytes.
    expect(codeOf(() => parseJsonBytes(new Uint8Array([0x7b, 0xff, 0x7d])))).toBe('ERR_JSON_INPUT')
    // A truncated multi byte sequence is invalid too.
    expect(codeOf(() => parseJsonBytes(new Uint8Array([0x7b, 0x22, 0xe4, 0xb8, 0x22, 0x7d])))).toBe('ERR_JSON_INPUT')
  })

  it('rejects a duplicate key however it is spelled', () => {
    // JSON.parse would silently keep the last value of both of these.
    expect(JSON.parse('{"a":1,"a":2}').a).toBe(2)
    expect(codeOf(() => parseJsonText('{"a":1,"a":2}'))).toBe('ERR_JSON_DUPLICATE_KEY')
    expect(codeOf(() => parseJsonText('{"a":1,"\\u0061":2}'))).toBe('ERR_JSON_DUPLICATE_KEY')
    expect(codeOf(() => parseJsonText('{"body":{"x":1},"body":{"x":2}}'))).toBe('ERR_JSON_DUPLICATE_KEY')
  })

  it('keeps __proto__ as a plain key instead of touching the prototype', () => {
    const value = parseJsonText('{"__proto__":{"polluted":true}}')
    expect(Object.prototype.hasOwnProperty.call(value, '__proto__')).toBe(true)
    expect(({} as Record<string, unknown>).polluted).toBeUndefined()
  })
})

describe('stage 1: canonical form', () => {
  it('is independent of key order and whitespace', () => {
    const a = parseJsonText('{ "to" : "b" ,\n  "from":"a" ,\t"body":{"z":1,"a":2} }')
    const b = parseJsonText('{"body":{"a":2,"z":1},"from":"a","to":"b"}')
    expect(equalBytes(canonicalize(a), canonicalize(b))).toBe(true)
    expect(canonicalizeToString(a)).toBe('{"body":{"a":2,"z":1},"from":"a","to":"b"}')
  })

  it('keeps array order significant', () => {
    expect(canonicalizeToString(parseJsonText('{"list":[3,1,2]}')))
      .not.toBe(canonicalizeToString(parseJsonText('{"list":[2,1,3]}')))
  })

  it('matches the RFC 8785 worked example', () => {
    const input = '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}'
    const expected = '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    expect(canonicalizeToString(parseJsonText(input))).toBe(expected)
  })

  it('serialises numbers with the ECMAScript algorithm, and says where exact data must be a string', () => {
    expect(canonicalizeToString(parseJsonText('{"a":[0,-0,1e21,1e-7,0.1,1.0]}')))
      .toBe('{"a":[0,0,1e+21,1e-7,0.1,1]}')
    // 2^53+1 is one past the largest exactly representable integer, so a
    // numeric literal silently changes value. This is the documented reason the
    // protocol says money and big integers travel as strings.
    const asNumber = canonicalizeToString(parseJsonText('{"v":9007199254740993}'))
    expect(asNumber).toBe(`{"v":${String(Number('9007199254740993'))}}`)
    expect(asNumber).toBe('{"v":9007199254740992}')
    expect(canonicalizeToString(parseJsonText('{"v":"9007199254740993"}'))).toBe('{"v":"9007199254740993"}')
    expect(MAX_SAFE_INTEGER).toBe(9007199254740991)
  })

  it('refuses a literal that overflows a double instead of turning it into Infinity', () => {
    expect(codeOf(() => parseJsonText('{"a":1e400}'))).toBe('ERR_JSON_NUMBER')
    expect(codeOf(() => canonicalize({ a: Number.POSITIVE_INFINITY }))).toBe('ERR_JSON_NUMBER')
    expect(codeOf(() => canonicalize({ a: Number.NaN }))).toBe('ERR_JSON_NUMBER')
  })
})

describe('stage 1: base64url is canonical', () => {
  it('round trips every length without padding', () => {
    for (let length = 0; length < 40; length++) {
      const bytes = new Uint8Array(length)
      for (let index = 0; index < length; index++) bytes[index] = (index * 7 + 3) & 0xff
      const encoded = encodeBase64Url(bytes)
      expect(encoded).not.toContain('=')
      expect(equalBytes(decodeBase64Url(encoded, 'ERR_PUBLIC_KEY'), bytes)).toBe(true)
    }
  })

  it('rejects every spelling that would give one key two identity strings', () => {
    const key = encodeBase64Url(testPublicKey('alice'))
    expect(codeOf(() => decodeBase64Url(`${key}=`, 'ERR_PUBLIC_KEY'))).toBe('ERR_PUBLIC_KEY')
    expect(codeOf(() => decodeBase64Url('A', 'ERR_PUBLIC_KEY'))).toBe('ERR_PUBLIC_KEY')
    // The standard alphabet shares '+' and '/', which are not url-safe.
    expect(codeOf(() => decodeBase64Url(key.replace(/-/g, '+').replace(/_/g, '/'), 'ERR_PUBLIC_KEY'))).toBe('ERR_PUBLIC_KEY')
  })

  it('rejects non zero padding bits, so no byte string has two encodings', () => {
    // 'AB' and 'AA' differ only in bits that no output byte consumes.
    expect(codeOf(() => decodeBase64Url('AB', 'ERR_PUBLIC_KEY'))).toBe('ERR_PUBLIC_KEY')
    expect(equalBytes(decodeBase64Url('AA', 'ERR_PUBLIC_KEY'), new Uint8Array([0]))).toBe(true)
  })

  it('accepts one canonical public key encoding and rejects the rest', () => {
    const compressed = testPublicKey('alice')
    expect(equalBytes(validatePublicKey(compressed), compressed)).toBe(true)
    // Uncompressed, and a well formed prefix with no curve point behind it.
    expect(codeOf(() => validatePublicKey(new Uint8Array(65)))).toBe('ERR_PUBLIC_KEY')
    const notOnCurve = new Uint8Array(33)
    notOnCurve[0] = 0x02
    expect(codeOf(() => validatePublicKey(notOnCurve))).toBe('ERR_PUBLIC_KEY')
    // 32 bytes is a scalar, not a point: it must never be accepted as an identity.
    expect(codeOf(() => validatePublicKey(testPrivateKey('alice')))).toBe('ERR_PUBLIC_KEY')
    expect(codeOf(() => validatePublicKey(new Uint8Array(0)))).toBe('ERR_PUBLIC_KEY')
  })
})

describe('stage 1: signature encoding', () => {
  it('signs one SHA-256 digest, with strict DER and low-S', () => {
    const digest = sha256Bytes(utf8.encode('roundtrip/v1\n{}'))
    const signature = signDigest(testPrivateKey('alice'), digest)
    const parsed = parseDerSignature(signature)
    expect(signature[0]).toBe(0x30)
    expect(signature[1]).toBe(signature.length - 2)
    expect(parsed.r > 0n).toBe(true)
    expect(parsed.s > 0n).toBe(true)
  })

  it('refuses high-S, trailing bytes and non minimal integers', () => {
    const digest = sha256Bytes(utf8.encode('roundtrip/v1\n{}'))
    const good = signDigest(testPrivateKey('alice'), digest)
    const { r, s } = parseDerSignature(good)
    const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
    // High-S: (r, n - s) is a valid ECDSA signature over the same digest, and a
    // receiver that ignores the low-S rule would accept it.
    const highS = encodeDer(r, order - s)
    expect(codeOf(() => parseDerSignature(highS))).toBe('ERR_SIGNATURE_FORMAT')
    expect(codeOf(() => parseDerSignature(new Uint8Array([...good, 0x00])))).toBe('ERR_SIGNATURE_FORMAT')
    expect(codeOf(() => parseDerSignature(good.subarray(0, good.length - 1)))).toBe('ERR_SIGNATURE_FORMAT')
  })

  it('refuses a digest of the wrong size, so a second hash cannot slip in', () => {
    expect(codeOf(() => signDigest(testPrivateKey('alice'), new Uint8Array(31)))).toBe('ERR_SIGNER_FAILED')
    expect(codeOf(() => signDigest(testPrivateKey('alice'), new Uint8Array(32).fill(1), ))).toBe('')
    // The digest that gets signed is exactly one SHA-256 over prefix || JCS,
    // computed by the caller. Hashing it again would be a different message, so
    // a receiver that hashes once can never be satisfied by a double hash.
    const unsigned = unsignedRequest()
    const bytes = signingBytes(unsigned)
    const once = sha256Bytes(bytes)
    expect(equalBytes(once, sha256Bytes(bytes))).toBe(true)
    expect(equalBytes(once, sha256Bytes(utf8.encode(text(bytes))))).toBe(true)
    expect(equalBytes(once, sha256Bytes(signingBytes(unsigned)))).toBe(true)
  })
})

/** Minimal DER writer, used only to build the malformed inputs above. */
function encodeDer (r: bigint, s: bigint): Uint8Array {
  const integer = (value: bigint): Uint8Array => {
    let hex = value.toString(16)
    if (hex.length % 2 === 1) hex = `0${hex}`
    if (value > 0xffn && Number(`0x${hex[0]}`) >= 8) hex = `00${hex}`
    const bytes = new Uint8Array(hex.length / 2)
    for (let index = 0; index < bytes.length; index++) {
      bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
    }
    return new Uint8Array([0x02, bytes.length, ...bytes])
  }
  const rBytes = integer(r)
  const sBytes = integer(s)
  return new Uint8Array([0x30, rBytes.length + sBytes.length, ...rBytes, ...sBytes])
}

describe('stage 1: the request digest', () => {
  it('is base64url of the digest of prefix || JCS(unsigned)', () => {
    const unsigned = unsignedRequest()
    const bytes = signingBytes(unsigned)
    expect(text(bytes.subarray(0, SIGNING_PREFIX.length))).toBe('roundtrip/v1\n')
    // The rest is exactly the canonical form of the unsigned object, so a
    // reader that canonicalises the parsed message reproduces these bytes.
    expect(equalBytes(bytes.subarray(SIGNING_PREFIX.length), canonicalize(unsignedToWire(unsigned)))).toBe(true)
    expect(requestIdOf(unsigned)).toBe(encodeBase64Url(sha256Bytes(bytes)))
    expect(requestIdOf(unsigned).length).toBe(43)
  })

  it('does not change when key order and whitespace change', () => {
    const canonical = encodeEnvelopeBytes(unsignedRequest(), signDigest(testPrivateKey('alice'), sha256Bytes(signingBytes(unsignedRequest()))))
    const wire = wireOf(canonical)
    const reordered = `{\n  "to": ${JSON.stringify(wire.to)},\n  "sig": ${JSON.stringify(wire.sig)},\n  "body": ${JSON.stringify(wire.body)},\n  "expires": ${wire.expires as number},\n  "nonce": ${JSON.stringify(wire.nonce)},\n  "from": ${JSON.stringify(wire.from)}\n}`
    const reparsed = parseRequest(parseJsonText(reordered))
    expect(reparsed.unsigned.from).toEqual(unsignedRequest().from)
    // Same message, different bytes on the wire, same request id.
    expect(equalBytes(canonical, utf8.encode(reordered))).toBe(false)
    expect(requestIdOf(reparsed.unsigned)).toBe(requestIdOf(parseRequest(parseJsonText(text(canonical))).unsigned))
  })

  it('changes when any signed field changes', () => {
    const base = requestIdOf(unsignedRequest())
    const variants = {
      from: unsignedRequest({ from: testPublicKey('mallory') }),
      to: unsignedRequest({ to: testPublicKey('carol') }),
      nonce: unsignedRequest({ nonce: new Uint8Array(32).fill(8) }),
      expires: unsignedRequest({ expires: TEST_EXPIRES + 1 }),
      body: unsignedRequest({ body: { op: 'transfer', args: { amount: '1' } } })
    }
    for (const [field, unsigned] of Object.entries(variants)) {
      expect(requestIdOf(unsigned), field).not.toBe(base)
    }
  })

  it('is not affected by the signature, so a retransmission keeps its id', () => {
    const unsigned = unsignedRequest()
    const first = signDigest(testPrivateKey('alice'), sha256Bytes(signingBytes(unsigned)))
    const second = signDigest(testPrivateKey('mallory'), sha256Bytes(signingBytes(unsigned)))
    expect(equalBytes(first, second)).toBe(false)
    expect(requestIdOf(unsigned)).toBe(requestIdOf(unsigned))
  })
})

describe('stage 1: the envelope shape is fixed', () => {
  const valid = (): Uint8Array => {
    const unsigned = unsignedRequest()
    return encodeEnvelopeBytes(unsigned, signDigest(testPrivateKey('alice'), sha256Bytes(signingBytes(unsigned))))
  }

  it('accepts exactly from, to, nonce, expires, body, sig', () => {
    const parsed = parseRequest(parseJsonText(text(valid())))
    expect(parsed.unsigned.expires).toBe(TEST_EXPIRES)
    expect(parsed.unsigned.nonce.length).toBe(32)
  })

  it('refuses a missing field, an unknown field and a wrong type', () => {
    for (const field of ['from', 'to', 'nonce', 'expires', 'body', 'sig']) {
      const wire = wireOf(valid())
      delete wire[field]
      expect(codeOf(() => parseRequest(wire)), `missing ${field}`).toBe('ERR_ENVELOPE_FIELD_MISSING')
    }
    const extra = { ...wireOf(valid()), version: 1 }
    expect(codeOf(() => parseRequest(extra))).toBe('ERR_ENVELOPE_FIELD_UNKNOWN')
    // There is no type, id or version field in this protocol.
    expect(codeOf(() => parseRequest({ ...wireOf(valid()), type: 'request' }))).toBe('ERR_ENVELOPE_FIELD_UNKNOWN')
    expect(codeOf(() => parseRequest({ ...wireOf(valid()), id: 'x' }))).toBe('ERR_ENVELOPE_FIELD_UNKNOWN')
    expect(codeOf(() => parseRequest({ ...wireOf(valid()), version: '1' }))).toBe('ERR_ENVELOPE_FIELD_UNKNOWN')
    // expires is read as a number, so a string is refused as a bad expiry
    // rather than as a generic type error.
    expect(codeOf(() => parseRequest({ ...wireOf(valid()), expires: '1790000000' }))).toBe('ERR_EXPIRES')
    expect(codeOf(() => parseRequest({ ...wireOf(valid()), from: 7 }))).toBe('ERR_ENVELOPE_FIELD_TYPE')
    expect(codeOf(() => parseRequest({ ...wireOf(valid()), body: { args: {} } }))).toBe('ERR_BODY')
  })

  it('keeps a request and a response in separate shapes', () => {
    const responseWire = wireOf(valid())
    // A request must not carry reply_to, and a response must not carry nonce.
    expect(codeOf(() => parseRequest({ ...responseWire, reply_to: encodeBase64Url(new Uint8Array(32)) }))).toBe('ERR_ENVELOPE_FIELD_UNKNOWN')
    expect(codeOf(() => parseResponse(responseWire))).toBe('ERR_ENVELOPE_FIELD_MISSING')
  })

  it('refuses a non object, a non array top level and an empty message', () => {
    expect(codeOf(() => parseRequest(parseJsonText('[]')))).toBe('ERR_ENVELOPE_NOT_OBJECT')
    expect(codeOf(() => parseRequest(parseJsonText('"x"')))).toBe('ERR_ENVELOPE_NOT_OBJECT')
    expect(codeOf(() => parseRequest(parseJsonText('null')))).toBe('ERR_ENVELOPE_NOT_OBJECT')
    expect(codeOf(() => parseRequest(parseJsonText('')))).toBe('ERR_JSON_SYNTAX')
  })

  it('bounds the nonce, and refuses a short one', () => {
    const short = { ...wireOf(valid()), nonce: encodeBase64Url(new Uint8Array(15)) }
    expect(codeOf(() => parseRequest(short))).toBe('ERR_NONCE')
    const long = { ...wireOf(valid()), nonce: encodeBase64Url(new Uint8Array(65)) }
    expect(codeOf(() => parseRequest(long))).toBe('ERR_NONCE')
    // 16 bytes is 128 bits, the documented minimum.
    expect(codeOf(() => parseRequest({ ...wireOf(valid()), nonce: encodeBase64Url(new Uint8Array(16)) }))).not.toBe('ERR_NONCE')
  })

  it('bounds expires to an integer in range', () => {
    expect(codeOf(() => parseRequest({ ...wireOf(valid()), expires: 1.5 }))).toBe('ERR_EXPIRES')
    expect(codeOf(() => parseRequest({ ...wireOf(valid()), expires: -1 }))).toBe('ERR_EXPIRES')
    expect(codeOf(() => parseRequest({ ...wireOf(valid()), expires: Number.MAX_SAFE_INTEGER + 2 }))).toBe('ERR_EXPIRES')
  })

  it('refuses a public key that is not a 33 byte compressed point', () => {
    expect(codeOf(() => parseRequest({ ...wireOf(valid()), from: encodeBase64Url(new Uint8Array(33)) }))).toBe('ERR_PUBLIC_KEY')
    expect(codeOf(() => parseRequest({ ...wireOf(valid()), to: encodeBase64Url(new Uint8Array(32)) }))).toBe('ERR_PUBLIC_KEY')
  })
})
describe('stage 1: the response body is unambiguous', () => {
  /** A well formed response wire object whose `body` the test may replace. */
  const responseWireWith = (body: unknown): Record<string, unknown> => {
    const unsigned = unsignedResponse()
    const signature = signDigest(testPrivateKey('bob'), sha256Bytes(signingBytes(unsigned)))
    return { ...wireOf(encodeEnvelopeBytes(unsigned, signature)), body }
  }
  const respond = (body: unknown): string => codeOf(() => parseResponse(responseWireWith(body) as never))

  it('requires ok, and then exactly the matching half', () => {
    expect(respond({ ok: true, result: 1 })).not.toBe('ERR_RESPONSE_SHAPE')
    expect(respond({ ok: false, error: { code: 'X', message: 'y' } })).not.toBe('ERR_RESPONSE_SHAPE')
    expect(respond({ ok: true })).toBe('ERR_RESPONSE_SHAPE')
    expect(respond({ ok: false })).toBe('ERR_RESPONSE_SHAPE')
    expect(respond({ ok: 'true', result: 1 })).toBe('ERR_RESPONSE_SHAPE')
    expect(respond('ok')).toBe('ERR_RESPONSE_SHAPE')
    // A successful response must not smuggle an error field past the reader,
    // and a failed one must not smuggle a result.
    expect(respond({ ok: true, result: 1, error: { code: 'X', message: 'y' } })).toBe('ERR_RESPONSE_SHAPE')
    expect(respond({ ok: false, result: 1, error: { code: 'X', message: 'y' } })).toBe('ERR_RESPONSE_SHAPE')
    expect(respond({ ok: false, error: { code: '', message: 'y' } })).toBe('ERR_RESPONSE_SHAPE')
    expect(respond({ ok: false, error: { code: 'X' } })).toBe('ERR_RESPONSE_SHAPE')
    expect(respond({ ok: false, error: { code: 'X', message: 'y', extra: 1 } })).toBe('ERR_RESPONSE_SHAPE')
  })
})

describe('stage 1: the committed vectors describe this implementation', () => {
  it('reproduces every key, digest, request id, signature and envelope', async () => {
    const vectors = await loadVectors()
    expect(vectors.version).toBe('roundtrip-vectors-v1')
    for (const key of vectors.keys) {
      const privateKey = hexToBytesLocal(key.privateKeyHex)
      expect(equalBytes(publicKeyFromPrivateKey(privateKey), hexToBytesLocal(key.publicKeyHex)), key.name).toBe(true)
      expect(encodeBase64Url(publicKeyFromPrivateKey(privateKey)), key.name).toBe(key.publicKeyBase64Url)
      const signer = new LocalRoundtripSigner(privateKey)
      expect(equalBytes(signer.publicKey(), hexToBytesLocal(key.publicKeyHex)), key.name).toBe(true)
    }
    for (const entry of vectors.requests) {
      const parsed = parseRequest(parseJsonText(entry.envelope))
      expect(text(signingBytes(parsed.unsigned)).endsWith(entry.wire), entry.name).toBe(true)
      expect(bytesToHexLocal(sha256Bytes(signingBytes(parsed.unsigned))), entry.name).toBe(entry.digestHex)
      expect(requestIdOf(parsed.unsigned), entry.name).toBe(entry.requestId)
      expect(encodeBase64Url(parsed.signature), entry.name).toBe(entry.signatureBase64Url)
      expect(bytesToHexLocal(parsed.signature), entry.name).toBe(entry.signatureHex)
      expect(equalBytes(decodeBase64Url(entry.messageBase64Url, 'ERR_SIGNATURE_FORMAT'), utf8.encode(entry.envelope)), entry.name).toBe(true)
    }
    for (const entry of vectors.responses) {
      const parsed = parseResponse(parseJsonText(entry.envelope))
      // A response quotes a request id, which is the request digest, and its own
      // signature covers that reply_to.
      expect(parsed.unsigned.replyTo.length).toBe(32)
      expect(encodeBase64Url(parsed.unsigned.replyTo)).toBe(entry.unsigned.reply_to)
      expect(() => { verifyDigest(parsed.unsigned.from, sha256Bytes(signingBytes(parsed.unsigned)), parsed.signature) }).not.toThrow()
      expect(encodeBase64Url(parsed.signature), entry.name).toBe(entry.signatureBase64Url)
      expect(equalBytes(decodeBase64Url(entry.messageBase64Url, 'ERR_SIGNATURE_FORMAT'), utf8.encode(entry.envelope)), entry.name).toBe(true)
    }
  })
})

interface Vectors {
  version: string
  keys: Array<{ name: string, privateKeyHex: string, publicKeyHex: string, publicKeyBase64Url: string }>
  requests: Array<{ name: string, wire: string, digestHex: string, requestId: string, signatureBase64Url: string, signatureHex: string, envelope: string, messageBase64Url: string }>
  responses: Array<{ name: string, unsigned: { from: string, to: string, reply_to: string }, signatureBase64Url: string, envelope: string, messageBase64Url: string }>
}

async function loadVectors (): Promise<Vectors> {
  const { readFile } = await import('node:fs/promises')
  const { fileURLToPath } = await import('node:url')
  const { resolve } = await import('node:path')
  const here = fileURLToPath(new URL('.', import.meta.url))
  return JSON.parse(await readFile(resolve(here, '../../testdata/vectors.json'), 'utf8')) as Vectors
}

function hexToBytesLocal (value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2)
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

function bytesToHexLocal (bytes: Uint8Array): string {
  let result = ''
  for (const byte of bytes) result += byte.toString(16).padStart(2, '0')
  return result
}

describe('stage 1: the core refuses oversized input before parsing it', () => {
  it('applies its own local limit', async () => {
    const core = new RoundtripCore({
      signer: new LocalRoundtripSigner(testPrivateKey('bob')),
      maxMessageBytes: 128,
      handler: () => ({ ok: true, result: null })
    })
    // Rejected on size, before the bytes are even read as JSON.
    expect(await codeOfAsync(async () => await core.handle(new Uint8Array(200)))).toBe('ERR_MESSAGE_TOO_LARGE')
    expect(await codeOfAsync(async () => await core.handle(utf8.encode('{"from":')))).toBe('ERR_JSON_SYNTAX')
  })
})
