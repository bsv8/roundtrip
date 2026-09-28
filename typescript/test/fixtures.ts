import { LocalRoundtripSigner, publicKeyFromPrivateKey, type RoundtripSigner } from '../src/index.js'
import { encodeBase64Url, hexToBytes } from '../src/index.js'
import {
  encodeEnvelopeBytes,
  parseJsonBytes,
  sha256Bytes,
  signDigest,
  signingBytes,
  type JsonObject,
  type JsonValue,
  type UnsignedRequest,
  type UnsignedResponse,
  type UnsignedTrimmedResponse
} from '../src/index.js'

/**
 * Throw away test identities. Fixed so both languages and the shared vectors in
 * `testdata/vectors.json` agree byte for byte. They are not production keys and
 * must never be reused as such.
 */
export const TEST_KEY_HEX: Record<string, string> = {
  alice: '1111111111111111111111111111111111111111111111111111111111111111',
  bob: '2222222222222222222222222222222222222222222222222222222222222222',
  carol: '3333333333333333333333333333333333333333333333333333333333333333',
  mallory: '4444444444444444444444444444444444444444444444444444444444444444',
  one: '0000000000000000000000000000000000000000000000000000000000000001',
  orderMinusOne: 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140'
}

export const TEST_KEY_NAMES = Object.keys(TEST_KEY_HEX)

export function testPrivateKey (name: string): Uint8Array {
  const hex = TEST_KEY_HEX[name]
  if (hex == null) throw new Error(`unknown test key: ${name}`)
  return hexToBytes(hex)
}

export function testPublicKey (name: string): Uint8Array {
  return publicKeyFromPrivateKey(testPrivateKey(name))
}

export function testSigner (name: string): RoundtripSigner {
  return new LocalRoundtripSigner(testPrivateKey(name))
}

export function testPublicKeyBase64Url (name: string): string {
  return encodeBase64Url(testPublicKey(name))
}

/** A deterministic nonce source, so tests never depend on entropy. */
export function fixedRandom (seed = 1): (length: number) => Uint8Array {
  let state = seed >>> 0
  return (length: number): Uint8Array => {
    const bytes = new Uint8Array(length)
    for (let index = 0; index < length; index++) {
      // xorshift32: predictable, and only ever used to make a nonce distinct.
      state ^= state << 13
      state >>>= 0
      state ^= state >>> 17
      state ^= state << 5
      state >>>= 0
      bytes[index] = state & 0xff
    }
    return bytes
  }
}

export const TEST_EXPIRES = 1790000000

/**
 * The clock a fixture receiver uses. The vectors pin `expires` to a fixed
 * instant, so a receiver that reads the wall clock would reject every vector
 * the day it is generated.
 */
export const TEST_NOW = TEST_EXPIRES - 5

/**
 * A well formed unsigned request, with every field overridable.
 *
 * This is the base for the attack tests: the shell is only ever changed after
 * this object exists, and the result is signed normally, so a test failure
 * means the receiver accepted a correctly signed message rather than that the
 * test produced malformed bytes.
 */
export function unsignedRequest (overrides: Partial<UnsignedRequest> = {}): UnsignedRequest {
  return {
    kind: 'request',
    from: testPublicKey('alice'),
    to: testPublicKey('bob'),
    nonce: new Uint8Array(32).fill(9),
    expires: TEST_EXPIRES,
    body: { op: 'get_balance', args: {} },
    ...overrides
  }
}

export function unsignedResponse (overrides: Partial<UnsignedResponse> = {}): UnsignedResponse {
  return {
    kind: 'response',
    from: testPublicKey('bob'),
    to: testPublicKey('alice'),
    replyTo: new Uint8Array(32).fill(1),
    body: { ok: true, result: { ok: 1 } },
    ...overrides
  }
}

/** The optional trusted HTTPS response: no `reply_to`, and no nonce either. */
export function unsignedTrimmedResponse (overrides: Partial<UnsignedTrimmedResponse> = {}): UnsignedTrimmedResponse {
  return {
    kind: 'trimmed-response',
    from: testPublicKey('bob'),
    to: testPublicKey('alice'),
    body: { ok: true, result: { ok: 1 } },
    ...overrides
  }
}

/**
 * Produces complete, correctly signed envelope bytes for any unsigned message.
 *
 * The signer is passed explicitly and is not required to be the owner of
 * `from`, so a test can also build a message that is self consistent but whose
 * signature does not verify, or one signed by a different identity.
 */
export function signedBytes (unsigned: UnsignedRequest | UnsignedResponse, signerName: string): Uint8Array {
  const digest = sha256Bytes(signingBytes(unsigned))
  return encodeEnvelopeBytes(unsigned, signDigest(testPrivateKey(signerName), digest))
}

export function signedRequestBytes (overrides: Partial<UnsignedRequest> = {}, signerName = 'alice'): Uint8Array {
  return signedBytes(unsignedRequest(overrides), signerName)
}

export function signedResponseBytes (overrides: Partial<UnsignedResponse> = {}, signerName = 'bob'): Uint8Array {
  return signedBytes(unsignedResponse(overrides), signerName)
}

/** Decodes envelope bytes back into the plain wire object, for field tampering. */
export function wireOf (bytes: Uint8Array): JsonObject {
  const value = parseJsonBytes(bytes)
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('envelope bytes are not a JSON object')
  }
  return value
}

/**
 * Rewrites the raw text of an envelope, without touching the signature.
 *
 * Used to prove that any change to a signed field breaks verification, and to
 * reproduce non canonical spellings of an otherwise identical message.
 */
export function rewriteText (bytes: Uint8Array, text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

/** Renders a wire object as JSON text; the caller controls key order and spacing. */
export function wireText (value: JsonValue): string {
  return JSON.stringify(value)
}

