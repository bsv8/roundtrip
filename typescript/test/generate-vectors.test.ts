import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, test } from 'vitest'
import {
  RoundtripCore,
  TRIMMED_RESPONSE_PREFIX,
  encodeBase64Url,
  encodeEnvelopeBytes,
  equalBytes,
  parseTrimmedResponse,
  parseJsonText,
  requestIdOf,
  sha256Bytes,
  signDigest,
  signingBytes,
  verifyDigest,
  type JsonValue,
  type UnsignedRequest,
  type UnsignedResponse,
  type UnsignedTrimmedResponse
} from '../src/index.js'
import { testPrivateKey, testPublicKey, testSigner } from './fixtures.js'
import { canonicalizeToString } from '../src/jcs.js'
import { installFixtures, runGenerator, verifyGenerated, type VectorMessage, type Vectors } from '../scripts/vector-cases.js'

const here = dirname(fileURLToPath(import.meta.url))
const target = resolve(here, '../../testdata/vectors.json')

const EXPIRES = 1790000000

/**
 * A vector is only worth shipping if its signature verifies against the `from`
 * field. Asserting it here means a mismatched signer can never reach the
 * committed file again: the first run would fail instead of publishing a
 * signature no other implementation can check.
 */
function assertSignedByFrom (name: string, unsigned: UnsignedRequest | UnsignedResponse | UnsignedTrimmedResponse, digest: Uint8Array, signature: Uint8Array, signerName: string): void {
  if (equalBytes(unsigned.from, testPublicKey(signerName)) !== true) {
    throw new Error(`vector ${name}: from is not the public key of the signer ${signerName}`)
  }
  try {
    verifyDigest(unsigned.from, digest, signature)
  } catch (error) {
    throw new Error(`vector ${name}: signature does not verify against from: ${error instanceof Error ? error.message : String(error)}`)
  }
}

function nonce (text: string): Uint8Array {
  const bytes = new Uint8Array(32)
  for (let index = 0; index < bytes.length; index++) bytes[index] = (text.charCodeAt(index % text.length) + index) & 0xff
  return bytes
}

/**
 * Builds one request vector. The signer is always the owner of `from`, so every
 * vector is self consistent: a second implementation can verify the signature
 * against the `from` field alone, without knowing the generator's intent.
 */
function requestVector (name: string, unsigned: UnsignedRequest, signerName: string): VectorMessage {
  const bytes = signingBytes(unsigned)
  const digest = sha256Bytes(bytes)
  const signature = signDigest(testPrivateKey(signerName), digest)
  assertSignedByFrom(name, unsigned, digest, signature, signerName)
  const envelopeBytes = encodeEnvelopeBytes(unsigned, signature)
  return {
    name,
    kind: 'request',
    unsigned: {
      from: encodeBase64Url(unsigned.from),
      to: encodeBase64Url(unsigned.to),
      nonce: encodeBase64Url(unsigned.nonce),
      expires: unsigned.expires,
      body: unsigned.body
    },
    wire: canonicalizeToString(parseJsonText(new TextDecoder().decode(bytes.slice('roundtrip/v1\n'.length)))),
    signingBytesHex: Buffer.from(bytes).toString('hex'),
    digestHex: Buffer.from(digest).toString('hex'),
    requestId: requestIdOf(unsigned),
    signatureBase64Url: encodeBase64Url(signature),
    signatureHex: Buffer.from(signature).toString('hex'),
    envelope: new TextDecoder().decode(envelopeBytes),
    messageBase64Url: encodeBase64Url(envelopeBytes)
  }
}

function responseVector (name: string, unsigned: UnsignedResponse, signerName: string, replyTo: string): VectorMessage {
  const bytes = signingBytes(unsigned)
  const digest = sha256Bytes(bytes)
  const signature = signDigest(testPrivateKey(signerName), digest)
  assertSignedByFrom(name, unsigned, digest, signature, signerName)
  const envelopeBytes = encodeEnvelopeBytes(unsigned, signature)
  return {
    name,
    kind: 'response',
    unsigned: {
      from: encodeBase64Url(unsigned.from),
      to: encodeBase64Url(unsigned.to),
      reply_to: replyTo,
      body: unsigned.body
    },
    wire: canonicalizeToString(parseJsonText(new TextDecoder().decode(bytes.slice('roundtrip/v1\n'.length)))),
    signingBytesHex: Buffer.from(bytes).toString('hex'),
    digestHex: Buffer.from(digest).toString('hex'),
    signatureBase64Url: encodeBase64Url(signature),
    signatureHex: Buffer.from(signature).toString('hex'),
    envelope: new TextDecoder().decode(envelopeBytes),
    messageBase64Url: encodeBase64Url(envelopeBytes)
  }
}

/**
 * Builds one trimmed response vector. It carries no request id, so the vector
 * pins the shape, the separate signing prefix and the signature, and nothing
 * about correlation.
 */
function trimmedResponseVector (name: string, unsigned: UnsignedTrimmedResponse, signerName: string): VectorMessage {
  const bytes = signingBytes(unsigned)
  const digest = sha256Bytes(bytes)
  const signature = signDigest(testPrivateKey(signerName), digest)
  assertSignedByFrom(name, unsigned, digest, signature, signerName)
  const envelopeBytes = encodeEnvelopeBytes(unsigned, signature)
  // The trimmed bytes really are signed with the other prefix, or the vector
  // would pin the wrong thing.
  if (new TextDecoder().decode(bytes.subarray(0, TRIMMED_RESPONSE_PREFIX.length)) !== TRIMMED_RESPONSE_PREFIX) {
    throw new Error(`vector ${name}: trimmed response is not signed with ${JSON.stringify(TRIMMED_RESPONSE_PREFIX)}`)
  }
  return {
    name,
    kind: 'trimmed-response',
    unsigned: {
      from: encodeBase64Url(unsigned.from),
      to: encodeBase64Url(unsigned.to),
      body: unsigned.body
    },
    wire: canonicalizeToString(parseJsonText(new TextDecoder().decode(bytes.slice(TRIMMED_RESPONSE_PREFIX.length)))),
    signingBytesHex: Buffer.from(bytes).toString('hex'),
    digestHex: Buffer.from(digest).toString('hex'),
    signatureBase64Url: encodeBase64Url(signature),
    signatureHex: Buffer.from(signature).toString('hex'),
    envelope: new TextDecoder().decode(envelopeBytes),
    messageBase64Url: encodeBase64Url(envelopeBytes)
  }
}

function build (): Vectors {
  installFixtures({ testPrivateKey, testPublicKey })
  const vectors = runGenerator()

  const balance: UnsignedRequest = {
    kind: 'request',
    from: testPublicKey('alice'),
    to: testPublicKey('bob'),
    nonce: nonce('balance'),
    expires: EXPIRES,
    body: { op: 'get_balance', args: { asset: 'BSV', as_of: 1790000000, memo: null } }
  }
  const unicode: UnsignedRequest = {
    kind: 'request',
    from: testPublicKey('alice'),
    to: testPublicKey('bob'),
    nonce: nonce('unicode'),
    expires: EXPIRES,
    body: { op: 'note', args: { text: 'héllo\n😀 "quoted" \\ slash /', tabs: 'a\tb', control: '\u0001' } }
  }
  const minimal: UnsignedRequest = {
    kind: 'request',
    from: testPublicKey('carol'),
    to: testPublicKey('alice'),
    nonce: nonce('minimal'),
    expires: EXPIRES,
    body: { op: 'ping' }
  }
  const wrongRecipient: UnsignedRequest = {
    kind: 'request',
    from: testPublicKey('alice'),
    to: testPublicKey('carol'),
    nonce: nonce('wrong-recipient'),
    expires: EXPIRES,
    body: { op: 'get_balance', args: {} }
  }
  const attacker: UnsignedRequest = {
    kind: 'request',
    from: testPublicKey('mallory'),
    to: testPublicKey('bob'),
    nonce: nonce('attacker'),
    expires: EXPIRES,
    body: { op: 'transfer', args: { amount: '1.00000000' } }
  }
  const bigNumbers: UnsignedRequest = {
    kind: 'request',
    from: testPublicKey('alice'),
    to: testPublicKey('bob'),
    nonce: nonce('big-numbers'),
    expires: EXPIRES,
    body: { op: 'quote', args: { big: 1e21, small: 1e-7, exact: '9007199254740993', list: [3, 1, 2] } }
  }

  vectors.requests = [
    requestVector('get_balance', balance, 'alice'),
    requestVector('unicode_body', unicode, 'alice'),
    requestVector('minimal_ping', minimal, 'carol'),
    requestVector('wrong_recipient', wrongRecipient, 'alice'),
    requestVector('attacker', attacker, 'mallory'),
    requestVector('big_numbers', bigNumbers, 'alice')
  ]

  const balanceId = vectors.requests[0].requestId as string
  const unicodeId = vectors.requests[1].requestId as string
  const replyToBytes = (id: string): Uint8Array => {
    const value = id.replace(/-/g, '+').replace(/_/g, '/')
    const padded = value + '='.repeat((4 - (value.length % 4)) % 4)
    return new Uint8Array(Buffer.from(padded, 'base64'))
  }

  vectors.responses = [
    responseVector('balance_ok', {
      kind: 'response',
      from: testPublicKey('bob'),
      to: testPublicKey('alice'),
      replyTo: replyToBytes(balanceId),
      body: { ok: true, result: { confirmed: 42, satoshis: '1050000000', assets: ['BSV'], nested: { b: 2, a: 1 } } }
    }, 'bob', balanceId),
    responseVector('balance_business_error', {
      kind: 'response',
      from: testPublicKey('bob'),
      to: testPublicKey('alice'),
      replyTo: replyToBytes(balanceId),
      body: { ok: false, error: { code: 'UNKNOWN_ASSET', message: '没有这个资产' } }
    }, 'bob', balanceId),
    responseVector('unicode_ok', {
      kind: 'response',
      from: testPublicKey('bob'),
      to: testPublicKey('alice'),
      replyTo: replyToBytes(unicodeId),
      body: { ok: true, result: { stored: true, note: 'ok😀' } }
    }, 'bob', unicodeId)
  ]

  // The optional trimmed response: same shell, no reply_to, its own prefix. It
  // exists so a second implementation cannot accidentally agree with the base
  // format here.
  vectors.trimmedResponses = [
    trimmedResponseVector('trimmed_ok', {
      kind: 'trimmed-response',
      from: testPublicKey('bob'),
      to: testPublicKey('alice'),
      body: { ok: true, result: { confirmed: 42, satoshis: '1050000000', nested: { b: 2, a: 1 } } }
    }, 'bob'),
    trimmedResponseVector('trimmed_business_error', {
      kind: 'trimmed-response',
      from: testPublicKey('carol'),
      to: testPublicKey('alice'),
      body: { ok: false, error: { code: 'UNKNOWN_ASSET', message: '没有这个资产' } }
    }, 'carol'),
    trimmedResponseVector('trimmed_unicode_ok', {
      kind: 'trimmed-response',
      from: testPublicKey('bob'),
      to: testPublicKey('alice'),
      body: { ok: true, result: { note: 'ok😀' } }
    }, 'bob')
  ]
  return vectors
}

test('shared vectors match this implementation', () => {
  const vectors = build()
  verifyGenerated(vectors)
  const text = `${JSON.stringify(vectors, null, 2)}\n`
  if (process.env.ROUNDTRIP_WRITE_VECTORS === '1') {
    writeFileSync(target, text)
    return
  }
  expect(existsSync(target)).toBe(true)
  const committed = JSON.parse(readFileSync(target, 'utf8')) as JsonValue
  expect(committed).toEqual(JSON.parse(text))
})

test('the vector file is loadable by the Go implementation', () => {
  // Guards the shape only; the Go suite asserts the values.
  const vectors = build()
  expect(vectors.keys.length).toBeGreaterThan(0)
  expect(vectors.requests.length).toBeGreaterThan(0)
  expect(vectors.responses.length).toBeGreaterThan(0)
  expect(vectors.trimmedResponses.length).toBeGreaterThan(0)
  // The shared file has to carry the strict reading refusals too, otherwise the
  // Go reader is never pinned to the same decisions.
  expect(vectors.reject.length).toBeGreaterThan(0)
  const core = new RoundtripCore({ signer: testSigner('alice') })
  expect(core.publicKey().length).toBe(33)
})
