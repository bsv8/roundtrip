import { describe, expect, it } from 'vitest'
import {
  LocalRoundtripSigner,
  RoundtripCore,
  SIGNING_PREFIX,
  TRIMMED_RESPONSE_PREFIX,
  digestOf,
  encodeBase64Url,
  encodeEnvelopeBytes,
  equalBytes,
  isRoundtripError,
  isTrimmedResponse,
  parseJsonText,
  parseRequest,
  parseResponse,
  parseTrimmedResponse,
  publicKeyToString,
  sha256Bytes,
  signDigest,
  signingBytes,
  signingPrefixOf,
  unsignedToWire,
  verifyDigest,
  verifyTrimmedResponse,
  type JsonObject,
  type UnsignedMessage,
  type UnsignedResponse,
  type UnsignedTrimmedResponse
} from '../src/index.js'
import {
  TEST_NOW,
  fixedRandom,
  signedBytes,
  testPrivateKey,
  testPublicKey,
  testSigner,
  unsignedRequest,
  unsignedResponse,
  unsignedTrimmedResponse
} from './fixtures.js'

/**
 * The message layer for the optional trusted HTTPS response.
 *
 * No transport in this version speaks it. What has to exist anyway is the
 * packing and the parsing, because an application that decides to use it needs
 * one canonical encoding and one strict reader, exactly like the base messages.
 *
 * What must keep holding is that the base readers refuse this shape. A trimmed
 * response is a separate message with a separate signing prefix, not a base
 * response with a field removed.
 */

const utf8 = new TextEncoder()
const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes)

function codeOf (body: () => unknown): string {
  try {
    body()
    return ''
  } catch (error) {
    return isRoundtripError(error) ? error.code : 'NOT_A_ROUNDTRIP_ERROR'
  }
}

async function codeOfAsync (body: () => Promise<unknown>): Promise<string> {
  try {
    await body()
    return ''
  } catch (error) {
    return isRoundtripError(error) ? error.code : 'NOT_A_ROUNDTRIP_ERROR'
  }
}

const alice = (): Uint8Array => testPublicKey('alice')
const bob = (): Uint8Array => testPublicKey('bob')

/** Signs an unsigned message with the test identity that owns its `from`. */
function signFor (unsigned: UnsignedMessage, signerName?: string): Uint8Array {
  const name = signerName ?? (equalBytes(unsigned.from, alice()) ? 'alice' : 'bob')
  return signDigest(testPrivateKey(name), sha256Bytes(signingBytes(unsigned)))
}

/** Complete, correctly signed trimmed response bytes. */
function trimmedBytes (overrides: Partial<UnsignedTrimmedResponse> = {}, signerName?: string): Uint8Array {
  const unsigned = unsignedTrimmedResponse(overrides)
  return encodeEnvelopeBytes(unsigned, signFor(unsigned, signerName))
}

describe('trimmed response: the wire shape', () => {
  it('carries exactly from, to, body and sig', () => {
    const unsigned = unsignedTrimmedResponse({ body: { ok: true, result: { confirmed: 42 } } })
    const wire = JSON.parse(text(encodeEnvelopeBytes(unsigned, signFor(unsigned)))) as JsonObject
    expect(Object.keys(wire).sort()).toEqual(['body', 'from', 'sig', 'to'])
    // No reply_to, no nonce, and no type, version or id either.
    for (const field of ['reply_to', 'nonce', 'expires', 'type', 'version', 'id']) {
      expect(Object.prototype.hasOwnProperty.call(wire, field), field).toBe(false)
    }
    expect(wire.from).toBe(publicKeyToString(bob()))
    expect(wire.to).toBe(publicKeyToString(alice()))
  })

  it('is canonical, so key order and whitespace do not change the signed bytes', () => {
    const unsigned = unsignedTrimmedResponse({ body: { ok: true, result: { b: 1, a: 2 } } })
    const bytes = encodeEnvelopeBytes(unsigned, signFor(unsigned))
    const wire = JSON.parse(text(bytes)) as JsonObject
    const respelled = `{ "sig" : ${JSON.stringify(wire.sig)} , "body": ${JSON.stringify(wire.body)},\n"to":${JSON.stringify(wire.to)},"from":${JSON.stringify(wire.from)} }`
    // The reader accepts the other spelling and reproduces the same bytes.
    const parsed = parseTrimmedResponse(parseJsonText(respelled))
    expect(equalBytes(digestOf(parsed.unsigned), digestOf(unsigned))).toBe(true)
    expect(equalBytes(encodeEnvelopeBytes(parsed.unsigned, parsed.signature), bytes)).toBe(true)
  })

  it('refuses a missing field, an unknown field and a base only field', () => {
    const unsigned = unsignedTrimmedResponse()
    const wire = JSON.parse(text(encodeEnvelopeBytes(unsigned, signFor(unsigned)))) as JsonObject
    for (const field of ['from', 'to', 'body', 'sig']) {
      const missing = { ...wire }
      delete missing[field]
      expect(codeOf(() => parseTrimmedResponse(missing)), `missing ${field}`).toBe('ERR_ENVELOPE_FIELD_MISSING')
    }
    // A base response field, or an expansion of this shape, is refused.
    expect(codeOf(() => parseTrimmedResponse({ ...wire, reply_to: encodeBase64Url(new Uint8Array(32)) }))).toBe('ERR_ENVELOPE_FIELD_UNKNOWN')
    expect(codeOf(() => parseTrimmedResponse({ ...wire, nonce: encodeBase64Url(new Uint8Array(32)) }))).toBe('ERR_ENVELOPE_FIELD_UNKNOWN')
    expect(codeOf(() => parseTrimmedResponse({ ...wire, version: 1 }))).toBe('ERR_ENVELOPE_FIELD_UNKNOWN')
    // The body still has to be one of the two signed shapes.
    expect(codeOf(() => parseTrimmedResponse({ ...wire, body: { result: 1 } }))).toBe('ERR_RESPONSE_SHAPE')
    expect(codeOf(() => parseTrimmedResponse({ ...wire, body: { ok: true } }))).toBe('ERR_RESPONSE_SHAPE')
    expect(codeOf(() => parseTrimmedResponse({ ...wire, from: encodeBase64Url(new Uint8Array(32)) }))).toBe('ERR_PUBLIC_KEY')
  })
})

describe('trimmed response: its own signing prefix', () => {
  it('signs with roundtrip/http-response/v1 and not with the base prefix', () => {
    const unsigned = unsignedTrimmedResponse()
    expect(signingPrefixOf(unsigned)).toBe(TRIMMED_RESPONSE_PREFIX)
    expect(TRIMMED_RESPONSE_PREFIX).toBe('roundtrip/http-response/v1\n')
    expect(signingPrefixOf(unsignedRequest())).toBe(SIGNING_PREFIX)
    const bytes = signingBytes(unsigned)
    expect(text(bytes.subarray(0, TRIMMED_RESPONSE_PREFIX.length))).toBe(TRIMMED_RESPONSE_PREFIX)
    expect(text(bytes.subarray(0, SIGNING_PREFIX.length))).not.toBe(SIGNING_PREFIX)
  })

  it('produces a different digest from a base response with the same fields', () => {
    const trimmed = unsignedTrimmedResponse()
    const base: UnsignedResponse = { ...unsignedResponse({ from: trimmed.from, to: trimmed.to, body: trimmed.body }) }
    expect(equalBytes(digestOf(trimmed), digestOf(base))).toBe(false)
  })

  it('cannot be replayed as a base response signature', () => {
    const trimmed = unsignedTrimmedResponse()
    const base: UnsignedResponse = { ...unsignedResponse({ from: trimmed.from, to: trimmed.to, body: trimmed.body }) }
    // The honest signature over the trimmed bytes does not verify over base bytes.
    expect(codeOf(() => { verifyDigest(base.from, digestOf(base), signFor(trimmed)) })).toBe('ERR_SIGNATURE')
    // And the reverse: a base signature cannot be moved onto a trimmed message.
    expect(codeOf(() => { verifyDigest(trimmed.from, digestOf(trimmed), signFor(base)) })).toBe('ERR_SIGNATURE')
  })

  it('is refused by the base readers in both directions', () => {
    const unsigned = unsignedTrimmedResponse()
    const wire = parseJsonText(text(encodeEnvelopeBytes(unsigned, signFor(unsigned))))
    // The protocol requires a trimmed response to be unusable as a base message.
    expect(codeOf(() => parseResponse(wire))).toBe('ERR_ENVELOPE_FIELD_MISSING')
    expect(codeOf(() => parseRequest(wire))).toBe('ERR_ENVELOPE_FIELD_MISSING')
    // And a base response is not a trimmed one.
    const baseWire = parseJsonText(text(signedBytes(unsignedResponse(), 'bob')))
    expect(codeOf(() => parseTrimmedResponse(baseWire))).toBe('ERR_ENVELOPE_FIELD_UNKNOWN')
  })
})

describe('trimmed response: one signing capability, no second code path', () => {
  it('is signed by the same signer interface', async () => {
    const signer = new LocalRoundtripSigner(testPrivateKey('bob'))
    const unsigned = unsignedTrimmedResponse()
    const signature = await signer.signRoundtrip(unsigned)
    expect(() => { verifyDigest(unsigned.from, digestOf(unsigned), signature) }).not.toThrow()
    // The kind guard knows the difference, and the signer still refuses
    // anything that is not a validated message.
    expect(isTrimmedResponse(unsigned)).toBe(true)
    expect(isTrimmedResponse(unsignedResponse())).toBe(false)
    expect(await codeOfAsync(async () => await signer.signRoundtrip({ kind: 'nonsense' } as never))).toBe('ERR_SIGNER_FAILED')
  })

  it('is packed by the same encoder, so there is one canonical form per kind', () => {
    for (const unsigned of [unsignedTrimmedResponse(), unsignedResponse(), unsignedRequest()]) {
      const signature = signFor(unsigned)
      const prefix = signingPrefixOf(unsigned)
      // One encoder for all three kinds: the envelope is the canonical form of
      // the unsigned message plus the signature, and nothing else.
      const bytes = encodeEnvelopeBytes(unsigned, signature)
      const wire = JSON.parse(text(bytes)) as JsonObject
      expect(wire.sig).toBe(encodeBase64Url(signature))
      // The envelope is exactly the unsigned fields plus sig, nothing more.
      expect(Object.keys(wire).sort()).toEqual([...Object.keys(unsignedToWire(unsigned)), 'sig'].sort())
      // The signed bytes are the prefix followed by the canonical unsigned
      // form, and the digest is taken over exactly those bytes.
      expect(text(signingBytes(unsigned).subarray(0, prefix.length))).toBe(prefix)
      expect(equalBytes(digestOf(unsigned), sha256Bytes(signingBytes(unsigned)))).toBe(true)
    }
  })
})

describe('trimmed response: what verification does and does not prove', () => {
  const expectation = { from: bob(), to: alice() }

  it('returns the business body for a correct response', () => {
    expect(verifyTrimmedResponse(parseJsonText(text(trimmedBytes({ body: { ok: true, result: { confirmed: 42 } } }))), expectation))
      .toEqual({ ok: true, result: { confirmed: 42 } })
    expect(verifyTrimmedResponse(parseJsonText(text(trimmedBytes({ body: { ok: false, error: { code: 'X', message: 'y' } } }))), expectation))
      .toEqual({ ok: false, error: { code: 'X', message: 'y' } })
  })

  it('still enforces both identities and the signature', () => {
    const wire = parseJsonText(text(trimmedBytes()))
    expect(codeOf(() => { verifyTrimmedResponse(wire, { from: bob(), to: testPublicKey('carol') }) })).toBe('ERR_RESPONSE_TO')
    expect(codeOf(() => { verifyTrimmedResponse(wire, { from: testPublicKey('carol'), to: alice() }) })).toBe('ERR_RESPONSE_FROM')
    // A result swapped in after signing, with bob's own signature left in place.
    const tampered = { ...(JSON.parse(text(trimmedBytes())) as JsonObject), body: { ok: true, result: { confirmed: 999999 } } }
    expect(codeOf(() => { verifyTrimmedResponse(tampered, expectation) })).toBe('ERR_RESPONSE_SIGNATURE')
    // A result signed by somebody else while claiming to be bob.
    expect(codeOf(() => { verifyTrimmedResponse(parseJsonText(text(trimmedBytes({}, 'mallory'))), expectation) })).toBe('ERR_RESPONSE_SIGNATURE')
  })

  it('cannot prove which request it answers, and that is the documented cost', async () => {
    // This is the trade off of dropping reply_to, written as a test rather than
    // a claim: the same bytes satisfy any request between the same two
    // identities, because the message carries nothing that tells them apart. A
    // trusted transport has to supply the correlation the signature gave up.
    const older = parseJsonText(text(trimmedBytes({ body: { ok: true, result: { account: 'A' } } })))
    const caller = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(3) })
    const first = await caller.buildRequest(bob(), { op: 'get_balance', args: { account: 'A' } })
    const second = await caller.buildRequest(bob(), { op: 'get_balance', args: { account: 'B' } })
    expect(first.requestId).not.toBe(second.requestId)
    // Both waiting calls would accept the same verified response.
    expect(verifyTrimmedResponse(older, expectation)).toEqual({ ok: true, result: { account: 'A' } })
    expect(verifyTrimmedResponse(older, expectation)).toEqual({ ok: true, result: { account: 'A' } })
  })
})

describe('trimmed response: the core never produces or consumes it', () => {
  it('answers a request with a base response, and refuses a trimmed one', async () => {
    const server = new RoundtripCore({ signer: testSigner('bob'), nowSeconds: () => TEST_NOW, handler: () => ({ ok: true, result: { ok: 1 } }) })
    const caller = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(3) })
    const prepared = await caller.buildRequest(bob(), { op: 'ping' })
    const responseBytes = await server.handle(prepared.bytes)
    expect(Object.keys(JSON.parse(text(responseBytes)) as JsonObject).sort()).toEqual(['body', 'from', 'reply_to', 'sig', 'to'])
    // The core has no trimmed mode, so a trimmed response cannot complete a call.
    const unsigned: UnsignedTrimmedResponse = { kind: 'trimmed-response', from: bob(), to: alice(), body: { ok: true, result: { stolen: true } } }
    expect(codeOf(() => { caller.verifyResponse(encodeEnvelopeBytes(unsigned, signFor(unsigned)), prepared) })).toBe('ERR_ENVELOPE_FIELD_MISSING')
    // And the honest base response still completes it.
    expect(caller.verifyResponse(responseBytes, prepared).ok).toBe(true)
  })
})
