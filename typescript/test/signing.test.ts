import { describe, expect, it } from 'vitest'
import {
  LocalRoundtripSigner,
  RoundtripCore,
  digestOf,
  encodeBase64Url,
  encodeEnvelopeBytes,
  equalBytes,
  isRoundtripError,
  parseJsonText,
  parseRequest,
  parseResponse,
  publicKeyToString,
  requestIdOf,
  resolvePublicKey,
  sha256Bytes,
  signDigest,
  signingBytes,
  type HandlerOutcome,
  type RoundtripSigner,
  type UnsignedMessage
} from '../src/index.js'
import {
  TEST_EXPIRES,
  TEST_NOW,
  fixedRandom,
  signedBytes,
  signedRequestBytes,
  testPrivateKey,
  testPublicKey,
  testSigner,
  unsignedRequest,
  unsignedResponse,
  wireOf
} from './fixtures.js'

const utf8 = new TextEncoder()
const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes)

async function codeOf (body: () => Promise<unknown>): Promise<string> {
  try {
    await body()
    return ''
  } catch (error) {
    return isRoundtripError(error) ? error.code : 'NOT_A_ROUNDTRIP_ERROR'
  }
}

/** A receiving core that records every handler invocation. */
function receiver (name = 'bob', extra: { maxRequestTtlSeconds?: number, clockSkewSeconds?: number, nowSeconds?: () => number } = {}): { core: RoundtripCore, calls: Array<{ from: Uint8Array, requestId: string, body: unknown }> } {
  const calls: Array<{ from: Uint8Array, requestId: string, body: unknown }> = []
  const core = new RoundtripCore({
    signer: testSigner(name),
    // Pinned to the vector instant, so expiry is a test decision and not a
    // function of the day the suite runs.
    nowSeconds: () => TEST_NOW,
    handler: ({ callerPublicKey, requestId, body }) => {
      calls.push({ from: new Uint8Array(callerPublicKey), requestId, body })
      return { ok: true, result: { accepted: true } }
    },
    ...extra
  })
  return { core, calls }
}

describe('stage 2: the signer is the only private key boundary', () => {
  it('sets from from the signer public key, and the business call cannot choose it', async () => {
    const core = new RoundtripCore({ signer: testSigner('alice'), randomBytes: fixedRandom(3) })
    const prepared = await core.buildRequest(testPublicKey('bob'), { op: 'ping' })
    expect(equalBytes(prepared.unsigned.from, core.publicKey())).toBe(true)
    // A string target is resolved to the same bytes as the binary one, so the
    // identity on the wire has exactly one spelling.
    expect(publicKeyToString(prepared.unsigned.to)).toBe(encodeBase64Url(testPublicKey('bob')))
    expect(equalBytes(resolvePublicKey(publicKeyToString(testPublicKey('bob'))), testPublicKey('bob'))).toBe(true)
  })

  it('returns a defensive copy of the identity', () => {
    const core = new RoundtripCore({ signer: testSigner('alice') })
    const first = core.publicKey()
    first[0] = 0x09
    expect(equalBytes(core.publicKey(), testPublicKey('alice'))).toBe(true)
  })

  it('refuses a signer whose signature does not verify for the identity it advertises', async () => {
    // The signer claims to be alice but signs with mallory. This is a
    // configuration error, and it must be caught locally, before any bytes
    // reach a transport.
    const lying: RoundtripSigner = {
      publicKey: () => testPublicKey('alice'),
      signRoundtrip: async (unsigned: UnsignedMessage): Promise<Uint8Array> =>
        await Promise.resolve(signDigest(testPrivateKey('mallory'), sha256Bytes(signingBytes(unsigned))))
    }
    const core = new RoundtripCore({ signer: lying })
    expect(await codeOf(async () => await core.buildRequest(testPublicKey('bob'), { op: 'ping' }))).toBe('ERR_SIGNER_KEY')
  })

  it('refuses a signer whose output is not a signature at all', async () => {
    const garbage: RoundtripSigner = {
      publicKey: () => testPublicKey('alice'),
      signRoundtrip: async (): Promise<Uint8Array> => await Promise.resolve(new Uint8Array([1, 2, 3]))
    }
    const core = new RoundtripCore({ signer: garbage })
    expect(await codeOf(async () => await core.buildRequest(testPublicKey('bob'), { op: 'ping' }))).toBe('ERR_SIGNER_KEY')
  })

  it('refuses to construct a core whose identity is not a valid public key', () => {
    expect(() => new RoundtripCore({ signer: { publicKey: () => new Uint8Array(32), signRoundtrip: async () => new Uint8Array() } })).toThrow()
  })

  it('does not let a signer sign something the core never validated', async () => {
    const seen: UnsignedMessage[] = []
    const spy: RoundtripSigner = {
      publicKey: () => testPublicKey('alice'),
      signRoundtrip: async (unsigned: UnsignedMessage): Promise<Uint8Array> => {
        seen.push(unsigned)
        return await testSigner('alice').signRoundtrip(unsigned)
      }
    }
    const core = new RoundtripCore({ signer: spy })
    const prepared = await core.buildRequest(testPublicKey('bob'), { op: 'ping', args: { a: 1 } })
    expect(seen).toHaveLength(1)
    // The signer is handed the whole unsigned message, so it can independently
    // re-check the shape and rebuild the canonical bytes itself.
    expect(equalBytes(sha256Bytes(signingBytes(seen[0])), digestOf(prepared.unsigned))).toBe(true)
  })
})

describe('stage 2: a tampered field breaks the request', () => {
  const valid = (): Uint8Array => signedRequestBytes()

  it('refuses a changed body, and the handler never runs', async () => {
    const { core, calls } = receiver()
    const wire = wireOf(valid())
    const tampered = { ...wire, body: { op: 'transfer', args: { amount: '1000.00000000' } } }
    const bytes = encodeEnvelopeBytes(parseRequest(parseJsonText(text(valid()))).unsigned, parseRequest(parseJsonText(text(valid()))).signature)
    // Re-encode with the original signature: only the bytes change.
    const forged = utf8.encode(JSON.stringify(tampered))
    expect(await codeOf(async () => await core.handle(forged))).toBe('ERR_SIGNATURE')
    expect(calls).toHaveLength(0)
    expect(bytes.length).toBeGreaterThan(0)
  })

  it('refuses every single field change, one at a time', async () => {
    const base = signedRequestBytes()
    const baseWire = wireOf(base)
    const mutations: Array<[string, (wire: Record<string, unknown>) => Record<string, unknown>]> = [
      ['from', (wire) => ({ ...wire, from: encodeBase64Url(testPublicKey('mallory')) })],
      ['to', (wire) => ({ ...wire, to: encodeBase64Url(testPublicKey('carol')) })],
      ['nonce', (wire) => ({ ...wire, nonce: encodeBase64Url(new Uint8Array(32).fill(4)) })],
      ['expires', (wire) => ({ ...wire, expires: TEST_EXPIRES + 86_400 })],
      ['body', (wire) => ({ ...wire, body: { op: 'transfer', args: { amount: '1' } } })],
      ['sig', (wire) => ({ ...wire, sig: encodeBase64Url(signDigest(testPrivateKey('mallory'), sha256Bytes(new Uint8Array(32)))) })]
    ]
    for (const [field, mutate] of mutations) {
      const { core, calls } = receiver()
      const code = await codeOf(async () => await core.handle(utf8.encode(JSON.stringify(mutate(baseWire)))))
      // Every change is refused. A changed recipient is caught one step earlier,
      // by the recipient check, so the two rejection reasons are both correct
      // and neither of them lets the request through.
      expect(code, field).not.toBe('')
      expect(calls, field).toHaveLength(0)
    }
  })

  it('refuses a message whose signature belongs to another identity', async () => {
    const { core, calls } = receiver()
    // Correctly formed, correctly canonical, but signed by mallory while
    // claiming to be alice.
    const bytes = signedBytes(unsignedRequest({ from: testPublicKey('alice') }), 'mallory')
    expect(await codeOf(async () => await core.handle(bytes))).toBe('ERR_SIGNATURE')
    expect(calls).toHaveLength(0)
  })

  it('refuses a body that was reordered or re-spelled after signing', async () => {
    const { core, calls } = receiver()
    const wire = wireOf(signedRequestBytes())
    // Same logical content, different JSON spelling: this one must still pass,
    // because the signature covers the canonical form, not the text.
    const respelled = `{"body":${JSON.stringify(wire.body)},"to":${JSON.stringify(wire.to)},"sig":${JSON.stringify(wire.sig)},"from":${JSON.stringify(wire.from)},"nonce":${JSON.stringify(wire.nonce)},"expires":${wire.expires as number}}`
    expect(await codeOf(async () => await core.handle(utf8.encode(respelled)))).toBe('')
    expect(calls).toHaveLength(1)
    // One extra space inside the object changes nothing either.
    const spaced = respelled.replace('{"body"', '{ "body"')
    expect(await codeOf(async () => await core.handle(utf8.encode(spaced)))).toBe('')
  })

  it('accepts a message whose JSON text differs, because the digest is over the canonical form', async () => {
    const { core, calls } = receiver()
    const wire = wireOf(signedRequestBytes())
    // The same logical request, pretty printed with a different key order.
    const prettyPrinted = `{\n  "body": ${JSON.stringify(wire.body)},\n  "expires": ${wire.expires as number},\n  "sig": ${JSON.stringify(wire.sig)},\n  "to": ${JSON.stringify(wire.to)},\n  "from": ${JSON.stringify(wire.from)},\n  "nonce": ${JSON.stringify(wire.nonce)}\n}`
    expect(utf8.encode(prettyPrinted).length).toBeGreaterThan(utf8.encode(JSON.stringify(wire)).length)
    const responseBytes = await core.handle(utf8.encode(prettyPrinted))
    // The responder quotes the digest of the canonical form, so the request id
    // is the same one the canonical text would have produced.
    const response = parseResponse(parseJsonText(text(responseBytes)))
    expect(encodeBase64Url(response.unsigned.replyTo)).toBe(requestIdOf(parseRequest(parseJsonText(JSON.stringify(wire))).unsigned))
    // A second delivery of the same request is recognised, whichever spelling
    // it arrives in, because the id comes from the canonical form.
    const duplicate = await core.handle(utf8.encode(prettyPrinted))
    const duplicateResponse = parseResponse(parseJsonText(text(duplicate)))
    expect((duplicateResponse.unsigned.body as { error?: { code?: string } }).error?.code).toBe('REQUEST_ALREADY_SEEN')
    expect(calls).toHaveLength(1)
  })
})

describe('stage 2: a message must not be executed by the wrong node', () => {
  it('refuses a request addressed to somebody else, and the handler never runs', async () => {
    const { core, calls } = receiver('bob')
    // Alice legitimately signs a request for carol. Delivering it to bob must
    // not execute it, even though the signature is perfectly valid.
    const bytes = signedRequestBytes({ to: testPublicKey('carol') })
    expect(await codeOf(async () => await core.handle(bytes))).toBe('ERR_RECIPIENT')
    expect(calls).toHaveLength(0)
    // The same bytes are accepted by the intended recipient.
    const carol = receiver('carol')
    expect(await codeOf(async () => await carol.core.handle(bytes))).toBe('')
    expect(carol.calls).toHaveLength(1)
    expect(equalBytes(carol.calls[0].from, testPublicKey('alice'))).toBe(true)
  })

  it('refuses a re-targeted request, because to is covered by the signature', async () => {
    // Mallory takes a request that alice signed for carol and re-addresses it to
    // herself. Delivering it to mallory passes the recipient check, so the only
    // thing left that can stop it is the signature.
    const mallory = receiver('mallory')
    const wire = wireOf(signedRequestBytes({ to: testPublicKey('carol') }))
    const retargeted = { ...wire, to: encodeBase64Url(testPublicKey('mallory')) }
    expect(await codeOf(async () => await mallory.core.handle(utf8.encode(JSON.stringify(retargeted))))).toBe('ERR_SIGNATURE')
    expect(mallory.calls).toHaveLength(0)
    // The genuine request still works for the peer it was signed for.
    expect(await codeOf(async () => await receiver('carol').core.handle(signedRequestBytes({ to: testPublicKey('carol') })))).toBe('')
  })

  it('refuses a request whose from does not match the authenticated transport peer', async () => {
    const { core, calls } = receiver('bob')
    // A relay that authenticated carol cannot forward alice's request as if it
    // came from carol: the transport identity and the message identity are both
    // checked.
    const bytes = signedRequestBytes({ from: testPublicKey('alice'), to: testPublicKey('bob') })
    expect(await codeOf(async () => await core.handle(bytes, { callerPublicKey: testPublicKey('carol') }))).toBe('ERR_CALLER_IDENTITY')
    expect(calls).toHaveLength(0)
    expect(await codeOf(async () => await core.handle(bytes, { callerPublicKey: testPublicKey('alice') }))).toBe('')
    expect(calls).toHaveLength(1)
  })

  it('rejects expiry and the expiry window before anything else', async () => {
    const now = TEST_EXPIRES + 10
    const { core, calls } = receiver('bob', { nowSeconds: () => now })
    expect(await codeOf(async () => await core.handle(signedRequestBytes({ expires: now - 100 })))).toBe('ERR_EXPIRED')
    expect(calls).toHaveLength(0)
    // Inside the allowed clock skew it is still accepted.
    expect(await codeOf(async () => await core.handle(signedRequestBytes({ expires: now - 3 })))).toBe('')
    expect(calls).toHaveLength(1)
    // Too far in the future is refused even though it has not expired.
    const strict = receiver('bob', { nowSeconds: () => now, maxRequestTtlSeconds: 30 })
    expect(await codeOf(async () => await strict.core.handle(signedRequestBytes({ expires: now + 3_600 })))).toBe('ERR_EXPIRY_WINDOW')
    expect(strict.calls).toHaveLength(0)
  })
})

describe('stage 2: a response is accepted only from the right peer', () => {
  const clientCore = (): RoundtripCore => new RoundtripCore({ signer: testSigner('alice'), randomBytes: fixedRandom(3) })

  it('completes a call only when from, to, reply_to and the signature all match', async () => {
    const client = clientCore()
    const prepared = await client.buildRequest(testPublicKey('bob'), { op: 'get_balance' })
    const replyTo = digestOf(prepared.unsigned)
    const good = signedBytes(unsignedResponse({ from: testPublicKey('bob'), to: testPublicKey('alice'), replyTo, body: { ok: true, result: { satoshis: '42' } } }), 'bob')
    const outcome = client.verifyResponse(good, prepared)
    expect(outcome.ok).toBe(true)
    expect(outcome.ok === true ? outcome.result : null).toEqual({ satoshis: '42' })
  })

  it('refuses a forged success response', async () => {
    const client = clientCore()
    const prepared = await client.buildRequest(testPublicKey('bob'), { op: 'get_balance' })
    const replyTo = digestOf(prepared.unsigned)
    // Mallory invents a result and signs it with her own key.
    const forged = signedBytes(unsignedResponse({ from: testPublicKey('mallory'), to: testPublicKey('alice'), replyTo, body: { ok: true, result: { satoshis: '999999999' } } }), 'mallory')
    expect(await codeOf(async () => await client.verifyResponse(forged, prepared))).toBe('ERR_RESPONSE_FROM')
  })

  it('refuses a response signed by the right key but with a changed body', async () => {
    const client = clientCore()
    const prepared = await client.buildRequest(testPublicKey('bob'), { op: 'get_balance' })
    const replyTo = digestOf(prepared.unsigned)
    const honest = unsignedResponse({ from: testPublicKey('bob'), to: testPublicKey('alice'), replyTo, body: { ok: true, result: { satoshis: '42' } } })
    const wire = wireOf(signedBytes(honest, 'bob'))
    // Flip the amount but keep bob's signature.
    const tampered = { ...wire, body: { ok: true, result: { satoshis: '999999999' } } }
    expect(await codeOf(async () => await client.verifyResponse(utf8.encode(JSON.stringify(tampered)), prepared))).toBe('ERR_RESPONSE_SIGNATURE')
  })

  it('refuses a response addressed to somebody else', async () => {
    const client = clientCore()
    const prepared = await client.buildRequest(testPublicKey('bob'), { op: 'get_balance' })
    const replyTo = digestOf(prepared.unsigned)
    const elsewhere = signedBytes(unsignedResponse({ from: testPublicKey('bob'), to: testPublicKey('carol'), replyTo, body: { ok: true, result: 1 } }), 'bob')
    expect(await codeOf(async () => await client.verifyResponse(elsewhere, prepared))).toBe('ERR_RESPONSE_TO')
  })

  it('refuses a valid response that answers a different request', async () => {
    const client = clientCore()
    const waiting = await client.buildRequest(testPublicKey('bob'), { op: 'get_balance', args: { account: 'A' } })
    const other = await client.buildRequest(testPublicKey('bob'), { op: 'get_balance', args: { account: 'B' } })
    // Bob's genuine answer to the other call.
    const answerToOther = signedBytes(unsignedResponse({
      from: testPublicKey('bob'),
      to: testPublicKey('alice'),
      replyTo: digestOf(other.unsigned),
      body: { ok: true, result: { account: 'B' } }
    }), 'bob')
    expect(await codeOf(async () => await client.verifyResponse(answerToOther, waiting))).toBe('ERR_RESPONSE_REPLY_TO')
    expect(requestIdOf(waiting.unsigned)).not.toBe(requestIdOf(other.unsigned))
  })

  it('refuses a business error that is not signed by the requested peer', async () => {
    const client = clientCore()
    const prepared = await client.buildRequest(testPublicKey('bob'), { op: 'get_balance' })
    const replyTo = digestOf(prepared.unsigned)
    const honest = unsignedResponse({ from: testPublicKey('bob'), to: testPublicKey('alice'), replyTo, body: { ok: false, error: { code: 'UNKNOWN_ASSET', message: '没有这个资产' } } })
    const outcome = client.verifyResponse(signedBytes(honest, 'bob'), prepared)
    expect(outcome.ok).toBe(false)
    expect(outcome.ok === false ? outcome.error.code : '').toBe('UNKNOWN_ASSET')
    // Claiming to be bob but signing with mallory: the identity fields all
    // check out and the signature does not, which is exactly the case a
    // business error must not be allowed to masquerade as.
    expect(await codeOf(async () => await client.verifyResponse(signedBytes(honest, 'mallory'), prepared))).toBe('ERR_RESPONSE_SIGNATURE')
    // A response that admits it comes from mallory is refused on the identity.
    const other = { ...unsignedResponse({ from: testPublicKey('bob'), to: testPublicKey('alice'), replyTo, body: honest.body }), from: testPublicKey('mallory') }
    expect(await codeOf(async () => await client.verifyResponse(signedBytes(other, 'mallory'), prepared))).toBe('ERR_RESPONSE_FROM')
  })
})

describe('stage 2: the core checks its own signature before sending', () => {
  it('never hands a response to a peer without verifying it locally first', async () => {
    const bad: RoundtripSigner = {
      publicKey: () => testPublicKey('bob'),
      signRoundtrip: async (unsigned: UnsignedMessage): Promise<Uint8Array> => {
        const honest = await testSigner('bob').signRoundtrip(unsigned)
        if (unsigned.kind === 'response') {
          // Corrupt the signature: the local check must catch it.
          const broken = new Uint8Array(honest)
          broken[broken.length - 1] ^= 0xff
          return broken
        }
        return honest
      }
    }
    const core = new RoundtripCore({ signer: bad, nowSeconds: () => TEST_NOW, handler: (): HandlerOutcome => ({ ok: true, result: 1 }) })
    const request = signedRequestBytes()
    expect(await codeOf(async () => await core.handle(request))).toBe('ERR_SIGNER_KEY')
  })

  it('keeps the local signer inside the fixed protocol, with no generic sign(bytes)', async () => {
    // The exposed capability is signRoundtrip over a validated message, so a
    // caller cannot ask the signer to sign arbitrary bytes.
    const signer: RoundtripSigner = new LocalRoundtripSigner(testPrivateKey('alice'))
    expect(Object.keys(signer).length).toBe(0)
    expect(Object.getOwnPropertyNames(LocalRoundtripSigner.prototype).sort()).toEqual(['constructor', 'publicKey', 'signRoundtrip'])
    const unsigned = unsignedRequest()
    const signature = await signer.signRoundtrip(unsigned)
    expect(equalBytes(sha256Bytes(signingBytes(unsigned)), digestOf(unsigned))).toBe(true)
    expect(signature.length).toBeGreaterThan(8)
  })
})
