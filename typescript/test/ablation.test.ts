import { describe, expect, it } from 'vitest'
import {
  LocalRoundtripSigner,
  MemoryReplayGuard,
  RoundtripCore,
  RoundtripError,
  canonicalize,
  digestOf,
  encodeBase64Url,
  encodeEnvelopeBytes,
  equalBytes,
  parseJsonBytes,
  parseJsonText,
  parseRequest,
  parseResponse,
  publicKeyToString,
  requestIdOf,
  sha256Bytes,
  signDigest,
  unsignedToWire,
  verifyDigest,
  type HandlerOutcome,
  type JsonObject,
  type JsonValue,
  type PreparedRequest,
  type ReplayGuard,
  type RoundtripHandler,
  type UnsignedResponse
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
  unsignedRequest
} from './fixtures.js'

/**
 * Stage 6: ablation.
 *
 * Every experiment removes exactly one mechanism, keeps everything else
 * identical, and states which requirement fails. An ablation variant exists only
 * in this file: the library exposes no "skip verification" switch, so nothing
 * here can be turned on in a deployment.
 *
 * Where the library has an injection point, the experiment drives the real code
 * path with a substituted dependency, as in experiment 7 with the replay guard.
 * Where it has none, because the check is internal to the core, the experiment
 * uses a reduced pipeline built from the same exported primitives, and the
 * control suite first proves that this reduced pipeline with nothing removed
 * behaves exactly like the shipped core.
 */

const utf8 = new TextEncoder()
const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes)

async function codeOf (body: () => Promise<unknown>): Promise<string> {
  try {
    await body()
    return ''
  } catch (error) {
    return error instanceof RoundtripError ? error.code : 'NOT_A_ROUNDTRIP_ERROR'
  }
}

/** The one step each experiment is allowed to delete. */
interface Removed {
  /** Do not verify the request signature. */
  requestSignature?: boolean
  /** Do not check that `to` is this node. */
  recipient?: boolean
  /** Do not verify the response signature. */
  responseSignature?: boolean
  /** Do not check that `reply_to` is the waiting request id. */
  responseReplyTo?: boolean
}

interface Node {
  publicKey: Uint8Array
  replay: ReplayGuard
  handler: RoundtripHandler
  now: () => number
  skew: number
  signer: LocalRoundtripSigner
}

function nodeFor (name: string, handler: RoundtripHandler, options: { replay?: ReplayGuard, now?: () => number } = {}): Node {
  const now = options.now ?? ((): number => TEST_NOW)
  return {
    publicKey: testPublicKey(name),
    replay: options.replay ?? new MemoryReplayGuard(now),
    handler,
    now,
    skew: 5,
    signer: new LocalRoundtripSigner(testPrivateKey(name))
  }
}

/**
 * The receiving pipeline of `RoundtripCore.processRequest`, written out so that a
 * single step can be deleted. The order is the shipped order: expiry,
 * recipient, signature, atomic claim, then the application.
 */
async function reducedHandle (owner: Node, requestBytes: Uint8Array, removed: Removed = {}): Promise<Uint8Array> {
  const envelope = parseRequest(parseJsonBytes(requestBytes))
  const unsigned = envelope.unsigned
  if (unsigned.expires + owner.skew < owner.now()) {
    throw new RoundtripError('ERR_EXPIRED', 'request has expired')
  }
  if (removed.recipient !== true && equalBytes(unsigned.to, owner.publicKey) !== true) {
    throw new RoundtripError('ERR_RECIPIENT', 'request is not addressed to this identity')
  }
  if (removed.requestSignature !== true) {
    verifyDigest(unsigned.from, digestOf(unsigned), envelope.signature)
  }
  const requestId = requestIdOf(unsigned)
  const claimed = await owner.replay.claim({ id: requestId, retainUntil: unsigned.expires + owner.skew })
  const outcome: HandlerOutcome = claimed !== true
    ? { ok: false, error: { code: 'REQUEST_ALREADY_SEEN', message: 'this request has already been received' } }
    : await owner.handler({ callerPublicKey: unsigned.from, requestId, body: unsigned.body, envelope })
  if (claimed === true) await owner.replay.complete(requestId)
  return await respond(owner, unsigned.from, digestOf(unsigned), outcome)
}

/** The same pipeline with the expiry comparison deleted, and nothing else. */
async function reducedHandleWithoutExpiry (owner: Node, requestBytes: Uint8Array): Promise<Uint8Array> {
  const envelope = parseRequest(parseJsonBytes(requestBytes))
  const unsigned = envelope.unsigned
  if (equalBytes(unsigned.to, owner.publicKey) !== true) {
    throw new RoundtripError('ERR_RECIPIENT', 'request is not addressed to this identity')
  }
  verifyDigest(unsigned.from, digestOf(unsigned), envelope.signature)
  const requestId = requestIdOf(unsigned)
  const claimed = await owner.replay.claim({ id: requestId, retainUntil: unsigned.expires + owner.skew })
  const outcome: HandlerOutcome = claimed !== true
    ? { ok: false, error: { code: 'REQUEST_ALREADY_SEEN', message: 'this request has already been received' } }
    : await owner.handler({ callerPublicKey: unsigned.from, requestId, body: unsigned.body, envelope })
  if (claimed === true) await owner.replay.complete(requestId)
  return await respond(owner, unsigned.from, digestOf(unsigned), outcome)
}

async function respond (owner: Node, to: Uint8Array, replyTo: Uint8Array, outcome: HandlerOutcome): Promise<Uint8Array> {
  const body: JsonObject = outcome.ok
    ? { ok: true, result: outcome.result }
    : { ok: false, error: { code: outcome.error.code, message: outcome.error.message } }
  const unsigned: UnsignedResponse = { kind: 'response', from: owner.publicKey, to, replyTo, body }
  return encodeEnvelopeBytes(unsigned, await owner.signer.signRoundtrip(unsigned))
}

/** The client half of `RoundtripCore.verifyResponse`, with steps deletable. */
function reducedVerify (owner: Node, prepared: PreparedRequest, responseBytes: Uint8Array, removed: Removed = {}): JsonValue {
  const envelope = parseResponse(parseJsonText(text(responseBytes)))
  const unsigned = envelope.unsigned
  if (equalBytes(unsigned.to, owner.publicKey) !== true) {
    throw new RoundtripError('ERR_RESPONSE_TO', 'response is not addressed to this identity')
  }
  if (equalBytes(unsigned.from, prepared.unsigned.to) !== true) {
    throw new RoundtripError('ERR_RESPONSE_FROM', 'response did not come from the requested peer')
  }
  if (removed.responseReplyTo !== true && equalBytes(unsigned.replyTo, digestOf(prepared.unsigned)) !== true) {
    throw new RoundtripError('ERR_RESPONSE_REPLY_TO', 'response does not belong to the waiting request')
  }
  if (removed.responseSignature !== true) {
    verifyDigest(unsigned.from, digestOf(unsigned), envelope.signature)
  }
  return unsigned.body
}

const acceptAll: RoundtripHandler = ({ callerPublicKey }) => ({ ok: true, result: { caller: publicKeyToString(callerPublicKey) } })

/** Counts executions, so a test can tell "refused" from "ran anyway". */
function counting (result: JsonValue = { moved: 1 }): { handler: RoundtripHandler, runs: number[] } {
  const runs: number[] = []
  return {
    runs,
    handler: (): HandlerOutcome => {
      runs.push(runs.length)
      return { ok: true, result }
    }
  }
}

/** Reads the error code out of a signed response, or undefined on success. */
function failureOf (responseBytes: Uint8Array): string | undefined {
  const body = parseResponse(parseJsonText(text(responseBytes))).unsigned.body as { ok: boolean, error?: { code: string } }
  return body.ok === true ? undefined : body.error?.code
}

describe('ablation control: the reduced pipeline is the shipped pipeline', () => {
  it('gives the same verdict as RoundtripCore for every input class', async () => {
    const battery: Array<[string, Uint8Array]> = [
      ['valid', signedRequestBytes()],
      ['wrong recipient', signedRequestBytes({ to: testPublicKey('carol') })],
      ['expired', signedRequestBytes({ expires: TEST_NOW - 600 })],
      ['signature from another key', signedBytes(unsignedRequest(), 'mallory')],
      ['malformed', utf8.encode('{"from":')],
      ['unknown field', utf8.encode(text(signedRequestBytes()).replace('"body":', '"version":1,"body":'))],
      ['duplicate key', utf8.encode('{"from":"a","from":"b"}')]
    ]
    const verdicts: Array<[string, string]> = []
    for (const [label, bytes] of battery) {
      const real = new RoundtripCore({ signer: testSigner('bob'), nowSeconds: () => TEST_NOW, handler: acceptAll })
      const realCode = await codeOf(async () => await real.handle(bytes))
      const reducedCode = await codeOf(async () => await reducedHandle(nodeFor('bob', acceptAll), bytes))
      verdicts.push([label, realCode])
      expect(reducedCode, label).toBe(realCode)
    }
    // The control is only meaningful if the battery still refuses things and
    // still accepts the one honest request.
    expect(verdicts).toEqual([
      ['valid', ''],
      ['wrong recipient', 'ERR_RECIPIENT'],
      ['expired', 'ERR_EXPIRED'],
      ['signature from another key', 'ERR_SIGNATURE'],
      ['malformed', 'ERR_JSON_SYNTAX'],
      ['unknown field', 'ERR_ENVELOPE_FIELD_UNKNOWN'],
      ['duplicate key', 'ERR_JSON_DUPLICATE_KEY']
    ])
  })

  it('signs the same response for a valid request', async () => {
    const request = signedRequestBytes()
    const real = new RoundtripCore({ signer: testSigner('bob'), nowSeconds: () => TEST_NOW, handler: acceptAll })
    const reduced = nodeFor('bob', acceptAll)
    const realResponse = parseResponse(parseJsonText(text(await real.handle(request))))
    const reducedResponse = parseResponse(parseJsonText(text(await reducedHandle(reduced, request))))
    // Same request id, same recipient, same result shape.
    expect(encodeBase64Url(realResponse.unsigned.replyTo)).toBe(encodeBase64Url(reducedResponse.unsigned.replyTo))
    expect(realResponse.unsigned.body).toEqual(reducedResponse.unsigned.body)
    expect(() => { verifyDigest(realResponse.unsigned.from, digestOf(realResponse.unsigned), realResponse.signature) }).not.toThrow()
  })
})

describe('experiment 1: delete request signature verification', () => {
  it('lets a forged from reach the handler', async () => {
    // Mallory sends a request that claims to be alice. She cannot sign it, so
    // the signature is over her own key.
    const forged = signedBytes(unsignedRequest({ from: testPublicKey('alice') }), 'mallory')

    const honest = counting()
    const baseline = new RoundtripCore({ signer: testSigner('bob'), nowSeconds: () => TEST_NOW, handler: honest.handler })
    expect(await codeOf(async () => await baseline.handle(forged))).toBe('ERR_SIGNATURE')
    expect(honest.runs).toHaveLength(0)

    // Ablated: only the verification line is gone.
    const ablated = counting()
    const response = await reducedHandle(nodeFor('bob', ablated.handler), forged, { requestSignature: true })
    expect(ablated.runs).toHaveLength(1)
    // The business ran, and it ran as alice.
    expect(parseResponse(parseJsonText(text(response))).unsigned.to).toEqual(testPublicKey('alice'))
  })
})

describe('experiment 2: delete the recipient check', () => {
  it('executes a request that was addressed to somebody else', async () => {
    // Alice legitimately signs a request for carol, and the wrong node receives
    // it. Nothing was forged: any relay that can read the bytes can hand them
    // to the wrong node.
    const misdelivered = signedRequestBytes({ to: testPublicKey('carol') })

    const honest = counting()
    const baseline = new RoundtripCore({ signer: testSigner('bob'), nowSeconds: () => TEST_NOW, handler: honest.handler })
    expect(await codeOf(async () => await baseline.handle(misdelivered))).toBe('ERR_RECIPIENT')
    expect(honest.runs).toHaveLength(0)

    // Ablated: the message is still correctly signed, and the recipient check is
    // the only thing left that could have refused it.
    const ablated = counting()
    await reducedHandle(nodeFor('bob', ablated.handler), misdelivered, { recipient: true })
    expect(ablated.runs).toHaveLength(1)
  })

  it('keeps signature coverage of to, so a re-targeted request still fails', async () => {
    const wire = parseJsonText(text(signedRequestBytes({ to: testPublicKey('carol') }))) as Record<string, string>
    const retargeted = utf8.encode(JSON.stringify({ ...wire, to: publicKeyToString(testPublicKey('mallory')) }))
    const ablated = counting()
    // Even with the recipient check gone, a changed recipient breaks the
    // signature, because to is part of the signed bytes.
    expect(await codeOf(async () => await reducedHandle(nodeFor('mallory', ablated.handler), retargeted, { recipient: true }))).toBe('ERR_SIGNATURE')
    expect(ablated.runs).toHaveLength(0)
  })
})

describe('experiment 3: delete response signature verification', () => {
  it('lets a forged success response complete the call', async () => {
    const client = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(3) })
    const prepared = await client.buildRequest(testPublicKey('bob'), { op: 'transfer', args: { amount: '1.00000000' } })
    // Mallory invents a result, claims to be bob, and signs with her own key.
    const unsigned: UnsignedResponse = {
      kind: 'response',
      from: testPublicKey('bob'),
      to: testPublicKey('alice'),
      replyTo: digestOf(prepared.unsigned),
      body: { ok: true, result: { sent: '1000.00000000' } }
    }
    const forged = encodeEnvelopeBytes(unsigned, await testSigner('mallory').signRoundtrip(unsigned))
    const clientNode = nodeFor('alice', acceptAll)

    // Baseline: refused, because the signature is not bob's.
    expect(() => { reducedVerify(clientNode, prepared, forged) }).toThrow(RoundtripError)
    // Ablated: the call completes with mallory's invented result.
    expect(reducedVerify(clientNode, prepared, forged, { responseSignature: true }))
      .toEqual({ ok: true, result: { sent: '1000.00000000' } })
  })
})

describe('experiment 4: delete reply_to verification', () => {
  it('lets an older genuine response complete a new call', async () => {
    const server = new RoundtripCore({ signer: testSigner('bob'), nowSeconds: () => TEST_NOW, handler: (): HandlerOutcome => ({ ok: true, result: { account: 'A' } }) })
    const client = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(3) })
    const clientNode = nodeFor('alice', acceptAll)

    // An earlier call, answered honestly, with the answer kept.
    const earlier = await client.buildRequest(testPublicKey('bob'), { op: 'get_balance', args: { account: 'A' } })
    const saved = await server.handle(earlier.bytes)
    // A later call, for a different account, is waiting for its own answer.
    const later = await client.buildRequest(testPublicKey('bob'), { op: 'get_balance', args: { account: 'B' } })
    expect(earlier.requestId).not.toBe(later.requestId)

    // Baseline: the stale answer is refused.
    expect(await codeOf(async () => { reducedVerify(clientNode, later, saved) })).toBe('ERR_RESPONSE_REPLY_TO')
    // Ablated: the old answer completes the new call, and the caller believes it
    // asked about B. This is a genuine signed response, not a random forgery.
    expect(reducedVerify(clientNode, later, saved, { responseReplyTo: true }))
      .toEqual({ ok: true, result: { account: 'A' } })
  })
})

describe('experiment 5: delete the nonce', () => {
  it('makes two new calls look like one replay', async () => {
    // The same nonce on two separate calls is exactly what removing the nonce
    // leaves behind, and it is not something an attacker needs to arrange.
    const nonce = new Uint8Array(32).fill(5)
    const first = signedRequestBytes({ nonce })
    const second = signedRequestBytes({ nonce })
    const idOf = (bytes: Uint8Array): string => requestIdOf(parseRequest(parseJsonText(text(bytes))).unsigned)
    expect(idOf(first)).toBe(idOf(second))

    // Baseline: with a fresh nonce per call, two identical calls both run.
    const baselineRuns = counting()
    const guarded = new RoundtripCore({ signer: testSigner('bob'), nowSeconds: () => TEST_NOW, handler: baselineRuns.handler })
    const caller = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(3) })
    for (let index = 0; index < 2; index++) {
      await guarded.handle((await caller.buildRequest(testPublicKey('bob'), { op: 'get_balance', args: { asset: 'BSV' } })).bytes)
    }
    expect(baselineRuns.runs).toHaveLength(2)

    // Ablated: the second, perfectly legitimate call is refused as a duplicate.
    const ablatedRuns = counting()
    const core = new RoundtripCore({ signer: testSigner('bob'), nowSeconds: () => TEST_NOW, handler: ablatedRuns.handler })
    await core.handle(first)
    expect(failureOf(await core.handle(second))).toBe('REQUEST_ALREADY_SEEN')
    // One execution served two different callers, and the second one gets an
    // error instead of its own result.
    expect(ablatedRuns.runs).toHaveLength(1)
  })
})

describe('experiment 6: delete expires', () => {
  it('lets an old request execute after its window has passed', async () => {
    // A request that was valid an hour ago, replayed now.
    const old = signedRequestBytes({ expires: TEST_NOW - 3_600 })

    const honest = counting()
    const baseline = new RoundtripCore({ signer: testSigner('bob'), nowSeconds: () => TEST_NOW, handler: honest.handler })
    expect(await codeOf(async () => await baseline.handle(old))).toBe('ERR_EXPIRED')
    expect(honest.runs).toHaveLength(0)

    // Ablated: one comparison is gone. The request is otherwise untouched, still
    // correctly signed and still addressed to this node.
    const ablated = counting()
    await reducedHandleWithoutExpiry(nodeFor('bob', ablated.handler), old)
    expect(ablated.runs).toHaveLength(1)
  })

  it('shows that record retention is derived from expires', async () => {
    // Without an expiry there is no deadline to keep a dedup record until, so a
    // bounded store has nothing to bound itself with.
    let now = TEST_NOW
    const guard = new MemoryReplayGuard(() => now)
    expect(await guard.claim({ id: 'x', retainUntil: TEST_EXPIRES + 5 })).toBe(true)
    now = TEST_EXPIRES + 6
    expect(guard.stateOf('x')).toBe('absent')
  })
})

describe('experiment 7: delete the atomic dedup claim', () => {
  it('runs the business twice for concurrent deliveries of one request', async () => {
    // A guard that is not atomic: every concurrent delivery wins the claim. This
    // is the real core and the real request path; only the guard is replaced.
    const naive: ReplayGuard = {
      capabilities: { persistent: false, shared: false, resultCache: false },
      claim: async (): Promise<boolean> => await Promise.resolve(true),
      complete: async (): Promise<void> => await Promise.resolve()
    }
    const request = signedRequestBytes()

    // Baseline: the shipped guard runs the business exactly once.
    const baselineRuns = counting()
    const guarded = new RoundtripCore({ signer: testSigner('bob'), nowSeconds: () => TEST_NOW, handler: baselineRuns.handler })
    await Promise.all(Array.from({ length: 8 }, async () => await guarded.handle(request)))
    expect(baselineRuns.runs).toHaveLength(1)

    // Ablated: eight deliveries, eight executions.
    const ablatedRuns = counting()
    const core = new RoundtripCore({ signer: testSigner('bob'), nowSeconds: () => TEST_NOW, replay: naive, handler: ablatedRuns.handler })
    await Promise.all(Array.from({ length: 8 }, async () => await core.handle(request)))
    expect(ablatedRuns.runs).toHaveLength(8)
  })
})

describe('experiment 8: delete canonical encoding', () => {
  it('makes two spellings of one message produce different signed bytes', () => {
    const unsigned = unsignedRequest({ body: { op: 'transfer', args: { amount: '1.00000000' } } })
    const wire = unsignedToWire(unsigned)
    const firstSpelling = parseJsonText(JSON.stringify({ to: wire.to, from: wire.from, nonce: wire.nonce, expires: wire.expires, body: wire.body }))
    const secondSpelling = parseJsonText(JSON.stringify({ body: wire.body, expires: wire.expires, nonce: wire.nonce, from: wire.from, to: wire.to }))

    // Baseline: JCS sorts the keys, so both spellings canonicalise identically
    // and produce one request id.
    expect(equalBytes(canonicalize(firstSpelling), canonicalize(secondSpelling))).toBe(true)
    expect(requestIdOf(unsigned)).toBe(requestIdOf(unsigned))

    // Ablated: a writer that keeps the insertion order instead of sorting.
    const canonicalBytes = utf8.encode(`roundtrip/v1\n${text(canonicalize(firstSpelling))}`)
    const ablatedBytes = utf8.encode(`roundtrip/v1\n${JSON.stringify(firstSpelling)}`)
    expect(equalBytes(ablatedBytes, canonicalBytes)).toBe(false)
    // Two senders, one message, two digests: a receiver that canonicalises can
    // never satisfy both.
    expect(equalBytes(sha256Bytes(ablatedBytes), sha256Bytes(canonicalBytes))).toBe(false)
  })

  it('shows a signature over non canonical bytes does not verify', () => {
    const unsigned = unsignedRequest()
    const wire = unsignedToWire(unsigned)
    const nonCanonical = JSON.stringify({ body: wire.body, to: wire.to, from: wire.from, nonce: wire.nonce, expires: wire.expires })
    const digest = sha256Bytes(utf8.encode(`roundtrip/v1\n${nonCanonical}`))
    const signature = signDigest(testPrivateKey('alice'), digest)
    // The key and the message are honest, but the receiver recomputes the
    // canonical bytes, so this signature is not valid for it.
    expect(() => { verifyDigest(unsigned.from, digestOf(unsigned), signature) }).toThrow(RoundtripError)
  })
})

describe('experiment 9: keep no id, type or version field', () => {
  it('needs none of them for any of the four requirements', async () => {
    const client = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(3) })
    const seen: string[] = []
    const server = new RoundtripCore({
      signer: testSigner('bob'),
      nowSeconds: () => TEST_NOW,
      handler: ({ callerPublicKey }): HandlerOutcome => {
        seen.push(publicKeyToString(callerPublicKey))
        return { ok: true, result: { ok: 1 } }
      }
    })
    const prepared = await client.buildRequest(testPublicKey('bob'), { op: 'ping' })
    const responseBytes = await server.handle(prepared.bytes)
    const response = parseResponse(parseJsonText(text(responseBytes)))

    // Nothing on the wire names a kind, a version or an independent id.
    const requestFields = Object.keys(JSON.parse(text(prepared.bytes)) as Record<string, unknown>).sort()
    const responseFields = Object.keys(JSON.parse(text(responseBytes)) as Record<string, unknown>).sort()
    expect(requestFields).toEqual(['body', 'expires', 'from', 'nonce', 'sig', 'to'])
    expect(responseFields).toEqual(['body', 'from', 'reply_to', 'sig', 'to'])
    for (const field of ['id', 'type', 'version', 'alg', 'kid']) {
      expect(requestFields.includes(field), field).toBe(false)
      expect(responseFields.includes(field), field).toBe(false)
    }

    // 1. the receiver learns who sent it, from the signature alone
    expect(seen).toEqual([publicKeyToString(client.publicKey())])
    expect(equalBytes(response.unsigned.from, testPublicKey('bob'))).toBe(true)
    // 2. the sender names the recipient, and the name is signed
    expect(equalBytes(response.unsigned.to, testPublicKey('alice'))).toBe(true)
    // 3. the correlation is the request digest, with no separate id
    expect(equalBytes(response.unsigned.replyTo, digestOf(prepared.unsigned))).toBe(true)
    // 4. two identical calls stay distinguishable through the nonce alone
    const other = await client.buildRequest(testPublicKey('bob'), { op: 'ping' })
    expect(other.requestId).not.toBe(prepared.requestId)
  })
})

describe('experiment 10: delete the identity handshake', () => {
  it('verifies both identities on the very first message', async () => {
    // Fresh instances, no prior exchange, no shared state, nothing negotiated.
    const client = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(3) })
    const seen: string[] = []
    const server = new RoundtripCore({
      signer: testSigner('bob'),
      nowSeconds: () => TEST_NOW,
      handler: ({ callerPublicKey }): HandlerOutcome => {
        seen.push(publicKeyToString(callerPublicKey))
        return { ok: true, result: { from: publicKeyToString(client.publicKey()) } }
      }
    })
    let exchanges = 0
    const outcome = await client.call({
      to: server.publicKey(),
      body: { op: 'ping' },
      exchange: async (requestBytes) => {
        exchanges++
        return await server.handle(requestBytes)
      }
    })
    // One request, one response, and both identities are established by them.
    expect(exchanges).toBe(1)
    expect(seen).toEqual([publicKeyToString(client.publicKey())])
    expect(outcome.ok === true ? outcome.result : null).toEqual({ from: publicKeyToString(client.publicKey()) })
  })
})

describe('experiment 11: delete the global waiting table', () => {
  it('keeps concurrent calls correct with one exchange per call', async () => {
    const server = new RoundtripCore({
      signer: testSigner('bob'),
      nowSeconds: () => TEST_NOW,
      // Each answer echoes the caller's argument, so a mixed up response would
      // be visible instead of invisible.
      handler: ({ body }): HandlerOutcome => ({ ok: true, result: { echo: (body as { args: { n: number } }).args.n } })
    })
    const client = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(3) })

    // A transport that answers in reverse order, so nothing can depend on order.
    const inFlight: Array<{ requestBytes: Uint8Array, resolve: (bytes: Uint8Array) => void }> = []
    const exchange = async (requestBytes: Uint8Array): Promise<Uint8Array> =>
      await new Promise<Uint8Array>((resolve) => {
        inFlight.push({ requestBytes, resolve })
      })
    const calls = Array.from({ length: 5 }, async (_value, n) =>
      await client.call({ to: testPublicKey('bob'), body: { op: 'get', args: { n } }, exchange }))
    // Let every call reach the transport first.
    while (inFlight.length < 5) await new Promise((resolve) => setTimeout(resolve, 1))
    // Answer them back to front.
    while (inFlight.length > 0) {
      const next = inFlight.pop()
      if (next == null) break
      next.resolve(await server.handle(next.requestBytes))
    }
    const outcomes = await Promise.all(calls)
    // Every call received the answer to its own question.
    expect(outcomes.map((outcome) => (outcome.ok === true ? outcome.result : null)))
      .toEqual([{ echo: 0 }, { echo: 1 }, { echo: 2 }, { echo: 3 }, { echo: 4 }])
  })
})

describe('experiment 12: delete the second HTTP mode', () => {
  it('meets every first version HTTP requirement with only the full shell', async () => {
    const server = new RoundtripCore({ signer: testSigner('bob'), nowSeconds: () => TEST_NOW, handler: acceptAll })
    const client = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(3) })

    // A signed request in, a signed response out, over one POST. The entry path
    // and the HTTP method decide nothing: body.op is the only business input.
    const prepared = await client.buildRequest(testPublicKey('bob'), { op: 'get_balance' })
    const responseBytes = await server.handle(prepared.bytes)
    expect(client.verifyResponse(responseBytes, prepared).ok).toBe(true)

    // The request id is still computed, because the server needs it for dedup.
    expect(encodeBase64Url(digestOf(prepared.unsigned))).toBe(prepared.requestId)

    // Nonce and expires are still in the request, so a new call stays distinct
    // and an old one stops being accepted.
    const fields = Object.keys(JSON.parse(text(prepared.bytes)) as Record<string, unknown>).sort()
    expect(fields).toEqual(['body', 'expires', 'from', 'nonce', 'sig', 'to'])
    expect(await codeOf(async () => await server.handle(signedRequestBytes({ expires: TEST_NOW - 600 })))).toBe('ERR_EXPIRED')

    // And the optional trimmed shape stays refused by the base receiver, so the
    // two modes cannot be confused for one another.
    const trimmed = {
      from: publicKeyToString(testPublicKey('bob')),
      to: publicKeyToString(client.publicKey()),
      body: { ok: true, result: 1 },
      sig: encodeBase64Url(new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]))
    }
    expect(() => { parseResponse(JSON.parse(JSON.stringify(trimmed)) as never) }).toThrow(RoundtripError)
  })

  it('still refuses a duplicate and still answers a fresh call', async () => {
    const runs = counting()
    const server = new RoundtripCore({ signer: testSigner('bob'), nowSeconds: () => TEST_NOW, handler: runs.handler })
    const caller = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(3) })
    const prepared = await caller.buildRequest(testPublicKey('bob'), { op: 'get_balance' })
    expect(failureOf(await server.handle(prepared.bytes))).toBeUndefined()
    // The same bytes again are the same request, so the business does not run.
    expect(failureOf(await server.handle(prepared.bytes))).toBe('REQUEST_ALREADY_SEEN')
    // A new call has a new nonce, so it runs.
    const fresh = await caller.buildRequest(testPublicKey('bob'), { op: 'get_balance' })
    expect(failureOf(await server.handle(fresh.bytes))).toBeUndefined()
    expect(runs.runs).toHaveLength(2)
  })
})
