import { describe, expect, it } from 'vitest'
import {
  MemoryReplayGuard,
  RoundtripCore,
  encodeBase64Url,
  isRoundtripError,
  parseJsonText,
  parseRequest,
  parseResponse,
  requestIdOf,
  type CallOutcome,
  type Exchange,
  type HandlerOutcome,
  type JsonValue,
  type ReplayClaim,
  type ReplayGuard
} from '../src/index.js'
import {
  TEST_EXPIRES,
  TEST_NOW,
  fixedRandom,
  signedRequestBytes,
  testPublicKey,
  testSigner,
  unsignedRequest
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

interface Received {
  from: Uint8Array
  requestId: string
  body: JsonValue
}

/** A receiving core with a fixed clock and a recorded handler. */
function receiver (options: { name?: string, handler?: (context: { callerPublicKey: Uint8Array, requestId: string, body: JsonValue }) => HandlerOutcome | Promise<HandlerOutcome>, replay?: ReplayGuard, clockSkewSeconds?: number } = {}): { core: RoundtripCore, calls: Received[] } {
  const calls: Received[] = []
  const core = new RoundtripCore({
    signer: testSigner(options.name ?? 'bob'),
    nowSeconds: () => TEST_NOW,
    replay: options.replay,
    clockSkewSeconds: options.clockSkewSeconds,
    handler: async (context) => {
      calls.push({ from: new Uint8Array(context.callerPublicKey), requestId: context.requestId, body: context.body })
      return options.handler == null ? { ok: true, result: { accepted: true } } : await options.handler(context)
    }
  })
  return { core, calls }
}

/** Reads the business outcome out of signed response bytes. */
function outcomeOf (responseBytes: Uint8Array): CallOutcome {
  const body = parseResponse(parseJsonText(text(responseBytes))).unsigned.body
  if ((body as { ok: boolean }).ok === true) {
    return { ok: true, result: (body as { result: JsonValue }).result, requestId: '' }
  }
  const error = (body as { error: { code: string, message: string } }).error
  return { ok: false, error: { code: error.code, message: error.message }, requestId: '' }
}

describe('stage 3: the handler is the application boundary', () => {
  it('receives the verified caller, the request id and the body', async () => {
    const { core, calls } = receiver()
    const prepared = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(4) })
    const request = await prepared.buildRequest(testPublicKey('bob'), { op: 'get_balance', args: { asset: 'BSV' } })
    const response = await core.handle(request.bytes)
    expect(calls).toHaveLength(1)
    expect(calls[0].requestId).toBe(request.requestId)
    expect(encodeBase64Url(calls[0].from)).toBe(encodeBase64Url(testPublicKey('alice')))
    expect(calls[0].body).toEqual({ op: 'get_balance', args: { asset: 'BSV' } })
    // The result comes back inside a signed shell, never as a bare value.
    expect(outcomeOf(response).ok).toBe(true)
  })

  it('turns a thrown handler into a signed business error, without leaking internals', async () => {
    const { core } = receiver({
      handler: (): HandlerOutcome => {
        throw new Error('database password is hunter2')
      }
    })
    const outcome = outcomeOf(await core.handle(signedRequestBytes()))
    expect(outcome.ok).toBe(false)
    if (outcome.ok === false) {
      expect(outcome.error.code).toBe('HANDLER_FAILED')
      expect(outcome.error.message).toBe('handler failed')
      expect(text(await core.handle(signedRequestBytes({ nonce: new Uint8Array(32).fill(2) })))).not.toContain('hunter2')
    }
  })

  it('passes a business error through unchanged', async () => {
    const { core } = receiver({
      handler: (): HandlerOutcome => ({ ok: false, error: { code: 'UNKNOWN_ASSET', message: '没有这个资产' } })
    })
    const outcome = outcomeOf(await core.handle(signedRequestBytes()))
    expect(outcome.ok === false ? outcome.error : null).toEqual({ code: 'UNKNOWN_ASSET', message: '没有这个资产' })
  })

  it('refuses to handle anything without a handler', async () => {
    const core = new RoundtripCore({ signer: testSigner('bob'), nowSeconds: () => TEST_NOW })
    expect(await codeOf(async () => await core.handle(signedRequestBytes()))).toBe('ERR_NO_HANDLER')
  })
})

describe('stage 3: the replay claim is atomic and one way', () => {
  it('runs the business once for concurrent deliveries of the same request', async () => {
    let release: () => void = (): void => undefined
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    const { core, calls } = receiver({
      // Hold every request inside the business so all of them are in flight at
      // the same time. A non atomic claim would let several through here.
      handler: async (): Promise<HandlerOutcome> => {
        await gate
        return { ok: true, result: { moved: 1 } }
      }
    })
    const bytes = signedRequestBytes()
    const inFlight = Array.from({ length: 8 }, async () => await core.handle(bytes))
    // Give every request time to reach the claim before any of them finishes.
    await new Promise((resolve) => setTimeout(resolve, 5))
    release()
    const responses = await Promise.all(inFlight)
    expect(calls).toHaveLength(1)
    const outcomes = responses.map(outcomeOf)
    expect(outcomes.filter((outcome) => outcome.ok === true)).toHaveLength(1)
    // The other seven are refused with a signed duplicate error, not dropped.
    for (const outcome of outcomes.filter((entry) => entry.ok === false)) {
      expect(outcome.ok === false ? outcome.error.code : '').toBe('REQUEST_ALREADY_SEEN')
    }
  })

  it('refuses a second delivery after the first one finished', async () => {
    const { core, calls } = receiver()
    const bytes = signedRequestBytes()
    expect(outcomeOf(await core.handle(bytes)).ok).toBe(true)
    const second = outcomeOf(await core.handle(bytes))
    expect(second.ok === false ? second.error.code : '').toBe('REQUEST_ALREADY_SEEN')
    expect(calls).toHaveLength(1)
  })

  it('does not release the claim when the execution was cancelled, so a retry cannot double spend', async () => {
    let entered = 0
    const { core, calls } = receiver({
      handler: async (): Promise<HandlerOutcome> => {
        entered++
        throw new Error('side effect half done')
      }
    })
    const bytes = signedRequestBytes()
    expect(outcomeOf(await core.handle(bytes)).ok).toBe(false)
    // A retry of the same request must not run the business again, even though
    // the first attempt failed after it started.
    expect(outcomeOf(await core.handle(bytes)).ok === false).toBe(true)
    expect(entered).toBe(1)
    expect(calls).toHaveLength(1)
  })

  it('keeps different requests independent', async () => {
    const { core, calls } = receiver()
    await Promise.all([
      core.handle(signedRequestBytes()),
      core.handle(signedRequestBytes({ nonce: new Uint8Array(32).fill(1) })),
      core.handle(signedRequestBytes({ nonce: new Uint8Array(32).fill(2) })),
      core.handle(signedRequestBytes({ body: { op: 'ping' } }))
    ])
    expect(calls).toHaveLength(4)
  })

  it('exposes what the in memory guard can and cannot promise', async () => {
    const guard = new MemoryReplayGuard(() => TEST_NOW)
    expect(guard.capabilities).toEqual({ persistent: false, shared: false, resultCache: false })
    const claim: ReplayClaim = { id: 'x', retainUntil: TEST_NOW + 60 }
    expect(await guard.claim(claim)).toBe(true)
    expect(await guard.claim(claim)).toBe(false)
    expect(guard.stateOf('x')).toBe('claimed')
    await guard.complete('x')
    expect(guard.stateOf('x')).toBe('completed')
    // Even a completed record is not a result cache: a duplicate cannot be
    // answered with the old result, only refused.
    expect(guard.capabilities.resultCache).toBe(false)
  })

  it('keeps a record until the request can no longer pass any expiry check', async () => {
    let now = TEST_NOW
    const guard = new MemoryReplayGuard(() => now)
    const id = 'request-1'
    expect(await guard.claim({ id, retainUntil: TEST_EXPIRES + 5 })).toBe(true)
    // Well past expiry, but still inside the retained window.
    now = TEST_EXPIRES + 4
    expect(await guard.claim({ id, retainUntil: TEST_EXPIRES + 5 })).toBe(false)
    // One second later the record is gone, because no receiver would accept the
    // request any more.
    now = TEST_EXPIRES + 6
    expect(guard.stateOf(id)).toBe('absent')
  })

  it('shows that the in memory guard does not survive a restart, and says so', async () => {
    const guard = new MemoryReplayGuard(() => TEST_NOW)
    const { core, calls } = receiver({ replay: guard })
    const bytes = signedRequestBytes()
    await core.handle(bytes)
    expect(calls).toHaveLength(1)
    // Simulates a process restart: everything in memory is gone.
    guard.clear()
    await core.handle(bytes)
    expect(calls).toHaveLength(2)
    // This is the documented limitation, not a passing claim: production has to
    // supply a persistent, shared store.
    expect(guard.capabilities.persistent).toBe(false)
    expect(guard.capabilities.shared).toBe(false)
  })

  it('shares one claim between two instances when the application supplies a shared guard', async () => {
    const shared = new MemoryReplayGuard(() => TEST_NOW)
    const first = receiver({ replay: shared })
    const second = receiver({ replay: shared })
    const bytes = signedRequestBytes()
    const [a, b] = await Promise.all([first.core.handle(bytes), second.core.handle(bytes)])
    expect(first.calls.length + second.calls.length).toBe(1)
    expect(outcomeOf(a).ok !== outcomeOf(b).ok).toBe(true)
  })
})

describe('stage 3: a call has a deadline and can be cancelled', () => {
  /** A transport that accepts the request and then never answers. */
  const silent: Exchange = async (_requestBytes, signal): Promise<Uint8Array> => await new Promise<Uint8Array>((resolve, reject) => {
    signal.addEventListener('abort', () => reject(signal.reason as Error), { once: true })
  })

  it('stops waiting locally when the deadline passes, and does not retry', async () => {
    const client = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, callTimeoutMs: 20 })
    let attempts = 0
    const counting: Exchange = async (requestBytes, signal) => {
      attempts++
      return await silent(requestBytes, signal)
    }
    expect(await codeOf(async () => await client.call({ to: testPublicKey('bob'), body: { op: 'ping' }, exchange: counting }))).toBe('ERR_CALL_TIMEOUT')
    // A timeout says nothing about whether the business ran, so the protocol
    // must not silently send the request again.
    expect(attempts).toBe(1)
  })

  it('passes the abort signal to the transport and stops the local wait', async () => {
    const client = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, callTimeoutMs: 5_000 })
    let transportSawAbort = false
    const watching: Exchange = async (requestBytes, signal) => await new Promise<Uint8Array>((resolve, reject) => {
      signal.addEventListener('abort', () => {
        transportSawAbort = true
        reject(signal.reason as Error)
      }, { once: true })
    })
    const controller = new AbortController()
    const pending = client.call({ to: testPublicKey('bob'), body: { op: 'ping' }, exchange: watching, signal: controller.signal })
    setTimeout(() => { controller.abort() }, 5)
    expect(await codeOf(async () => await pending)).toBe('ERR_CALL_ABORTED')
    expect(transportSawAbort).toBe(true)
  })

  it('does not start a call that is already cancelled', async () => {
    const client = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW })
    const controller = new AbortController()
    controller.abort()
    let touched = false
    expect(await codeOf(async () => await client.call({
      to: testPublicKey('bob'),
      body: { op: 'ping' },
      signal: controller.signal,
      exchange: async (bytes) => {
        touched = true
        return bytes
      }
    }))).toBe('ERR_CALL_ABORTED')
    expect(touched).toBe(false)
  })

  it('reports a transport failure as a failure, never as a business result', async () => {
    const client = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW })
    expect(await codeOf(async () => await client.call({
      to: testPublicKey('bob'),
      body: { op: 'ping' },
      exchange: async () => await Promise.reject(new Error('connection reset'))
    }))).toBe('ERR_TRANSPORT')
  })

  it('keeps a late response from completing a later call', async () => {
    const responder = receiver()
    const client = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(9), callTimeoutMs: 20 })
    // One exchange that swallows the first request, so the call times out.
    let held: Uint8Array | null = null
    const lossy: Exchange = async (requestBytes) => {
      if (held == null) {
        held = requestBytes
        return await new Promise<Uint8Array>((_resolve, reject) => setTimeout(() => reject(new Error('gone')), 40))
      }
      return await responder.core.handle(requestBytes)
    }
    expect(await codeOf(async () => await client.call({ to: testPublicKey('bob'), body: { op: 'first' }, exchange: lossy }))).toBe('ERR_CALL_TIMEOUT')
    // The responder answers the request that was never delivered in time.
    const late = responder.core.handle(held as unknown as Uint8Array)
    // A second, unrelated call must not be completed by that late answer.
    const second = await client.call({ to: testPublicKey('bob'), body: { op: 'second' }, exchange: lossy })
    expect(second.ok).toBe(true)
    const lateBytes = await late
    // Handing the late response to the client as if it belonged to the new call
    // is exactly what reply_to prevents.
    const prepared = await client.buildRequest(testPublicKey('bob'), { op: 'third' })
    expect(await codeOf(async () => await client.verifyResponse(lateBytes, prepared))).toBe('ERR_RESPONSE_REPLY_TO')
  })

  it('reuses the same request id for a retransmission of the same request', async () => {
    const client = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(3) })
    const first = await client.buildRequest(testPublicKey('bob'), { op: 'get_balance', args: { account: 'A' } })
    const again = await client.buildRequest(testPublicKey('bob'), { op: 'get_balance', args: { account: 'A' } })
    expect(again.requestId).not.toBe(first.requestId)
    // Resending the prepared bytes is a retransmission and keeps the id, which
    // is what lets the receiver refuse to run the business twice.
    const sent: Uint8Array[] = []
    const echo: Exchange = async (requestBytes) => {
      sent.push(requestBytes)
      return requestBytes
    }
    const responder = receiver()
    const outcome = await client.send(first, async (bytes) => await responder.core.handle(bytes))
    expect(outcome.ok).toBe(true)
    const duplicate = await client.send(first, async (bytes) => await responder.core.handle(bytes))
    expect(duplicate.ok === false ? duplicate.error.code : '').toBe('REQUEST_ALREADY_SEEN')
    expect(sent).toHaveLength(0)
    expect(requestIdOf(parseRequest(parseJsonText(text(first.bytes))).unsigned)).toBe(first.requestId)
  })
})
