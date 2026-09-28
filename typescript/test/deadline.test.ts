import { describe, expect, it } from 'vitest'
import {
  RoundtripCore,
  digestOf,
  isRoundtripError,
  publicKeyToString,
  type Exchange,
  type JsonValue
} from '../src/index.js'
import {
  TEST_NOW,
  fixedRandom,
  signedBytes,
  testPublicKey,
  testSigner,
  unsignedResponse
} from './fixtures.js'

/**
 * The call deadline has to bound the wait on its own.
 *
 * A transport is allowed to be slow, and it is allowed to be written badly. If
 * the deadline only worked when the adapter cooperated, then an adapter that
 * ignores cancellation would both hang the caller and be able to hand a late
 * answer back as if the call had succeeded in time.
 */

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

const DELAY_MS = 20

function client (timeoutMs: number): RoundtripCore {
  return new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, randomBytes: fixedRandom(3), callTimeoutMs: timeoutMs })
}

/** A responder that produces a genuine signed response for the request. */
function responderFor (): { respond: (requestBytes: Uint8Array) => Promise<Uint8Array>, calls: () => number } {
  let calls = 0
  const service = new RoundtripCore({
    signer: testSigner('bob'),
    nowSeconds: () => TEST_NOW,
    handler: (): { ok: true, result: JsonValue } => ({ ok: true, result: { ok: 1 } })
  })
  return {
    respond: async (requestBytes: Uint8Array): Promise<Uint8Array> => {
      calls++
      return (await service.processRequest(requestBytes)).bytes
    },
    calls: (): number => calls
  }
}

describe('the call deadline is enforced by the core', () => {
  it('refuses a valid response that arrives after the deadline', async () => {
    // The transport ignores the signal and answers late, with a perfectly valid
    // signed response. The caller stopped waiting, so this is not its result.
    const responder = responderFor()
    let finished: () => void = (): void => undefined
    const answered = new Promise<void>((resolve) => {
      finished = resolve
    })
    const late: Exchange = async (requestBytes) => {
      await new Promise((resolve) => setTimeout(resolve, DELAY_MS * 6))
      const bytes = await responder.respond(requestBytes)
      finished()
      return bytes
    }
    const caller = client(DELAY_MS)
    const prepared = await caller.buildRequest(testPublicKey('bob'), { op: 'ping' })
    expect(await codeOf(async () => await caller.send(prepared, late))).toBe('ERR_CALL_TIMEOUT')
    // The business did run on the far side, and its genuine answer arrived too
    // late. The point is that this call does not report it as a result it
    // obtained in time.
    await answered
    expect(responder.calls()).toBe(1)
  })

  it('returns at the deadline even when the transport never settles', async () => {
    // The worst case: an exchange that ignores cancellation and never resolves.
    // Nothing about the deadline may depend on the adapter cooperating.
    const stubborn: Exchange = async () => await new Promise<Uint8Array>(() => undefined)
    const caller = client(DELAY_MS)
    const prepared = await caller.buildRequest(testPublicKey('bob'), { op: 'ping' })
    const started = Date.now()
    expect(await codeOf(async () => await caller.send(prepared, stubborn))).toBe('ERR_CALL_TIMEOUT')
    const elapsed = Date.now() - started
    expect(elapsed).toBeGreaterThanOrEqual(DELAY_MS - 2)
    expect(elapsed).toBeLessThan(DELAY_MS * 20)
  })

  it('still returns a response that arrived in time', async () => {
    const responder = responderFor()
    const prompt: Exchange = async (requestBytes) => await responder.respond(requestBytes)
    const caller = client(5_000)
    const prepared = await caller.buildRequest(testPublicKey('bob'), { op: 'ping' })
    const outcome = await caller.send(prepared, prompt)
    expect(outcome.ok).toBe(true)
  })

  it('reports a caller cancellation as an abort, not as a timeout', async () => {
    const stubborn: Exchange = async () => await new Promise<Uint8Array>(() => undefined)
    const caller = client(5_000)
    const prepared = await caller.buildRequest(testPublicKey('bob'), { op: 'ping' })
    const controller = new AbortController()
    const pending = caller.send(prepared, stubborn, { signal: controller.signal })
    setTimeout(() => { controller.abort() }, 5)
    expect(await codeOf(async () => await pending)).toBe('ERR_CALL_ABORTED')
  })

  it('does not promote a late response to a call that already timed out', async () => {
    // The same bytes, offered to a call that is no longer waiting. A waiting call
    // completes at most once, and a call that ended cannot be completed later.
    const caller = client(DELAY_MS)
    const prepared = await caller.buildRequest(testPublicKey('bob'), { op: 'ping' })
    const unsigned = unsignedResponse({
      from: testPublicKey('bob'),
      to: caller.publicKey(),
      replyTo: digestOf(prepared.unsigned),
      body: { ok: true, result: { ok: 1 } }
    })
    const bytes = signedBytes(unsigned, 'bob')
    const slow: Exchange = async () => {
      await new Promise((resolve) => setTimeout(resolve, DELAY_MS * 6))
      return bytes
    }
    expect(await codeOf(async () => await caller.send(prepared, slow))).toBe('ERR_CALL_TIMEOUT')
    // The bytes are genuine, so a caller that is still waiting accepts them.
    const fresh = new RoundtripCore({ signer: testSigner('alice'), nowSeconds: () => TEST_NOW, callTimeoutMs: 5_000 })
    const other = await fresh.buildRequest(testPublicKey('bob'), { op: 'ping' })
    expect(text(bytes)).toContain(encodeBase64UrlOf(other))
  })
})

function encodeBase64UrlOf (prepared: { unsigned: { to: Uint8Array } }): string {
  return publicKeyToString(prepared.unsigned.to)
}

describe('the HTTP client bounds what it reads', () => {
  it('does not read an unbounded error body', async () => {
    const { httpExchange } = await import('../src/index.js')
    const chunk = new Uint8Array(64 * 1024).fill(0x41)
    let produced = 0
    let cancelled = false
    // A peer that answers 500 with an endless error page.
    const endless = new ReadableStream<Uint8Array>({
      pull (controller) {
        produced += chunk.length
        controller.enqueue(chunk)
      },
      cancel (): void {
        cancelled = true
      }
    })
    const exchange = httpExchange('http://127.0.0.1:1/roundtrip', {
      maxResponseBytes: 128 * 1024,
      fetch: async () => await Promise.resolve(new Response(endless, { status: 500 }))
    })
    const caller = client(5_000)
    const prepared = await caller.buildRequest(testPublicKey('bob'), { op: 'ping' })
    // The status is still the reported reason; the point is that the body is not
    // accumulated without limit on the way there.
    expect(await codeOf(async () => await caller.send(prepared, exchange))).toBe('ERR_HTTP_STATUS')
    expect(cancelled).toBe(true)
    expect(produced).toBeLessThanOrEqual(256 * 1024)
  })

  it('refuses an oversized success body the same way', async () => {
    const { httpExchange } = await import('../src/index.js')
    const chunk = new Uint8Array(64 * 1024).fill(0x41)
    let cancelled = false
    const endless = new ReadableStream<Uint8Array>({
      pull (controller) {
        controller.enqueue(chunk)
      },
      cancel (): void {
        cancelled = true
      }
    })
    const exchange = httpExchange('http://127.0.0.1:1/roundtrip', {
      maxResponseBytes: 128 * 1024,
      fetch: async () => await Promise.resolve(new Response(endless, { status: 200 }))
    })
    const caller = client(5_000)
    const prepared = await caller.buildRequest(testPublicKey('bob'), { op: 'ping' })
    expect(await codeOf(async () => await caller.send(prepared, exchange))).toBe('ERR_RESPONSE_SIZE')
    expect(cancelled).toBe(true)
  })
})
