import { describe, expect, it } from 'vitest'
import { RoundtripCore, publicKeyToString, type Exchange, type HandlerOutcome } from '../src/index.js'
import { TEST_NOW, fixedRandom, testPublicKey, testSigner } from './fixtures.js'

/**
 * The baseline: one request, one signed response, over any transport that can
 * move bytes. Everything the other suites remove is present here.
 */

const node = (name: string, handler?: () => HandlerOutcome): RoundtripCore => new RoundtripCore({
  signer: testSigner(name),
  nowSeconds: () => TEST_NOW,
  randomBytes: fixedRandom(3),
  ...(handler == null ? {} : { handler })
})

/** Wires a caller straight into a receiver, standing in for a transport. */
function direct (server: RoundtripCore): Exchange {
  return async (requestBytes) => await server.handle(requestBytes)
}

describe('baseline: one signed request, one signed response', () => {
  it('answers a call and reports the business result', async () => {
    const server = node('bob', () => ({ ok: true, result: { confirmed: 42, satoshis: '1050000000' } }))
    const client = node('alice')
    const outcome = await client.call({ to: server.publicKey(), body: { op: 'get_balance', args: { asset: 'BSV' } }, exchange: direct(server) })
    expect(outcome.ok).toBe(true)
    expect(outcome.ok === true ? outcome.result : null).toEqual({ confirmed: 42, satoshis: '1050000000' })
    expect(outcome.requestId).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })

  it('reports a signed business failure as a failure, not as an error', async () => {
    const server = node('bob', () => ({ ok: false, error: { code: 'UNKNOWN_ASSET', message: '没有这个资产' } }))
    const client = node('alice')
    const outcome = await client.call({ to: server.publicKey(), body: { op: 'get_balance', args: { asset: 'XYZ' } }, exchange: direct(server) })
    expect(outcome.ok).toBe(false)
    expect(outcome.ok === false ? outcome.error : null).toEqual({ code: 'UNKNOWN_ASSET', message: '没有这个资产' })
  })

  it('works in both directions with the same shell', async () => {
    const alice = node('alice', () => ({ ok: true, result: 'pong' }))
    const bob = node('bob', () => ({ ok: true, result: 'ping' }))
    const toAlice = await bob.call({ to: alice.publicKey(), body: { op: 'ping' }, exchange: direct(alice) })
    const toBob = await alice.call({ to: bob.publicKey(), body: { op: 'ping' }, exchange: direct(bob) })
    expect(toAlice.ok === true ? toAlice.result : null).toBe('pong')
    expect(toBob.ok === true ? toBob.result : null).toBe('ping')
  })

  it('serves concurrent calls on separate streams without a shared wait table', async () => {
    const server = node('bob', () => ({ ok: true, result: { accepted: true } }))
    const client = node('alice')
    const outcomes = await Promise.all(Array.from({ length: 5 }, async () =>
      await client.call({ to: server.publicKey(), body: { op: 'ping' }, exchange: direct(server) })))
    expect(outcomes.filter((outcome) => outcome.ok === true)).toHaveLength(5)
    // Every call got its own answer, so nothing was mixed up between them.
    expect(new Set(outcomes.map((outcome) => outcome.requestId)).size).toBe(5)
  })

  it('gives two identical business calls two different request ids', async () => {
    const server = node('bob', () => ({ ok: true, result: 1 }))
    const client = node('alice')
    const first = await client.call({ to: server.publicKey(), body: { op: 'get_balance', args: { asset: 'BSV' } }, exchange: direct(server) })
    const second = await client.call({ to: server.publicKey(), body: { op: 'get_balance', args: { asset: 'BSV' } }, exchange: direct(server) })
    // Same business, same instant, different nonce, so the receiver runs both
    // instead of treating the second as a replay of the first.
    expect(first.requestId).not.toBe(second.requestId)
    expect(first.ok).toBe(true)
    expect(second.ok).toBe(true)
  })

  it('accepts a base64url target and the binary one as the same identity', async () => {
    const server = node('bob', () => ({ ok: true, result: 1 }))
    const client = node('alice')
    const outcome = await client.call({ to: publicKeyToString(server.publicKey()), body: { op: 'ping' }, exchange: direct(server) })
    expect(outcome.ok).toBe(true)
    expect(encodeEqual(server.publicKey(), testPublicKey('bob'))).toBe(true)
  })
})

function encodeEqual (left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index])
}
