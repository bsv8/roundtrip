import { RoundtripError } from '../errors.js'
import type { Exchange } from '../core.js'
import { HTTP_CONTENT_TYPE } from './endpoint.js'

export interface HttpExchangeOptions {
  fetch?: typeof globalThis.fetch
  maxResponseBytes?: number
  headers?: Record<string, string>
}

const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024

/**
 * One POST, one response.
 *
 * There is no global waiting table and no response dispatch loop: the HTTP call
 * that sends the request is the call that waits for its answer. A non 2xx
 * status is reported as a transport failure, because an unsigned status code or
 * a proxy error page is not a signed business result.
 */
export function httpExchange (url: string, options: HttpExchangeOptions = {}): Exchange {
  const doFetch = options.fetch ?? globalThis.fetch
  if (typeof doFetch !== 'function') {
    throw new RoundtripError('ERR_TRANSPORT', 'no fetch implementation is available')
  }
  const maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES
  return async (requestBytes: Uint8Array, signal: AbortSignal): Promise<Uint8Array> => {
    const response = await doFetch(url, {
      method: 'POST',
      headers: { 'content-type': HTTP_CONTENT_TYPE, ...options.headers },
      body: requestBytes,
      signal
    })
    if (response.ok !== true) {
      // Drain a bounded amount so the connection can be reused, then stop. An
      // error page or a hostile peer must not be able to grow this client's
      // memory without limit, exactly as on the success path.
      await readBounded(response, maxResponseBytes).catch(() => undefined)
      throw new RoundtripError('ERR_HTTP_STATUS', `unexpected HTTP status ${response.status}`)
    }
    return await readBounded(response, maxResponseBytes)
  }
}

/**
 * Reads at most `limit` bytes and gives up on the rest.
 *
 * Both the success and the error path go through here, so a body that is too
 * large is refused the same way whichever status carried it.
 */
async function readBounded (response: Response, limit: number): Promise<Uint8Array> {
  const body = response.body
  if (body == null) {
    // A response with no stream can only be read whole, so it is checked after
    // the fact rather than during.
    const buffer = new Uint8Array(await response.arrayBuffer())
    if (buffer.length > limit) {
      throw new RoundtripError('ERR_RESPONSE_SIZE', 'response exceeds the local message limit')
    }
    return buffer
  }
  const reader = body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done === true) break
    if (value == null) continue
    total += value.length
    if (total > limit) {
      await reader.cancel()
      throw new RoundtripError('ERR_RESPONSE_SIZE', 'response exceeds the local message limit')
    }
    chunks.push(value)
  }
  const output = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    output.set(chunk, offset)
    offset += chunk.length
  }
  return output
}
