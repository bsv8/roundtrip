import { peerIdFromPublicKeyBytes } from 'bitcoin-libp2p/identity'
import { authenticateConnection } from 'bitcoin-libp2p/libp2p'
import { readUvarintFrames, writeUvarintFrame } from 'bitcoin-libp2p/stream'
import type { Connection, Libp2p, Stream } from '@libp2p/interface'
import { RoundtripError, throwIfAborted } from '../errors.js'
import { decodeBase64Url } from '../bytes.js'
import { validatePublicKey } from '../crypto.js'
import type { Exchange, RoundtripCore } from '../core.js'

/** One request and one response per stream, framed with the upstream uvarint tool. */
export const ROUNDTRIP_PROTOCOL = '/roundtrip/1'

export interface Libp2pAdapterOptions {
  protocol?: string
  /** Local inbound frame limit; the core applies the message limit as well. */
  maxFrameBytes?: number
  /** Local bound on how long one inbound request may take to arrive complete. */
  timeoutMs?: number
}

const DEFAULT_MAX_FRAME_BYTES = 1024 * 1024 + 16
const DEFAULT_STREAM_TIMEOUT_MS = 15_000

interface HandleResult {
  unregister: () => Promise<void>
}

/**
 * Serves `/roundtrip/1`: open stream, read one frame, answer with one frame,
 * close the stream.
 *
 * The stream is not reused for a second call, and a second frame on the same
 * stream is a protocol error rather than a new request. Reading to the end of
 * the caller's write side is what makes a second frame detectable, so a caller
 * that never half closes is bounded by `timeoutMs` instead of hanging here.
 */
export async function serveLibp2p (node: Libp2p, core: RoundtripCore, options: Libp2pAdapterOptions = {}): Promise<HandleResult> {
  const protocol = options.protocol ?? ROUNDTRIP_PROTOCOL
  const maxFrameBytes = options.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES
  const timeoutMs = options.timeoutMs ?? DEFAULT_STREAM_TIMEOUT_MS
  await node.handle(protocol, (stream: Stream, connection: Connection) => {
    void serveStream(stream, connection, core, maxFrameBytes, timeoutMs).catch(() => {
      abortQuietly(stream)
    })
  })
  return {
    unregister: async (): Promise<void> => {
      await node.unhandle(protocol)
    }
  }
}

async function serveStream (stream: Stream, connection: Connection, core: RoundtripCore, maxFrameBytes: number, timeoutMs: number): Promise<void> {
  const controller = new AbortController()
  const timer = setTimeout(() => {
    controller.abort(new RoundtripError('ERR_CALL_TIMEOUT', `no complete request within ${timeoutMs}ms`))
  }, timeoutMs)
  try {
    // Connection authentication is not message verification: the core still
    // verifies the signature, and it also requires that the request `from` is
    // exactly this authenticated peer.
    const peer = authenticateConnection(connection)
    const requestBytes = await readSingleFrame(stream, maxFrameBytes, controller.signal)
    if (requestBytes == null) {
      abortQuietly(stream)
      return
    }
    const processed = await core.processRequest(requestBytes, { callerPublicKey: peer.publicKey })
    writeUvarintFrame(stream, processed.bytes)
    await closeQuietly(stream)
  } catch (error) {
    abortQuietly(stream, error)
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Builds the `exchange` for one peer.
 *
 * The target is the 33-byte business public key. The PeerId used for dialling is
 * derived with the upstream native helper, never hand assembled. Before the call
 * the authenticated remote public key of the connection must equal the target,
 * so a relayed or wrong connection cannot answer a call addressed to someone
 * else.
 */
export function libp2pExchange (node: Libp2p, to: Uint8Array | string, options: Libp2pAdapterOptions = {}): Exchange {
  const protocol = options.protocol ?? ROUNDTRIP_PROTOCOL
  const maxFrameBytes = options.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES
  const publicKey = validatePublicKey(typeof to === 'string' ? decodeBase64Url(to, 'ERR_PUBLIC_KEY') : to)
  const peerId = peerIdFromPublicKeyBytes(publicKey)
  return async (requestBytes: Uint8Array, signal: AbortSignal): Promise<Uint8Array> => {
    throwIfAborted(signal)
    const connection = await abortable(node.dial(peerId), signal)
    // A connection authenticated as somebody else must never answer a call
    // addressed to the target identity.
    authenticateConnection(connection, { publicKey })
    const stream = await abortable(connection.newStream(protocol), signal)
    const onAbort = (): void => abortQuietly(stream)
    signal.addEventListener('abort', onAbort, { once: true })
    try {
      writeUvarintFrame(stream, requestBytes)
      // Half close after the one request frame. The read side stays open for the
      // response, and the responder now knows the request is complete: it reads
      // to end of stream precisely so that a second frame is detectable.
      await stream.close()
      const responseBytes = await readSingleFrame(stream, maxFrameBytes)
      if (responseBytes == null) {
        throw new RoundtripError('ERR_FRAME', 'stream closed before a response frame arrived')
      }
      return responseBytes
    } catch (error) {
      if (error instanceof RoundtripError) throw error
      throw new RoundtripError('ERR_TRANSPORT', error instanceof Error ? error.message : 'libp2p stream failed', { cause: error })
    } finally {
      signal.removeEventListener('abort', onAbort)
      await closeQuietly(stream)
    }
  }
}

/**
 * Reads exactly one frame. Zero frames is a truncated call; a second frame is a
 * protocol error, because one stream carries one request and one response.
 *
 * The end of the peer's write side is what terminates this read, so a peer that
 * never half closes is bounded by the call timeout rather than by this function.
 */
async function readSingleFrame (stream: Stream, maxFrameBytes: number, signal?: AbortSignal): Promise<Uint8Array | undefined> {
  const iterator = readUvarintFrames(stream, { maxInboundFrameBytes: maxFrameBytes, ...(signal == null ? {} : { signal }) })[Symbol.asyncIterator]()
  try {
    const first = await iterator.next()
    if (first.done === true) return undefined
    const second = await iterator.next()
    if (second.done !== true) {
      throw new RoundtripError('ERR_FRAME', 'a stream must carry exactly one request and one response')
    }
    return first.value
  } finally {
    void iterator.return?.(undefined).catch(() => undefined)
  }
}

function abortable<T> (promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted === true) {
    throw signal.reason instanceof Error ? signal.reason : new RoundtripError('ERR_CALL_ABORTED', 'call aborted')
  }
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => {
      reject(signal.reason instanceof Error ? signal.reason : new RoundtripError('ERR_CALL_ABORTED', 'call aborted'))
    }
    signal.addEventListener('abort', onAbort, { once: true })
    void promise.then(value => {
      signal.removeEventListener('abort', onAbort)
      resolve(value)
    }, error => {
      signal.removeEventListener('abort', onAbort)
      reject(error)
    })
  })
}

function abortQuietly (stream: Stream, cause?: unknown): void {
  try {
    stream.abort(cause instanceof Error ? cause : new RoundtripError('ERR_TRANSPORT', 'stream aborted'))
  } catch {
    // The stream may already be in a terminal state.
  }
}

async function closeQuietly (stream: Stream): Promise<void> {
  try {
    await stream.close()
  } catch {
    // Closing an already closed stream is not an error for us.
  }
}
