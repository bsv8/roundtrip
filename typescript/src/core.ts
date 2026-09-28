import { decodeBase64Url, encodeBase64Url, equalBytes } from './bytes.js'
import { verifyDigest } from './crypto.js'
import {
  bodyToOutcome,
  encodeEnvelopeBytes,
  outcomeToBody,
  parseRequest,
  parseResponse,
  requestIdOf,
  type RequestEnvelope,
  type UnsignedRequest,
  type UnsignedResponse
} from './envelope.js'
import { RoundtripError, throwIfAborted } from './errors.js'
import { parseJsonBytes } from './json.js'
import { MemoryReplayGuard, type ReplayGuard } from './replay.js'
import { digestOf, type RoundtripSigner } from './signer.js'
import { validatePublicKey } from './crypto.js'
import type { BusinessError, HandlerOutcome, JsonValue } from './types.js'

export const DEFAULT_MAX_MESSAGE_BYTES = 1024 * 1024
export const DEFAULT_REQUEST_TTL_SECONDS = 60
export const DEFAULT_MAX_REQUEST_TTL_SECONDS = 60
export const DEFAULT_CLOCK_SKEW_SECONDS = 5
export const DEFAULT_CALL_TIMEOUT_MS = 15_000
export const DEFAULT_NONCE_BYTES = 32

/** Business error code used for every duplicate delivery in this version. */
export const REPLAY_ERROR_CODE = 'REQUEST_ALREADY_SEEN'
export const HANDLER_ERROR_CODE = 'HANDLER_FAILED'

/** Moves one request envelope to one response envelope. No signatures, no business. */
export type Exchange = (requestBytes: Uint8Array, signal: AbortSignal) => Promise<Uint8Array>

export interface CoreConfig {
  signer: RoundtripSigner
  /** Required only by the receiving side. */
  handler?: RoundtripHandler
  replay?: ReplayGuard
  maxMessageBytes?: number
  requestTtlSeconds?: number
  maxRequestTtlSeconds?: number
  clockSkewSeconds?: number
  callTimeoutMs?: number
  nowSeconds?: () => number
  randomBytes?: (length: number) => Uint8Array
}

export interface HandlerContext {
  callerPublicKey: Uint8Array
  requestId: string
  body: JsonValue
  envelope: RequestEnvelope
}

/**
 * Application entry point. Structure, recipient, signature and dedup checks
 * have already passed when this runs, so authorization is the application's job
 * inside the handler.
 */
export type RoundtripHandler = (context: HandlerContext) => HandlerOutcome | Promise<HandlerOutcome>

export interface PreparedRequest {
  unsigned: UnsignedRequest
  bytes: Uint8Array
  requestId: string
}

export interface CallInput {
  to: Uint8Array | string
  body: JsonValue
  exchange: Exchange
  timeoutMs?: number
  signal?: AbortSignal
}

export type CallOutcome =
  | { ok: true, result: JsonValue, requestId: string }
  | { ok: false, error: BusinessError, requestId: string }

export interface BuildRequestOptions {
  nonce?: Uint8Array
  expires?: number
  signal?: AbortSignal
}

export interface HandleOptions {
  /**
   * Authenticated transport identity of the sender, when the transport has one
   * (libp2p connection). It must equal the request `from`.
   */
  callerPublicKey?: Uint8Array
}

export interface ProcessedRequest {
  requestId: string
  outcome: HandlerOutcome
  bytes: Uint8Array
}

export class RoundtripCore {
  readonly #signer: RoundtripSigner
  readonly #handler: RoundtripHandler | undefined
  readonly #replay: ReplayGuard
  readonly #publicKey: Uint8Array
  readonly #maxMessageBytes: number
  readonly #requestTtlSeconds: number
  readonly #maxRequestTtlSeconds: number
  readonly #clockSkewSeconds: number
  readonly #callTimeoutMs: number
  readonly #nowSeconds: () => number
  readonly #randomBytes: (length: number) => Uint8Array

  constructor (config: CoreConfig) {
    this.#signer = config.signer
    this.#handler = config.handler
    this.#nowSeconds = config.nowSeconds ?? ((): number => Math.floor(Date.now() / 1000))
    // The default guard gets this instance's clock, so retention and the expiry
    // check can never disagree.
    this.#replay = config.replay ?? new MemoryReplayGuard(this.#nowSeconds)
    this.#publicKey = validatePublicKey(config.signer.publicKey())
    this.#maxMessageBytes = positiveInteger(config.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES, 'maxMessageBytes')
    this.#requestTtlSeconds = positiveInteger(config.requestTtlSeconds ?? DEFAULT_REQUEST_TTL_SECONDS, 'requestTtlSeconds')
    this.#maxRequestTtlSeconds = positiveInteger(config.maxRequestTtlSeconds ?? DEFAULT_MAX_REQUEST_TTL_SECONDS, 'maxRequestTtlSeconds')
    this.#clockSkewSeconds = nonNegativeInteger(config.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS, 'clockSkewSeconds')
    this.#callTimeoutMs = positiveInteger(config.callTimeoutMs ?? DEFAULT_CALL_TIMEOUT_MS, 'callTimeoutMs')
    this.#randomBytes = config.randomBytes ?? ((length: number): Uint8Array => globalThis.crypto.getRandomValues(new Uint8Array(length)))
  }

  /** The identity this instance signs with. The identity of an instance is fixed. */
  publicKey (): Uint8Array {
    return new Uint8Array(this.#publicKey)
  }

  get replay (): ReplayGuard {
    return this.#replay
  }

  get limits (): { maxMessageBytes: number, requestTtlSeconds: number, maxRequestTtlSeconds: number, clockSkewSeconds: number, callTimeoutMs: number } {
    return {
      maxMessageBytes: this.#maxMessageBytes,
      requestTtlSeconds: this.#requestTtlSeconds,
      maxRequestTtlSeconds: this.#maxRequestTtlSeconds,
      clockSkewSeconds: this.#clockSkewSeconds,
      callTimeoutMs: this.#callTimeoutMs
    }
  }

  /**
   * Builds and signs one request. The nonce comes from a cryptographically
   * secure source, so two identical business calls get two different ids. A
   * retransmission must reuse the returned bytes.
   */
  async buildRequest (to: Uint8Array | string, body: JsonValue, options: BuildRequestOptions = {}): Promise<PreparedRequest> {
    const target = resolvePublicKey(to)
    const nonce = options.nonce ?? this.#randomBytes(DEFAULT_NONCE_BYTES)
    if (nonce.length < 16) {
      throw new RoundtripError('ERR_NONCE', 'nonce must be at least 16 bytes')
    }
    const expires = options.expires ?? (this.#nowSeconds() + this.#requestTtlSeconds)
    if (Number.isInteger(expires) !== true) {
      throw new RoundtripError('ERR_EXPIRES', 'expires must be an integer number of unix seconds')
    }
    const unsigned: UnsignedRequest = { kind: 'request', from: this.#publicKey, to: target, nonce, expires, body }
    const signature = await this.#sign(unsigned, options.signal)
    const bytes = encodeEnvelopeBytes(unsigned, signature)
    return { unsigned, bytes, requestId: requestIdOf(unsigned) }
  }

  /**
   * One request, one response.
   *
   * The response must come from the requested peer, must be addressed to this
   * instance, must quote the id of the request that is waiting, and must carry
   * a valid signature. A waiting call completes at most once.
   */
  async call (input: CallInput): Promise<CallOutcome> {
    const prepared = await this.buildRequest(input.to, input.body, { signal: input.signal })
    return await this.send(prepared, input.exchange, input)
  }

  async send (prepared: PreparedRequest, exchange: Exchange, options: { timeoutMs?: number, signal?: AbortSignal } = {}): Promise<CallOutcome> {
    const timeoutMs = options.timeoutMs ?? this.#callTimeoutMs
    const controller = new AbortController()
    const timer = setTimeout(() => {
      controller.abort(new RoundtripError('ERR_CALL_TIMEOUT', `no response within ${timeoutMs}ms`))
    }, timeoutMs)
    const onParentAbort = (): void => {
      controller.abort(new RoundtripError('ERR_CALL_ABORTED', 'call aborted by the caller'))
    }
    options.signal?.addEventListener('abort', onParentAbort, { once: true })
    let responseBytes: Uint8Array
    try {
      // The deadline has to bound this wait on its own. A transport that only
      // stops when it is told to would otherwise hold the caller for ever, so
      // the abort races the exchange instead of being left to the adapter.
      const pending = exchange(prepared.bytes, controller.signal)
      // The losing promise still needs a handler, or a late rejection from the
      // transport would surface as an unhandled rejection.
      pending.catch(() => undefined)
      responseBytes = await Promise.race([pending, aborted(controller.signal)])
    } catch (error) {
      if (error instanceof RoundtripError) throw error
      if (controller.signal.aborted) throw controller.signal.reason as RoundtripError
      throw new RoundtripError('ERR_TRANSPORT', error instanceof Error ? error.message : 'exchange failed', { cause: error })
    } finally {
      clearTimeout(timer)
      options.signal?.removeEventListener('abort', onParentAbort)
    }
    // The transport can also win this race and then hand over bytes after the
    // deadline. A late answer is not a result for this call, so it is refused
    // before any of it is verified.
    throwIfAborted(controller.signal)
    return this.verifyResponse(responseBytes, prepared)
  }

  /**
   * Verifies an incoming response. The three identity fields and the signature
   * are all required, so a response for another call can never complete this
   * one.
   */
  verifyResponse (responseBytes: Uint8Array, prepared: PreparedRequest): CallOutcome {
    if (responseBytes.length > this.#maxMessageBytes) {
      throw new RoundtripError('ERR_RESPONSE_SIZE', 'response exceeds the local message limit')
    }
    const envelope = parseResponse(parseJsonBytes(responseBytes))
    const unsigned = envelope.unsigned
    if (equalBytes(unsigned.to, this.#publicKey) !== true) {
      throw new RoundtripError('ERR_RESPONSE_TO', 'response is not addressed to this identity')
    }
    if (equalBytes(unsigned.from, prepared.unsigned.to) !== true) {
      throw new RoundtripError('ERR_RESPONSE_FROM', 'response did not come from the requested peer')
    }
    if (equalBytes(unsigned.replyTo, digestOf(prepared.unsigned)) !== true) {
      throw new RoundtripError('ERR_RESPONSE_REPLY_TO', 'response does not belong to the waiting request')
    }
    try {
      verifyDigest(unsigned.from, digestOf(unsigned), envelope.signature)
    } catch (error) {
      if (error instanceof RoundtripError && error.code === 'ERR_SIGNATURE') {
        throw new RoundtripError('ERR_RESPONSE_SIGNATURE', error.message, { cause: error })
      }
      throw error
    }
    const outcome = bodyToOutcome(unsigned.body)
    return outcome.ok
      ? { ok: true, result: outcome.result, requestId: prepared.requestId }
      : { ok: false, error: outcome.error, requestId: prepared.requestId }
  }

  /**
   * Processes one signed request and returns the signed response bytes.
   *
   * Order matters: structure and size, then expiry, then recipient, then
   * signature, then the atomic replay claim, and only then the application.
   * Claiming before the handler is what stops two concurrent deliveries of the
   * same request from both producing side effects.
   */
  async handle (requestBytes: Uint8Array, options: HandleOptions = {}): Promise<Uint8Array> {
    return (await this.processRequest(requestBytes, options)).bytes
  }

  async processRequest (requestBytes: Uint8Array, options: HandleOptions = {}): Promise<ProcessedRequest> {
    if (this.#handler == null) {
      throw new RoundtripError('ERR_NO_HANDLER', 'this instance has no request handler')
    }
    if (requestBytes.length > this.#maxMessageBytes) {
      throw new RoundtripError('ERR_MESSAGE_TOO_LARGE', `request exceeds ${this.#maxMessageBytes} bytes`)
    }
    const envelope = parseRequest(parseJsonBytes(requestBytes))
    const unsigned = envelope.unsigned
    const now = this.#nowSeconds()
    if (unsigned.expires > now + this.#maxRequestTtlSeconds) {
      throw new RoundtripError('ERR_EXPIRY_WINDOW', 'request expiry is further away than the local window allows')
    }
    if (unsigned.expires + this.#clockSkewSeconds < now) {
      throw new RoundtripError('ERR_EXPIRED', 'request has expired')
    }
    if (equalBytes(unsigned.to, this.#publicKey) !== true) {
      throw new RoundtripError('ERR_RECIPIENT', 'request is not addressed to this identity')
    }
    if (options.callerPublicKey != null && equalBytes(options.callerPublicKey, unsigned.from) !== true) {
      throw new RoundtripError('ERR_CALLER_IDENTITY', 'request from does not match the authenticated transport peer')
    }
    try {
      verifyDigest(unsigned.from, digestOf(unsigned), envelope.signature)
    } catch (error) {
      if (error instanceof RoundtripError && error.code === 'ERR_SIGNATURE') {
        throw new RoundtripError('ERR_SIGNATURE', error.message, { cause: error })
      }
      throw error
    }

    const requestId = requestIdOf(unsigned)
    const outcome = await this.#dispatch(requestId, unsigned, envelope)
    const response = await this.#signResponse(unsigned.from, requestId, outcome)
    return { requestId, outcome, bytes: encodeEnvelopeBytes(response.unsigned, response.signature) }
  }

  async #dispatch (requestId: string, unsigned: UnsignedRequest, envelope: RequestEnvelope): Promise<HandlerOutcome> {
    const claimed = await this.#replay.claim({
      id: requestId,
      retainUntil: unsigned.expires + this.#clockSkewSeconds
    })
    if (claimed !== true) {
      return { ok: false, error: { code: REPLAY_ERROR_CODE, message: 'this request has already been received' } }
    }
    let outcome: HandlerOutcome
    try {
      outcome = await (this.#handler as RoundtripHandler)({
        callerPublicKey: unsigned.from,
        requestId,
        body: unsigned.body,
        envelope
      })
    } catch (error) {
      // A handler failure is a signed business error, not a transport error,
      // and it must not leak internals to the caller.
      outcome = { ok: false, error: { code: HANDLER_ERROR_CODE, message: 'handler failed' } }
    }
    await this.#replay.complete(requestId)
    return outcome
  }

  async #signResponse (caller: Uint8Array, requestId: string, outcome: HandlerOutcome): Promise<{ unsigned: UnsignedResponse, signature: Uint8Array }> {
    const unsigned: UnsignedResponse = {
      kind: 'response',
      from: this.#publicKey,
      to: new Uint8Array(caller),
      replyTo: decodeBase64Url(requestId, 'ERR_REPLY_TO'),
      body: outcomeToBody(outcome)
    }
    return { unsigned, signature: await this.#sign(unsigned) }
  }

  async #sign (unsigned: UnsignedRequest | UnsignedResponse, signal?: AbortSignal): Promise<Uint8Array> {
    throwIfAborted(signal)
    let signature: Uint8Array
    try {
      signature = await this.#signer.signRoundtrip(unsigned, signal)
    } catch (error) {
      if (error instanceof RoundtripError) throw error
      throw new RoundtripError('ERR_SIGNER_FAILED', error instanceof Error ? error.message : 'signer failed', { cause: error })
    }
    // Verify before anything leaves this process: a signer whose output does not
    // match the canonical bytes is a configuration error, not a network error.
    try {
      verifyDigest(unsigned.from, digestOf(unsigned), signature)
    } catch (error) {
      throw new RoundtripError('ERR_SIGNER_KEY', 'signer produced a signature that does not verify for this identity', { cause: error })
    }
    return signature
  }
}

function positiveInteger (value: number, name: string): number {
  if (Number.isSafeInteger(value) !== true || value <= 0) {
    throw new RoundtripError('ERR_JSON_NUMBER', `${name} must be a positive safe integer`)
  }
  return value
}

function nonNegativeInteger (value: number, name: string): number {
  if (Number.isSafeInteger(value) !== true || value < 0) {
    throw new RoundtripError('ERR_JSON_NUMBER', `${name} must be a non negative safe integer`)
  }
  return value
}

export function resolvePublicKey (value: Uint8Array | string): Uint8Array {
  if (typeof value === 'string') return validatePublicKey(decodeBase64Url(value, 'ERR_PUBLIC_KEY'))
  return validatePublicKey(value)
}

/** Rejects as soon as the signal is aborted, without settling on its own. */
function aborted (signal: AbortSignal): Promise<never> {
  return new Promise<never>((_resolve, reject) => {
    if (signal.aborted === true) {
      reject(signal.reason as RoundtripError)
      return
    }
    signal.addEventListener('abort', () => reject(signal.reason as RoundtripError), { once: true })
  })
}

export function publicKeyToString (publicKey: Uint8Array): string {
  return encodeBase64Url(publicKey)
}
