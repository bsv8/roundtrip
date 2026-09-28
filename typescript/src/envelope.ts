import { RoundtripError } from './errors.js'
import { decodeBase64Url, encodeBase64Url, equalBytes, utf8 } from './bytes.js'
import { canonicalize } from './jcs.js'
import { parseDerSignature, sha256Bytes, validatePublicKey, verifyDigest } from './crypto.js'
import { MAX_SAFE_INTEGER } from './json.js'
import { isJsonObject, type BusinessError, type JsonObject, type JsonValue } from './types.js'

/** Domain separation and version tag; it never travels on the wire. */
export const SIGNING_PREFIX = 'roundtrip/v1\n'

/**
 * A second, separate prefix for the optional trimmed HTTPS response.
 *
 * It exists so a trimmed response cannot be mistaken for a base request or a
 * base response: the bytes that are signed are different, so a signature made
 * for one is never valid for the other. It is a message layer concern only; no
 * transport in this version produces or accepts it.
 */
export const TRIMMED_RESPONSE_PREFIX = 'roundtrip/http-response/v1\n'

export const MIN_NONCE_BYTES = 16
export const MAX_NONCE_BYTES = 64
export const PUBLIC_KEY_BYTES = 33
export const DIGEST_BYTES = 32

export interface UnsignedRequest {
  readonly kind: 'request'
  from: Uint8Array
  to: Uint8Array
  nonce: Uint8Array
  expires: number
  body: JsonValue
}

export interface UnsignedResponse {
  readonly kind: 'response'
  from: Uint8Array
  to: Uint8Array
  replyTo: Uint8Array
  body: JsonValue
}

/**
 * The optional trusted HTTPS response: no `reply_to`, because the correlation is
 * carried by the transport instead of by the signature.
 *
 * Dropping the field also drops the proof that the response answers a particular
 * request. That is the documented trade off, and it is why the base reader has to
 * keep refusing this shape.
 */
export interface UnsignedTrimmedResponse {
  readonly kind: 'trimmed-response'
  from: Uint8Array
  to: Uint8Array
  body: JsonValue
}

export type UnsignedMessage = UnsignedRequest | UnsignedResponse | UnsignedTrimmedResponse

export interface RequestEnvelope {
  readonly unsigned: UnsignedRequest
  readonly signature: Uint8Array
}

export interface ResponseEnvelope {
  readonly unsigned: UnsignedResponse
  readonly signature: Uint8Array
}

export interface TrimmedResponseEnvelope {
  readonly unsigned: UnsignedTrimmedResponse
  readonly signature: Uint8Array
}

const REQUEST_FIELDS = ['from', 'to', 'nonce', 'expires', 'body', 'sig'] as const
const RESPONSE_FIELDS = ['from', 'to', 'reply_to', 'body', 'sig'] as const
const TRIMMED_RESPONSE_FIELDS = ['from', 'to', 'body', 'sig'] as const

export function isRequest (value: UnsignedMessage): value is UnsignedRequest {
  return value.kind === 'request'
}

export function isTrimmedResponse (value: UnsignedMessage): value is UnsignedTrimmedResponse {
  return value.kind === 'trimmed-response'
}

/** The prefix that separates the message kinds in the signed bytes. */
export function signingPrefixOf (unsigned: UnsignedMessage): string {
  return unsigned.kind === 'trimmed-response' ? TRIMMED_RESPONSE_PREFIX : SIGNING_PREFIX
}

/** The exact object that gets canonicalized and hashed. */
export function unsignedToWire (unsigned: UnsignedMessage): JsonObject {
  if (unsigned.kind === 'request') {
    return {
      from: encodeBase64Url(unsigned.from),
      to: encodeBase64Url(unsigned.to),
      nonce: encodeBase64Url(unsigned.nonce),
      expires: unsigned.expires,
      body: unsigned.body
    }
  }
  if (unsigned.kind === 'trimmed-response') {
    return {
      from: encodeBase64Url(unsigned.from),
      to: encodeBase64Url(unsigned.to),
      body: unsigned.body
    }
  }
  return {
    from: encodeBase64Url(unsigned.from),
    to: encodeBase64Url(unsigned.to),
    reply_to: encodeBase64Url(unsigned.replyTo),
    body: unsigned.body
  }
}

export function signedToWire (unsigned: UnsignedMessage, signature: Uint8Array): JsonObject {
  parseDerSignature(signature)
  return { ...unsignedToWire(unsigned), sig: encodeBase64Url(signature) }
}

export function signingBytes (unsigned: UnsignedMessage): Uint8Array {
  const canonical = canonicalize(unsignedToWire(unsigned))
  const prefix = utf8(signingPrefixOf(unsigned))
  const bytes = new Uint8Array(prefix.length + canonical.length)
  bytes.set(prefix)
  bytes.set(canonical, prefix.length)
  return bytes
}

/** The request id is the digest of the same bytes the signature covers. */
export function requestIdOf (unsigned: UnsignedRequest): string {
  return encodeBase64Url(sha256Bytes(signingBytes(unsigned)))
}

export function encodeEnvelopeBytes (unsigned: UnsignedMessage, signature: Uint8Array): Uint8Array {
  return canonicalize(signedToWire(unsigned, signature))
}

function assertPlainObject (value: JsonValue, missing: string): JsonObject {
  if (isJsonObject(value) === false) {
    throw new RoundtripError('ERR_ENVELOPE_NOT_OBJECT', 'envelope must be a JSON object')
  }
  return value
}

function assertFields (value: JsonObject, allowed: readonly string[], code: 'ERR_ENVELOPE_FIELD_MISSING' | 'ERR_ENVELOPE_FIELD_UNKNOWN' | 'ERR_ENVELOPE_SHAPE'): void {
  for (const field of allowed) {
    if (Object.prototype.hasOwnProperty.call(value, field) !== true) {
      if (code === 'ERR_ENVELOPE_FIELD_UNKNOWN') {
        throw new RoundtripError(code, `envelope must not carry ${field}`)
      }
      throw new RoundtripError(code, `envelope is missing ${field}`)
    }
  }
  for (const key of Object.keys(value)) {
    if (allowed.includes(key) !== true) {
      throw new RoundtripError('ERR_ENVELOPE_FIELD_UNKNOWN', `envelope has an unknown top level field: ${key}`)
    }
  }
}

function readStringField (value: JsonObject, field: string): string {
  const raw = value[field]
  if (typeof raw !== 'string') {
    throw new RoundtripError('ERR_ENVELOPE_FIELD_TYPE', `${field} must be a string`)
  }
  return raw
}

function readPublicKeyField (value: JsonObject, field: string): Uint8Array {
  const bytes = decodeBase64Url(readStringField(value, field), 'ERR_PUBLIC_KEY')
  if (bytes.length !== PUBLIC_KEY_BYTES) {
    throw new RoundtripError('ERR_PUBLIC_KEY', `${field} must be a ${PUBLIC_KEY_BYTES} byte compressed SEC1 key`)
  }
  try {
    return validatePublicKey(bytes)
  } catch (error) {
    if (error instanceof RoundtripError) throw error
    throw new RoundtripError('ERR_PUBLIC_KEY', `${field} is not a valid secp256k1 point`)
  }
}

function readSignatureField (value: JsonObject): Uint8Array {
  const signature = decodeBase64Url(readStringField(value, 'sig'), 'ERR_SIGNATURE_FORMAT')
  parseDerSignature(signature)
  return signature
}

function readRequestBody (value: JsonValue): JsonValue {
  if (isJsonObject(value) === false) {
    throw new RoundtripError('ERR_BODY', 'request body must be a JSON object')
  }
  const op = value.op
  if (typeof op !== 'string' || op.length === 0) {
    throw new RoundtripError('ERR_BODY', 'request body must carry a non empty string op')
  }
  return value
}

/**
 * Strict reader for a signed request.
 *
 * The shape is fixed: exactly `from, to, nonce, expires, body, sig`. There is
 * no `reply_to`, no `type`, no `id` and no `version`; an unknown top level
 * field is a protocol error instead of something to ignore.
 */
export function parseRequest (value: JsonValue): RequestEnvelope {
  const record = assertPlainObject(value, 'request')
  assertFields(record, REQUEST_FIELDS, 'ERR_ENVELOPE_FIELD_MISSING')
  const nonce = decodeBase64Url(readStringField(record, 'nonce'), 'ERR_NONCE')
  if (nonce.length < MIN_NONCE_BYTES || nonce.length > MAX_NONCE_BYTES) {
    throw new RoundtripError('ERR_NONCE', `nonce must be ${MIN_NONCE_BYTES}..${MAX_NONCE_BYTES} bytes`)
  }
  const expires = record.expires
  if (typeof expires !== 'number' || Number.isInteger(expires) !== true) {
    throw new RoundtripError('ERR_EXPIRES', 'expires must be an integer number of unix seconds')
  }
  if (expires < 0 || expires > MAX_SAFE_INTEGER) {
    throw new RoundtripError('ERR_EXPIRES', 'expires is out of range')
  }
  const unsigned: UnsignedRequest = {
    kind: 'request',
    from: readPublicKeyField(record, 'from'),
    to: readPublicKeyField(record, 'to'),
    nonce,
    expires,
    body: readRequestBody(record.body)
  }
  return { unsigned, signature: readSignatureField(record) }
}

/** Strict reader for a signed base response. */
export function parseResponse (value: JsonValue): ResponseEnvelope {
  const record = assertPlainObject(value, 'response')
  assertFields(record, RESPONSE_FIELDS, 'ERR_ENVELOPE_FIELD_MISSING')
  const replyTo = decodeBase64Url(readStringField(record, 'reply_to'), 'ERR_REPLY_TO')
  if (replyTo.length !== DIGEST_BYTES) {
    throw new RoundtripError('ERR_REPLY_TO', `reply_to must be a ${DIGEST_BYTES} byte digest`)
  }
  const body = assertResponseBody(record.body)
  const unsigned: UnsignedResponse = {
    kind: 'response',
    from: readPublicKeyField(record, 'from'),
    to: readPublicKeyField(record, 'to'),
    replyTo,
    body
  }
  return { unsigned, signature: readSignatureField(record) }
}

/**
 * Strict reader for the optional trimmed response: exactly `from, to, body, sig`.
 *
 * It is a separate reader on purpose. `reply_to` is refused here, and this shape
 * is refused by `parseRequest` and `parseResponse`, so a trimmed response can
 * never be accepted as a base message or the other way round.
 */
export function parseTrimmedResponse (value: JsonValue): TrimmedResponseEnvelope {
  const record = assertPlainObject(value, 'trimmed response')
  assertFields(record, TRIMMED_RESPONSE_FIELDS, 'ERR_ENVELOPE_FIELD_MISSING')
  const body = assertResponseBody(record.body)
  const unsigned: UnsignedTrimmedResponse = {
    kind: 'trimmed-response',
    from: readPublicKeyField(record, 'from'),
    to: readPublicKeyField(record, 'to'),
    body
  }
  return { unsigned, signature: readSignatureField(record) }
}

export interface TrimmedResponseExpectation {
  /** This node's own identity; the response must be addressed to it. */
  to: Uint8Array
  /** The peer the call was addressed to; the response must come from it. */
  from: Uint8Array
}

/**
 * Reads and verifies a trimmed response, and returns its business body.
 *
 * There is deliberately no request id to check: with `reply_to` gone, the
 * signature no longer proves which request this answers. The correlation belongs
 * to the trusted transport, so the caller has to be sure the bytes came from the
 * call it is completing. `from` and `to` are still enforced here, because a
 * signed identity is not a substitute for either of them.
 */
export function verifyTrimmedResponse (value: JsonValue, expected: TrimmedResponseExpectation): JsonValue {
  const envelope = parseTrimmedResponse(value)
  const unsigned = envelope.unsigned
  if (equalBytes(unsigned.to, expected.to) !== true) {
    throw new RoundtripError('ERR_RESPONSE_TO', 'response is not addressed to this identity')
  }
  if (equalBytes(unsigned.from, expected.from) !== true) {
    throw new RoundtripError('ERR_RESPONSE_FROM', 'response did not come from the requested peer')
  }
  try {
    verifyDigest(unsigned.from, sha256Bytes(signingBytes(unsigned)), envelope.signature)
  } catch (error) {
    if (error instanceof RoundtripError && error.code === 'ERR_SIGNATURE') {
      throw new RoundtripError('ERR_RESPONSE_SIGNATURE', error.message, { cause: error })
    }
    throw error
  }
  return unsigned.body
}

/**
 * A base response body is `{"ok":true,"result":...}` or
 * `{"ok":false,"error":{"code":"...","message":"..."}}`. Nothing else: the
 * caller must be able to tell a signed business failure from a transport
 * error page.
 */
export function assertResponseBody (value: JsonValue): JsonObject {
  if (isJsonObject(value) === false) {
    throw new RoundtripError('ERR_RESPONSE_SHAPE', 'response body must be a JSON object')
  }
  const ok = value.ok
  if (typeof ok !== 'boolean') {
    throw new RoundtripError('ERR_RESPONSE_SHAPE', 'response body must carry a boolean ok')
  }
  if (ok === true) {
    if (Object.prototype.hasOwnProperty.call(value, 'result') !== true) {
      throw new RoundtripError('ERR_RESPONSE_SHAPE', 'a successful response must carry result')
    }
    for (const key of Object.keys(value)) {
      if (key !== 'ok' && key !== 'result') {
        throw new RoundtripError('ERR_RESPONSE_SHAPE', `a successful response has an unexpected field: ${key}`)
      }
    }
    return value
  }
  if (Object.prototype.hasOwnProperty.call(value, 'result') === true) {
    throw new RoundtripError('ERR_RESPONSE_SHAPE', 'a failed response must not carry result')
  }
  const error = value.error
  if (isJsonObject(error) === false) {
    throw new RoundtripError('ERR_RESPONSE_SHAPE', 'a failed response must carry an error object')
  }
  for (const key of Object.keys(error)) {
    if (key !== 'code' && key !== 'message') {
      throw new RoundtripError('ERR_RESPONSE_SHAPE', `error has an unexpected field: ${key}`)
    }
  }
  if (typeof error.code !== 'string' || error.code.length === 0) {
    throw new RoundtripError('ERR_RESPONSE_SHAPE', 'error.code must be a non empty string')
  }
  if (typeof error.message !== 'string') {
    throw new RoundtripError('ERR_RESPONSE_SHAPE', 'error.message must be a string')
  }
  return value
}

export function outcomeToBody (outcome: { ok: true, result: JsonValue } | { ok: false, error: BusinessError }): JsonObject {
  if (outcome.ok) return { ok: true, result: outcome.result }
  return { ok: false, error: { code: outcome.error.code, message: outcome.error.message } }
}

export function bodyToOutcome (body: JsonValue): { ok: true, result: JsonValue } | { ok: false, error: BusinessError } {
  const record = assertResponseBody(body)
  if (record.ok === true) return { ok: true, result: record.result }
  const error = record.error as JsonObject
  return { ok: false, error: { code: error.code as string, message: error.message as string } }
}
