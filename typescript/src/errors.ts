/**
 * Stable error codes. The Go implementation mirrors this list one-to-one so a
 * test can assert the same rejection reason in both languages.
 */
export const ROUNDTRIP_ERROR_CODES = [
  'ERR_JSON_INPUT',
  'ERR_JSON_SYNTAX',
  'ERR_JSON_DUPLICATE_KEY',
  'ERR_JSON_STRING',
  'ERR_JSON_NUMBER',
  'ERR_JSON_DEPTH',
  'ERR_ENVELOPE_NOT_OBJECT',
  'ERR_ENVELOPE_FIELD_MISSING',
  'ERR_ENVELOPE_FIELD_UNKNOWN',
  'ERR_ENVELOPE_FIELD_TYPE',
  'ERR_ENVELOPE_SHAPE',
  'ERR_PUBLIC_KEY',
  'ERR_NONCE',
  'ERR_EXPIRES',
  'ERR_REPLY_TO',
  'ERR_SIGNATURE_FORMAT',
  'ERR_BODY',
  'ERR_MESSAGE_TOO_LARGE',
  'ERR_SIGNATURE',
  'ERR_RECIPIENT',
  'ERR_EXPIRED',
  'ERR_EXPIRY_WINDOW',
  'ERR_REPLAYED',
  'ERR_CALL_TIMEOUT',
  'ERR_CALL_ABORTED',
  'ERR_TRANSPORT',
  'ERR_RESPONSE_SIZE',
  'ERR_RESPONSE_FROM',
  'ERR_RESPONSE_TO',
  'ERR_RESPONSE_REPLY_TO',
  'ERR_RESPONSE_SIGNATURE',
  'ERR_RESPONSE_SHAPE',
  'ERR_SIGNER_KEY',
  'ERR_SIGNER_FAILED',
  'ERR_CALLER_IDENTITY',
  'ERR_NO_HANDLER',
  'ERR_FRAME',
  'ERR_HTTP_STATUS'
] as const

export type RoundtripErrorCode = (typeof ROUNDTRIP_ERROR_CODES)[number]

export class RoundtripError extends Error {
  readonly code: RoundtripErrorCode

  constructor (code: RoundtripErrorCode, message: string, options: { cause?: unknown } = {}) {
    super(message, { cause: options.cause })
    this.name = 'RoundtripError'
    this.code = code
  }
}

export function isRoundtripError (value: unknown): value is RoundtripError {
  return value instanceof RoundtripError
}

export function throwIfAborted (signal?: AbortSignal): void {
  if (signal?.aborted !== true) return
  const reason: unknown = signal.reason
  if (reason instanceof RoundtripError) throw reason
  throw new RoundtripError('ERR_CALL_ABORTED', reason instanceof Error ? reason.message : 'call aborted', { cause: reason })
}
