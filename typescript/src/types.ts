/** JSON value model shared with the Go implementation. */
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }

/** A JSON object without inherited prototype, so `__proto__` stays a plain key. */
export type JsonObject = { [key: string]: JsonValue }

export function isJsonObject (value: JsonValue): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Business level error carried inside a signed response body. */
export interface BusinessError {
  code: string
  message: string
}

export type HandlerOutcome =
  | { ok: true, result: JsonValue }
  | { ok: false, error: BusinessError }
