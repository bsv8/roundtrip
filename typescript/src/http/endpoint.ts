import type { IncomingMessage, ServerResponse } from 'node:http'
import { RoundtripError } from '../errors.js'
import type { RoundtripCore } from '../core.js'

export const HTTP_PATH = '/roundtrip'
export const HTTP_CONTENT_TYPE = 'application/json'

/** Transport neutral view of one HTTP request. */
export interface HttpRequestView {
  method: string
  path: string
  contentType?: string | undefined
  body: Uint8Array
}

export interface HttpResponseView {
  status: number
  contentType: string
  body: Uint8Array
}

export type HttpEndpoint = (request: HttpRequestView) => Promise<HttpResponseView>

export interface HttpEndpointOptions {
  /** Fixed entry path; the operation only comes from the signed `body.op`. */
  path?: string
}

/**
 * `POST <path>` with a signed request shell in and a signed response shell out.
 *
 * The HTTP request/response pair does not replace the signed correlation: the
 * response still carries `reply_to`, because anyone on a plain HTTP path can
 * swap an older validly signed response in front of the current call.
 */
export function createHttpEndpoint (core: RoundtripCore, options: HttpEndpointOptions = {}): HttpEndpoint {
  const path = options.path ?? HTTP_PATH
  return async (request: HttpRequestView): Promise<HttpResponseView> => {
    if (request.path !== path) {
      return errorResponse(404, 'NOT_FOUND', 'unknown entry path')
    }
    if (request.method !== 'POST') {
      return errorResponse(405, 'METHOD_NOT_ALLOWED', 'only POST is accepted')
    }
    if (request.contentType != null && request.contentType.split(';')[0]?.trim().toLowerCase() !== HTTP_CONTENT_TYPE) {
      return errorResponse(415, 'UNSUPPORTED_MEDIA_TYPE', 'content type must be application/json')
    }
    try {
      const bytes = await core.handle(request.body)
      return { status: 200, contentType: HTTP_CONTENT_TYPE, body: bytes }
    } catch (error) {
      if (error instanceof RoundtripError) {
        return errorResponse(statusForCode(error.code), error.code, error.message)
      }
      return errorResponse(500, 'INTERNAL', 'request could not be processed')
    }
  }
}

function statusForCode (code: string): number {
  switch (code) {
    case 'ERR_MESSAGE_TOO_LARGE':
    case 'ERR_RESPONSE_SIZE':
      return 413
    case 'ERR_RECIPIENT':
    case 'ERR_CALLER_IDENTITY':
      return 403
    case 'ERR_NO_HANDLER':
    case 'ERR_SIGNER_KEY':
    case 'ERR_SIGNER_FAILED':
      return 500
    default:
      return 400
  }
}

function errorResponse (status: number, code: string, message: string): HttpResponseView {
  // An unsigned status is an entry error. It must never look like a signed
  // business result, so the body carries no envelope fields at all.
  const body = new TextEncoder().encode(JSON.stringify({ error: { code, message } }))
  return { status, contentType: HTTP_CONTENT_TYPE, body }
}

/** Binds the endpoint to `node:http`. */
export function toNodeHandler (endpoint: HttpEndpoint, maxBodyBytes = 1024 * 1024) {
  return async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    const method = request.method ?? 'GET'
    const path = (request.url ?? '/').split('?')[0] ?? '/'
    let body: Uint8Array
    try {
      const read = await readBody(request, maxBodyBytes)
      if (read.tooLarge) {
        // The body is refused before it is parsed, but the caller still gets a
        // real answer: the connection is only dropped after the response is on
        // the wire, otherwise the client could not tell this apart from a
        // broken network.
        respond(response, errorResponse(413, 'ERR_MESSAGE_TOO_LARGE', 'request body exceeds the local limit'), true)
        return
      }
      body = read.body
    } catch (error) {
      respond(response, errorResponse(400, 'ERR_TRANSPORT', error instanceof Error ? error.message : 'the request could not be read'), true)
      return
    }
    const view = await endpoint({
      method,
      path,
      contentType: request.headers['content-type'],
      body
    })
    respond(response, view)
  }
}

function respond (response: ServerResponse, view: HttpResponseView, close = false): void {
  const headers: Record<string, string> = {
    'content-type': view.contentType,
    'content-length': String(view.body.length)
  }
  if (close === true) headers.connection = 'close'
  response.writeHead(view.status, headers)
  response.end(view.body)
}

/**
 * Buffers the body up to `maxBodyBytes`.
 *
 * The declared content length is checked first, so an oversized body is usually
 * refused before it is read at all. When the limit is only discovered while
 * reading, the accumulation stops but the connection is left alone: destroying
 * it here would swallow the 413 the caller needs.
 */
function readBody (request: IncomingMessage, maxBodyBytes: number): Promise<{ body: Uint8Array, tooLarge: false } | { tooLarge: true }> {
  const declared = Number(request.headers['content-length'])
  if (Number.isFinite(declared) && declared > maxBodyBytes) {
    return Promise.resolve({ tooLarge: true })
  }
  return new Promise((resolve, reject) => {
    const chunks: Uint8Array[] = []
    let total = 0
    let settled = false
    const cleanup = (): void => {
      request.off('data', onData)
      request.off('end', onEnd)
      request.off('error', onError)
      request.pause()
    }
    function onData (chunk: Uint8Array): void {
      total += chunk.length
      if (total > maxBodyBytes) {
        if (settled === true) return
        settled = true
        cleanup()
        resolve({ tooLarge: true })
        return
      }
      chunks.push(new Uint8Array(chunk))
    }
    function onEnd (): void {
      if (settled === true) return
      settled = true
      cleanup()
      const body = new Uint8Array(total)
      let offset = 0
      for (const chunk of chunks) {
        body.set(chunk, offset)
        offset += chunk.length
      }
      resolve({ body, tooLarge: false })
    }
    function onError (error: Error): void {
      if (settled === true) return
      settled = true
      cleanup()
      reject(error)
    }
    request.on('data', onData)
    request.on('end', onEnd)
    request.on('error', onError)
  })
}
