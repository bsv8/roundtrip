export {
  ROUNDTRIP_ERROR_CODES,
  RoundtripError,
  isRoundtripError,
  type RoundtripErrorCode
} from './errors.js'

export type { JsonObject, JsonValue, BusinessError, HandlerOutcome } from './types.js'

export { MAX_JSON_DEPTH, MAX_SAFE_INTEGER, decodeUtf8, parseJsonBytes, parseJsonText } from './json.js'
export { canonicalize, canonicalizeToString } from './jcs.js'
export {
  bytesToHex,
  concatBytes,
  decodeBase64Url,
  encodeBase64Url,
  equalBytes,
  hexToBytes,
  utf8
} from './bytes.js'
export {
  SECP256K1_ORDER,
  parseDerSignature,
  publicKeyFromPrivateKey,
  sha256Bytes,
  signDigest,
  validatePrivateKey,
  validatePublicKey,
  verifyDigest,
  type DerSignature
} from './crypto.js'
export {
  DIGEST_BYTES,
  MAX_NONCE_BYTES,
  MIN_NONCE_BYTES,
  PUBLIC_KEY_BYTES,
  SIGNING_PREFIX,
  TRIMMED_RESPONSE_PREFIX,
  assertResponseBody,
  bodyToOutcome,
  encodeEnvelopeBytes,
  isRequest,
  isTrimmedResponse,
  outcomeToBody,
  parseRequest,
  parseResponse,
  parseTrimmedResponse,
  requestIdOf,
  signedToWire,
  signingBytes,
  signingPrefixOf,
  unsignedToWire,
  verifyTrimmedResponse,
  type RequestEnvelope,
  type ResponseEnvelope,
  type TrimmedResponseEnvelope,
  type TrimmedResponseExpectation,
  type UnsignedMessage,
  type UnsignedRequest,
  type UnsignedResponse,
  type UnsignedTrimmedResponse
} from './envelope.js'
export { LocalRoundtripSigner, digestOf, type RoundtripSigner } from './signer.js'
export { MemoryReplayGuard, type ReplayCapabilities, type ReplayClaim, type ReplayGuard } from './replay.js'
export {
  DEFAULT_CALL_TIMEOUT_MS,
  DEFAULT_CLOCK_SKEW_SECONDS,
  DEFAULT_MAX_MESSAGE_BYTES,
  DEFAULT_MAX_REQUEST_TTL_SECONDS,
  DEFAULT_REQUEST_TTL_SECONDS,
  HANDLER_ERROR_CODE,
  REPLAY_ERROR_CODE,
  RoundtripCore,
  publicKeyToString,
  resolvePublicKey,
  type BuildRequestOptions,
  type CallInput,
  type CallOutcome,
  type CoreConfig,
  type Exchange,
  type HandleOptions,
  type HandlerContext,
  type PreparedRequest,
  type ProcessedRequest,
  type RoundtripHandler
} from './core.js'
export {
  HTTP_CONTENT_TYPE,
  HTTP_PATH,
  createHttpEndpoint,
  toNodeHandler,
  type HttpEndpoint,
  type HttpEndpointOptions,
  type HttpRequestView,
  type HttpResponseView
} from './http/endpoint.js'
export { httpExchange, type HttpExchangeOptions } from './http/client.js'
export {
  ROUNDTRIP_PROTOCOL,
  libp2pExchange,
  serveLibp2p,
  type Libp2pAdapterOptions
} from './libp2p/index.js'
