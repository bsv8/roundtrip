import { RoundtripError, throwIfAborted } from './errors.js'
import { publicKeyFromPrivateKey, sha256Bytes, signDigest } from './crypto.js'
import { signingBytes, type UnsignedMessage } from './envelope.js'
import { MIN_NONCE_BYTES } from './envelope.js'

/**
 * The only capability the core needs. The core never sees a private key, and it
 * never accepts arbitrary bytes: a signer is handed a validated unsigned
 * request or unsigned response and returns a signature over exactly those
 * fields. The implementation stays responsible for building the canonical bytes
 * inside its own trusted boundary.
 */
export interface RoundtripSigner {
  publicKey (): Uint8Array
  signRoundtrip (unsigned: UnsignedMessage, signal?: AbortSignal): Promise<Uint8Array>
}

/**
 * In-process signer for tests, examples and single process deployments.
 *
 * The private key never crosses the `RoundtripSigner` interface, and this class
 * is deliberately not meant for a browser or any untrusted environment. Keys
 * created for tests and examples are throw away material.
 */
export class LocalRoundtripSigner implements RoundtripSigner {
  readonly #privateKey: Uint8Array
  readonly #publicKey: Uint8Array

  constructor (privateKey: Uint8Array) {
    this.#publicKey = publicKeyFromPrivateKey(privateKey)
    this.#privateKey = new Uint8Array(privateKey)
  }

  publicKey (): Uint8Array {
    return new Uint8Array(this.#publicKey)
  }

  async signRoundtrip (unsigned: UnsignedMessage, signal?: AbortSignal): Promise<Uint8Array> {
    throwIfAborted(signal)
    // Re-check the shape inside the signer: a signer that validates nothing
    // would happily sign bytes the core never validated.
    assertSignable(unsigned)
    const digest = sha256Bytes(signingBytes(unsigned))
    const signature = signDigest(this.#privateKey, digest)
    throwIfAborted(signal)
    return signature
  }
}

function assertSignable (unsigned: UnsignedMessage): void {
  if (unsigned == null || (unsigned.kind !== 'request' && unsigned.kind !== 'response' && unsigned.kind !== 'trimmed-response')) {
    throw new RoundtripError('ERR_SIGNER_FAILED', 'signer only accepts a validated unsigned message')
  }
  if (unsigned.body === undefined) {
    throw new RoundtripError('ERR_SIGNER_FAILED', 'unsigned message must carry a body')
  }
  // Only a request carries a nonce. A base response quotes a request id and a
  // trimmed response quotes nothing, so neither has one to check.
  if (unsigned.kind === 'request' && unsigned.nonce.length < MIN_NONCE_BYTES) {
    throw new RoundtripError('ERR_SIGNER_FAILED', 'unsigned request must carry a nonce')
  }
  if (unsigned.from.length !== 33 || unsigned.to.length !== 33) {
    throw new RoundtripError('ERR_SIGNER_FAILED', 'unsigned message must carry 33-byte public keys')
  }
}

/**
 * Recomputes the digest of unsigned bytes; used by verification helpers.
 *
 * The prefix follows the message kind, so a trimmed response and a base response
 * with the same fields never share a digest.
 */
export function digestOf (unsigned: UnsignedMessage): Uint8Array {
  return sha256Bytes(signingBytes(unsigned))
}
