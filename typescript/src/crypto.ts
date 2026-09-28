import { schnorr, secp256k1 as secp } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { RoundtripError } from './errors.js'
import { bytesToHex, equalBytes } from './bytes.js'

/** secp256k1 group order. */
export const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const HALF_ORDER = SECP256K1_ORDER / 2n
const HALF_ORDER_HEX = HALF_ORDER.toString(16).padStart(64, '0')

/** One SHA-256 over the signed bytes, then ECDSA over that digest. */
export function sha256Bytes (bytes: Uint8Array): Uint8Array {
  return sha256(bytes)
}

export function validatePrivateKey (privateKey: Uint8Array): Uint8Array {
  if (privateKey.length !== 32) {
    throw new RoundtripError('ERR_SIGNER_KEY', 'private key must be exactly 32 bytes')
  }
  try {
    secp.getPublicKey(privateKey, true)
  } catch (cause) {
    throw new RoundtripError('ERR_SIGNER_KEY', 'private key scalar is outside 1..n-1', { cause })
  }
  return new Uint8Array(privateKey)
}

export function publicKeyFromPrivateKey (privateKey: Uint8Array): Uint8Array {
  return new Uint8Array(secp.getPublicKey(validatePrivateKey(privateKey), true))
}

export function validatePublicKey (publicKey: Uint8Array): Uint8Array {
  if (publicKey.length !== 33 || (publicKey[0] !== 0x02 && publicKey[0] !== 0x03)) {
    throw new RoundtripError('ERR_PUBLIC_KEY', 'public key must be a compressed 33-byte SEC1 point')
  }
  try {
    const decoded = schnorr.Point.fromHex(bytesToHex(publicKey)).toBytes(true)
    if (equalBytes(decoded, publicKey) === false) {
      throw new Error('public key is not the canonical compressed encoding of its point')
    }
  } catch (cause) {
    throw new RoundtripError('ERR_PUBLIC_KEY', 'public key is not a valid secp256k1 point', { cause })
  }
  return new Uint8Array(publicKey)
}

/**
 * RFC 6979 deterministic ECDSA over `digest`, strict DER and low-S.
 *
 * The nonce is derived from the private key and the digest only, so both
 * implementations in this repository produce the same bytes for the same
 * vector; that is what the shared test data pins down.
 */
export function signDigest (privateKey: Uint8Array, digest: Uint8Array): Uint8Array {
  if (digest.length !== 32) {
    throw new RoundtripError('ERR_SIGNER_FAILED', 'digest must be 32 bytes')
  }
  const signature = new Uint8Array(secp.sign(digest, validatePrivateKey(privateKey), {
    prehash: false,
    lowS: true,
    format: 'der'
  }))
  parseDerSignature(signature)
  return signature
}

export interface DerSignature {
  r: bigint
  s: bigint
}

/** Strict DER reader: minimal lengths, positive integers, low-S, in range. */
export function parseDerSignature (signature: Uint8Array): DerSignature {
  const fail = (message: string): never => {
    throw new RoundtripError('ERR_SIGNATURE_FORMAT', message)
  }
  if (signature.length < 8 || signature.length > 72) fail('DER signature length is out of range')
  if (signature[0] !== 0x30) fail('DER sequence tag is missing')
  if (signature[1] !== signature.length - 2) fail('DER sequence length is not strict')
  let offset = 2
  const readInteger = (): bigint => {
    if (signature[offset++] !== 0x02) fail('DER integer tag is missing')
    const length = signature[offset++]
    if (length === undefined || length === 0 || length > 33 || offset + length > signature.length) {
      fail('DER integer length is malformed')
    }
    if ((signature[offset] & 0x80) !== 0) fail('DER integer is negative')
    if (signature[offset] === 0x00 && (length === 1 || (signature[offset + 1] & 0x80) === 0)) {
      fail('DER integer is not minimally encoded')
    }
    let value = 0n
    for (let index = 0; index < length; index++) {
      value = (value << 8n) | BigInt(signature[offset + index])
    }
    offset += length
    return value
  }
  const r = readInteger()
  const s = readInteger()
  if (offset !== signature.length) fail('DER signature has trailing bytes')
  if (r <= 0n || r >= SECP256K1_ORDER) fail('DER r scalar is out of range')
  if (s <= 0n || s > HALF_ORDER) fail('DER s scalar is out of range or high-S')
  return { r, s }
}

export function isLowS (s: bigint): boolean {
  return s <= HALF_ORDER
}

/** Strict DER to the fixed width `r || s` form the curve library verifies. */
export function derToCompact (signature: Uint8Array): Uint8Array {
  const { r, s } = parseDerSignature(signature)
  const compact = new Uint8Array(64)
  writeScalar(compact, 0, r)
  writeScalar(compact, 32, s)
  return compact
}

function writeScalar (target: Uint8Array, offset: number, value: bigint): void {
  let remaining = value
  for (let index = 31; index >= 0; index--) {
    target[offset + index] = Number(remaining & 0xffn)
    remaining >>= 8n
  }
}

export function halfOrderHex (): string {
  return HALF_ORDER_HEX
}

/** Throws `ERR_SIGNATURE` when `digest` was not signed by `publicKey`. */
export function verifyDigest (publicKey: Uint8Array, digest: Uint8Array, signature: Uint8Array): void {
  if (digest.length !== 32) {
    throw new RoundtripError('ERR_SIGNATURE', 'digest must be 32 bytes')
  }
  parseDerSignature(signature)
  const key = validatePublicKey(publicKey)
  const compact = derToCompact(signature)
  let valid = false
  try {
    valid = secp.verify(compact, digest, key, { prehash: false, lowS: true })
  } catch (cause) {
    throw new RoundtripError('ERR_SIGNATURE', 'signature verification failed', { cause })
  }
  if (valid !== true) {
    throw new RoundtripError('ERR_SIGNATURE', 'signature verification failed')
  }
}
