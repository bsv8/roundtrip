import { parseJsonText } from '../src/json.js'
import { canonicalizeToString } from '../src/jcs.js'
import { RoundtripError } from '../src/errors.js'

export interface VectorNumber {
  /** IEEE 754 bit pattern, as printed in RFC 8785 Appendix B. */
  ieee754Hex: string
  /** The JSON literal a producer may have written. */
  value: string
  /** The ECMAScript compatible serialization required by RFC 8785. */
  expected: string
  comment?: string
}

export interface VectorJcs {
  name: string
  input: string
  expected: string
}

export interface VectorKey {
  name: string
  privateKeyHex: string
  publicKeyHex: string
  publicKeyBase64Url: string
}

export interface VectorMessage {
  name: string
  /** Which message kind this vector pins down. */
  kind: 'request' | 'response' | 'trimmed-response'
  /** Unsigned message, in the same shape the implementation uses internally. */
  unsigned: {
    from: string
    to: string
    nonce?: string
    expires?: number
    reply_to?: string
    body: unknown
  }
  /** Canonical JSON of the object that is hashed. */
  wire: string
  /** UTF8("roundtrip/v1\n") || JCS(unsigned). */
  signingBytesHex: string
  digestHex: string
  /** base64url(SHA256(signing bytes)); requests only. */
  requestId?: string
  signatureBase64Url: string
  signatureHex: string
  /** Canonical JSON of the complete signed envelope. */
  envelope: string
  /** base64url of the envelope bytes, ready to put on a transport. */
  messageBase64Url: string
}

/** Inputs both implementations must refuse, with the shared error code. */
export interface VectorReject {
  name: string
  input: string
  code: string
}

export interface Vectors {
  version: string
  protocolPrefix: string
  /** The second, separate prefix for the optional trimmed response. */
  trimmedResponsePrefix: string
  generator: string
  keys: VectorKey[]
  rfc8785: { input: string, expected: string }
  numbers: VectorNumber[]
  jcs: VectorJcs[]
  reject: VectorReject[]
  requests: VectorMessage[]
  responses: VectorMessage[]
  trimmedResponses: VectorMessage[]
}

/** RFC 8785 Appendix B, copied verbatim. */
export const RFC8785_NUMBERS: VectorNumber[] = [
  { ieee754Hex: '0000000000000000', value: '0', expected: '0', comment: 'Zero' },
  { ieee754Hex: '8000000000000000', value: '-0', expected: '0', comment: 'Minus zero' },
  { ieee754Hex: '0000000000000001', value: '5e-324', expected: '5e-324', comment: 'Min pos number' },
  { ieee754Hex: '8000000000000001', value: '-5e-324', expected: '-5e-324', comment: 'Min neg number' },
  { ieee754Hex: '7fefffffffffffff', value: '1.7976931348623157e+308', expected: '1.7976931348623157e+308', comment: 'Max pos number' },
  { ieee754Hex: 'ffefffffffffffff', value: '-1.7976931348623157e+308', expected: '-1.7976931348623157e+308', comment: 'Max neg number' },
  { ieee754Hex: '4340000000000000', value: '9007199254740992', expected: '9007199254740992', comment: 'Max pos int' },
  { ieee754Hex: 'c340000000000000', value: '-9007199254740992', expected: '-9007199254740992', comment: 'Max neg int' },
  { ieee754Hex: '4430000000000000', value: '295147905179352830000', expected: '295147905179352830000', comment: '~2**68' },
  { ieee754Hex: '44b52d02c7e14af5', value: '9.999999999999997e+22', expected: '9.999999999999997e+22' },
  { ieee754Hex: '44b52d02c7e14af6', value: '1e+23', expected: '1e+23' },
  { ieee754Hex: '44b52d02c7e14af7', value: '1.0000000000000001e+23', expected: '1.0000000000000001e+23' },
  { ieee754Hex: '444b1ae4d6e2ef4e', value: '999999999999999700000', expected: '999999999999999700000' },
  { ieee754Hex: '444b1ae4d6e2ef4f', value: '999999999999999900000', expected: '999999999999999900000' },
  { ieee754Hex: '444b1ae4d6e2ef50', value: '1e+21', expected: '1e+21' },
  { ieee754Hex: '3eb0c6f7a0b5ed8c', value: '9.999999999999997e-7', expected: '9.999999999999997e-7' },
  { ieee754Hex: '3eb0c6f7a0b5ed8d', value: '0.000001', expected: '0.000001' },
  { ieee754Hex: '41b3de4355555553', value: '333333333.3333332', expected: '333333333.3333332' },
  { ieee754Hex: '41b3de4355555554', value: '333333333.33333325', expected: '333333333.33333325' },
  { ieee754Hex: '41b3de4355555555', value: '333333333.3333333', expected: '333333333.3333333' },
  { ieee754Hex: '41b3de4355555556', value: '333333333.3333334', expected: '333333333.3333334' },
  { ieee754Hex: '41b3de4355555557', value: '333333333.33333343', expected: '333333333.33333343' },
  { ieee754Hex: 'becbf647612f3696', value: '-0.0000033333333333333333', expected: '-0.0000033333333333333333' },
  { ieee754Hex: '43143ff3c1cb0959', value: '1424953923781206.2', expected: '1424953923781206.2', comment: 'Round to even' }
]

/** RFC 8785 Sections 3.2.2 and 3.2.3, copied verbatim. */
export const RFC8785_EXAMPLE = {
  input: '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}',
  expected: '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
}

export const JCS_CASES: VectorJcs[] = [
  {
    name: 'whitespace and key order do not matter',
    input: '{ "to" : "b" ,\n  "from":"a" ,\t"body":{"z":1,"a":2} }',
    expected: '{"body":{"a":2,"z":1},"from":"a","to":"b"}'
  },
  {
    name: 'array order is significant',
    input: '{"list":[3,1,2,{"b":1,"a":0}]}',
    expected: '{"list":[3,1,2,{"a":0,"b":1}]}'
  },
  {
    name: 'nested objects are sorted recursively',
    input: '{"b":{"d":[{"y":1,"x":2}],"c":true},"a":null}',
    expected: '{"a":null,"b":{"c":true,"d":[{"x":2,"y":1}]}}'
  },
  {
    name: 'control characters use the short escapes and lowercase \\u',
    input: '{"s":"\\u0000\\b\\t\\n\\f\\r\\u000f\\u001f\\u000b"}',
    expected: '{"s":"\\u0000\\b\\t\\n\\f\\r\\u000f\\u001f\\u000b"}'
  },
  {
    name: 'quote and backslash are escaped, solidus is not',
    input: '{"s":"\\"\\\\\\/"}',
    expected: '{"s":"\\"\\\\/"}'
  },
  {
    name: 'non ascii stays literal, no unicode normalization',
    input: '{"\\u00e9":"caf\\u00e9","\\ud83d\\ude00":"emoji"}',
    expected: '{"é":"café","😀":"emoji"}'
  },
  {
    name: 'keys sort by UTF-16 code units, so an astral key sorts before U+FFFD',
    input: '{"\\ufffd":1,"\\ud83d\\ude00":2,"a":3,"A":4,"":5,"aa":6}',
    expected: '{"":5,"A":4,"a":3,"aa":6,"😀":2,"�":1}'
  },
  {
    name: 'primitives only',
    input: '{"t":true,"f":false,"n":null,"s":"x"}',
    expected: '{"f":false,"n":null,"s":"x","t":true}'
  },
  {
    name: 'numbers inside a body',
    input: '{"a":[0,-0,1e21,1e-7,0.1,1.0,100,3.141592653589793]}',
    expected: '{"a":[0,0,1e+21,1e-7,0.1,1,100,3.141592653589793]}'
  }
]

export interface RejectCase {
  name: string
  input: string
  code: string
}

/** Inputs both implementations must refuse, with the shared error code. */
export const REJECT_CASES: RejectCase[] = [
  { name: 'duplicate object key', input: '{"a":1,"a":2}', code: 'ERR_JSON_DUPLICATE_KEY' },
  { name: 'duplicate nested key', input: '{"x":{"a":1,"a":2}}', code: 'ERR_JSON_DUPLICATE_KEY' },
  { name: 'escaped and plain spelling of one key', input: '{"\\u0061b":1,"ab":2}', code: 'ERR_JSON_DUPLICATE_KEY' },
  { name: 'trailing content', input: '{"a":1} {}', code: 'ERR_JSON_SYNTAX' },
  { name: 'trailing comma', input: '{"a":1,}', code: 'ERR_JSON_SYNTAX' },
  { name: 'leading zero', input: '{"a":01}', code: 'ERR_JSON_SYNTAX' },
  { name: 'plus sign', input: '{"a":+1}', code: 'ERR_JSON_SYNTAX' },
  { name: 'hex number', input: '{"a":0x10}', code: 'ERR_JSON_SYNTAX' },
  { name: 'bare dot', input: '{"a":.5}', code: 'ERR_JSON_SYNTAX' },
  { name: 'exponent without digits', input: '{"a":1e}', code: 'ERR_JSON_SYNTAX' },
  { name: 'raw control character', input: '{"a":"x\u0001y"}', code: 'ERR_JSON_STRING' },
  { name: 'lone high surrogate', input: '{"a":"\\ud83d"}', code: 'ERR_JSON_STRING' },
  { name: 'lone low surrogate', input: '{"a":"\\ude00"}', code: 'ERR_JSON_STRING' },
  { name: 'surrogate pair split by text', input: '{"a":"\\ud83dx\\ude00"}', code: 'ERR_JSON_STRING' },
  { name: 'single quotes', input: "{'a':1}", code: 'ERR_JSON_SYNTAX' },
  { name: 'unquoted key', input: '{a:1}', code: 'ERR_JSON_SYNTAX' },
  { name: 'number overflow to infinity', input: '{"a":1e400}', code: 'ERR_JSON_NUMBER' },
  { name: 'truncated object', input: '{"a":', code: 'ERR_JSON_SYNTAX' },
  { name: 'empty input', input: '', code: 'ERR_JSON_SYNTAX' },
  { name: 'nesting too deep', input: `${'['.repeat(70)}${']'.repeat(70)}`, code: 'ERR_JSON_DEPTH' },
  { name: 'bad escape', input: '{"a":"\\x41"}', code: 'ERR_JSON_SYNTAX' },
  { name: 'truncated unicode escape', input: '{"a":"\\u00"}', code: 'ERR_JSON_SYNTAX' }
]

export function runGenerator (): Vectors {
  const keys: VectorKey[] = []
  for (const name of ['alice', 'bob', 'carol', 'mallory', 'one', 'orderMinusOne']) {
    keys.push(keyVector(name))
  }
  return {
    version: 'roundtrip-vectors-v1',
    protocolPrefix: 'roundtrip/v1\n',
    trimmedResponsePrefix: 'roundtrip/http-response/v1\n',
    generator: 'typescript/scripts/generate-vectors.ts',
    keys,
    rfc8785: RFC8785_EXAMPLE,
    numbers: RFC8785_NUMBERS,
    jcs: JCS_CASES,
    reject: REJECT_CASES,
    requests: [],
    responses: [],
    trimmedResponses: []
  }
}

/** Self check: the generated data must agree with the RFC text and with the reader. */
export function verifyGenerated (vectors: Vectors): void {
  const canonicalExample = canonicalizeToString(parseJsonText(vectors.rfc8785.input))
  if (canonicalExample !== vectors.rfc8785.expected) {
    throw new Error(`RFC 8785 example mismatch:\n  got      ${canonicalExample}\n  expected ${vectors.rfc8785.expected}`)
  }
  for (const entry of vectors.numbers) {
    const value = parseJsonText(entry.value)
    const actual = canonicalizeToString(value)
    if (actual !== entry.expected) {
      throw new Error(`RFC 8785 number ${entry.value} serialized as ${actual}, expected ${entry.expected}`)
    }
  }
  for (const entry of vectors.jcs) {
    const actual = canonicalizeToString(parseJsonText(entry.input))
    if (actual !== entry.expected) {
      throw new Error(`JCS case ${entry.name} produced ${actual}, expected ${entry.expected}`)
    }
  }
  for (const entry of REJECT_CASES) {
    let code = ''
    try {
      parseJsonText(entry.input)
    } catch (error) {
      code = error instanceof RoundtripError ? error.code : 'UNKNOWN'
    }
    if (code !== entry.code) {
      throw new Error(`reject case ${entry.name} produced ${code}, expected ${entry.code}`)
    }
  }
}

function keyVector (name: string): VectorKey {
  const { testPrivateKey, testPublicKey } = requireFixtures()
  const privateKey = testPrivateKey(name)
  const publicKey = testPublicKey(name)
  return {
    name,
    privateKeyHex: toHex(privateKey),
    publicKeyHex: toHex(publicKey),
    publicKeyBase64Url: base64Url(publicKey)
  }
}

let fixtures: { testPrivateKey: (name: string) => Uint8Array, testPublicKey: (name: string) => Uint8Array } | null = null

function requireFixtures (): { testPrivateKey: (name: string) => Uint8Array, testPublicKey: (name: string) => Uint8Array } {
  if (fixtures == null) throw new Error('call installFixtures() first')
  return fixtures
}

export function installFixtures (value: { testPrivateKey: (name: string) => Uint8Array, testPublicKey: (name: string) => Uint8Array }): void {
  fixtures = value
}

function toHex (bytes: Uint8Array): string {
  let result = ''
  for (const byte of bytes) result += byte.toString(16).padStart(2, '0')
  return result
}

function base64Url (bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url')
}
