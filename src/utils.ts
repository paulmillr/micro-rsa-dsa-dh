/*! micro-rsa-dsa-dh - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { type TArg, type TRet } from '@noble/hashes/utils.js';
import {
  abytes,
  anumber,
  bytesToHex,
  hexToBytes,
  isBytes,
  randomBytes,
} from '@noble/hashes/utils.js';
export { type TArg, type TRet } from '@noble/hashes/utils.js';

/** Secure PRNG function like `randomBytes()` from `@noble/hashes/utils`. */
export type RandFn = (bytes: number) => TRet<Uint8Array>;

/** Hash function with noble-style metadata and incremental API. */
export type Hash = {
  /** Hash one message in a single call. */
  (message: TArg<Uint8Array>): TRet<Uint8Array>;
  /** Digest size in bytes. */
  outputLen: number;
  /** Internal compression block size in bytes. */
  blockLen: number;
  /**
   * Creates a fresh incremental hash instance.
   * @returns New hash object ready for `update(...).digest()`.
   */
  create: () => any;
};

/** Hex input accepted by this package. */
export type Hex = Uint8Array | string; // hex strings are accepted for simplicity

const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _2n = /* @__PURE__ */ BigInt(2);
const isPosBig = (n: bigint) => typeof n === 'bigint' && _0n <= n;
function abignumber(n: number | bigint) {
  if (typeof n === 'bigint') {
    if (!isPosBig(n)) throw new RangeError('positive bigint expected, got ' + n);
  } else anumber(n);
  return n;
}

/**
 * Takes hex string or Uint8Array, converts to Uint8Array.
 * Validates output length.
 * Will throw error for other types.
 * @param title - Descriptive title for an error, for example `private key`.
 * @param hex - Hex string or `Uint8Array`.
 * @param expectedLength - Optional output length to enforce.
 * @returns Normalized byte copy of the provided input.
 * @throws On wrong input types. {@link TypeError}
 * @throws On malformed hex input or wrong normalized byte length. {@link RangeError}
 * @example
 * Normalize hex into bytes before feeding it into crypto helpers.
 * ```ts
 * import { ensureBytes } from 'micro-rsa-dsa-dh/utils.js';
 * ensureBytes('msg', '0a0b');
 * ```
 */
export function ensureBytes(
  title: string,
  hex: TArg<Hex>,
  expectedLength?: number
): TRet<Uint8Array> {
  let res: Uint8Array;
  if (typeof hex === 'string') {
    try {
      res = hexToBytes(hex);
    } catch (e) {
      // Keep malformed hex as a value/range failure instead of flattening it to plain Error.
      throw new RangeError(`${title} must be valid hex string, got "${hex}". Cause: ${e}`);
    }
  } else if (isBytes(hex)) {
    // Uint8Array.from() instead of hash.slice() because node.js Buffer
    // is instance of Uint8Array, and its slice() creates **mutable** copy
    // Uint8Array.from() also guarantees a plain byte copy, so Buffer-backed
    // views cannot keep aliasing caller-owned memory after normalization.
    // Policy: use the exact noble-curves/noble-hashes isBytes semantics for
    // compatibility. Prototype-only spoofing can still reach this copy step
    // and be rejected by the native typed-array brand check.
    res = Uint8Array.from(hex);
  } else {
    throw new TypeError(`${title} must be hex string or Uint8Array`);
  }
  const len = res.length;
  if (typeof expectedLength === 'number' && len !== expectedLength)
    throw new RangeError(`${title} expected ${expectedLength} bytes, got ${len}`);
  return res as TRet<Uint8Array>;
}

/**
 * Integer-to-Octet-String Primitive (I2OSP)
 *
 * @param x - The nonnegative integer to be converted.
 * @param xLen - The intended length of the resulting octet string.
 * @returns The corresponding octet string of length xLen.
 * @throws On integers that do not fit into the requested output length. {@link RangeError}
 * @example
 * Serialize a bigint into a fixed-width big-endian byte array.
 * ```ts
 * import { I2OSP } from 'micro-rsa-dsa-dh/utils.js';
 * I2OSP(258n, 2);
 * ```
 */
export function I2OSP(x: bigint, xLen: number): TRet<Uint8Array> {
  // RFC 8017 §4.1 defines `x` as a "nonnegative integer to be converted";
  // step 1 separately rejects values that exceed the requested octet length.
  if (x < _0n) throw new RangeError('integer must be nonnegative');
  if (x >= _1n << BigInt(8 * xLen)) throw new RangeError('integer too large');
  if (xLen === 0) return new Uint8Array(0) as TRet<Uint8Array>; // x = 0 here
  // Native radix conversion is much faster than a per-byte bigint shift loop.
  return hexToBytes(x.toString(16).padStart(2 * xLen, '0')) as TRet<Uint8Array>;
}

/**
 * Octet String-to-Integer Primitive (OS2IP)
 *
 * @param X - The octet string to be converted.
 * @returns The corresponding nonnegative integer.
 * @example
 * Parse a big-endian byte array back into a bigint.
 * ```ts
 * import { OS2IP } from 'micro-rsa-dsa-dh/utils.js';
 * OS2IP(Uint8Array.from([1, 2]));
 * ```
 */
export function OS2IP(X: TArg<Uint8Array>): bigint {
  // RFC 8017 §4.2 takes an octet string `X`; use the noble-hashes byte assertion
  // so non-octet typed arrays cannot feed negative or wider-than-octet values here.
  X = abytes(X, undefined, 'OS2IP');
  // Native radix conversion is much faster than a per-byte bigint shift loop.
  return hexToNumber(bytesToHex(X));
}

/**
 * Efficiently raise num to power and do modular division.
 * Unsafe in some contexts: uses ladder, so can expose bigint bits.
 * @param num - Non-negative base value.
 * @param power - Non-negative exponent.
 * @param modulo - Positive modulus.
 * @returns `num ** power mod modulo`.
 * @throws On negative bases, negative powers, or non-positive moduli. {@link RangeError}
 * @example
 * Modular exponentiation used by RSA, DSA, and DH math.
 * ```ts
 * import { pow } from 'micro-rsa-dsa-dh/utils.js';
 * pow(2n, 6n, 11n) // 64n % 11n == 9n
 * ```
 */
export function pow(num: bigint, power: bigint, modulo: bigint): bigint {
  if (num < _0n || power < _0n || modulo <= _0n)
    throw new RangeError('Expected non-negative base/power and positive modulo');
  if (modulo === _1n) return _0n;
  // RFC 8017 RSA representatives are in [0, n - 1], and FIPS 186-5 B.3.1
  // Miller-Rabin bases satisfy 1 < b < w - 1; reject negative bases instead
  // of silently normalizing values outside those caller domains.
  let res = _1n;
  while (power > _0n) {
    if (power & _1n) res = (res * num) % modulo;
    num = (num * num) % modulo;
    power >>= _1n;
  }
  return res;
}

/**
 * Calculates a positive modulo result.
 * @param a - Dividend.
 * @param b - Positive modulus.
 * @returns Remainder in the range `[0, b)`.
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Keep a modulo result positive even for negative dividends.
 * ```ts
 * import { mod } from 'micro-rsa-dsa-dh/utils.js';
 * mod(-13n, 64n);
 * ```
 */
export function mod(a: bigint, b: bigint): bigint {
  // The documented `[0, b)` range and all FIPS/RFC group-order callers require
  // a positive modulus; negative moduli make that range meaningless.
  if (b <= _0n) throw new RangeError('mod: expected positive modulus');
  const result = a % b;
  return result >= _0n ? result : b + result;
}

/**
 * Computes the greatest common divisor (GCD) using the Euclidean algorithm.
 * @param a - First integer.
 * @param b - Second integer.
 * @returns GCD of `a` and `b`.
 * @example
 * Compute the greatest common divisor with the Euclidean algorithm.
 * ```ts
 * import { gcd } from 'micro-rsa-dsa-dh/utils.js';
 * gcd(48n, 18n);
 * ```
 */
export function gcd(a: bigint, b: bigint): bigint {
  while (b !== _0n) {
    let t = b;
    b = a % b;
    a = t;
  }
  // NOTE: GCD cannot be negative: 1 is always greater than any negative divisor.
  return a < _0n ? -a : a;
}

/**
 * Computes the multiplicative inverse modulo `modulo`.
 * @param number - Value to invert.
 * @param modulo - Positive modulus.
 * @returns Multiplicative inverse of `number` modulo `modulo`.
 * @throws On zero values or non-positive moduli. {@link RangeError}
 * @throws If the inverse does not exist for the provided modulus. {@link Error}
 * @example
 * Find the modular inverse used by RSA and DSA math.
 * ```ts
 * import { invert } from 'micro-rsa-dsa-dh/utils.js';
 * invert(3n, 11n);
 * ```
 */
export function invert(number: bigint, modulo: bigint): bigint {
  // FIPS 186-5 Appendix B.1 requires the modulus to be a positive integer
  // greater than 1; `modulo = 1` has no multiplicative inverse domain.
  if (number === _0n || modulo <= _1n)
    throw new RangeError(
      `invert: expected non-zero number and modulus greater than 1, got n=${number} mod=${modulo}`
    );
  // Euclidean GCD https://brilliant.org/wiki/extended-euclidean-algorithm/
  // Fermat's little theorem "CT-like" version inv(n) = n^(m-2) mod m is 30x slower.
  let a = mod(number, modulo);
  let b = modulo;
  // Only the Bezout coefficient of `number` is needed, so the second
  // coefficient pair (y, v) of the extended Euclidean algorithm is not tracked.
  // prettier-ignore
  let x = _0n, u = _1n;
  while (a !== _0n) {
    // JIT applies optimization if those two lines follow each other
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    // prettier-ignore
    b = a, a = r, x = u, u = m;
  }
  const gcd = b;
  if (gcd !== _1n) throw new Error('invert: does not exist');
  return mod(x, modulo);
}

/**
 * Calculates the integer square root of a bigint.
 *
 * This function computes the floor of the square root of `n` using a method
 * similar to the Newton-Raphson division. The algorithm starts with a large
 * initial guess and iteratively refines this guess until convergence.
 * The result is the largest integer `b` such that `b * b <= n`.
 *
 * @param n - The non-negative bigint value of which to find the square root.
 * @returns The integer square root of `n`.
 * @throws On negative bigint input. {@link RangeError}
 * @example
 * Compute the integer square root used while bounding prime candidates.
 * ```ts
 * import { sqrt } from 'micro-rsa-dsa-dh/utils.js';
 * sqrt(81n);
 * ```
 */
export function sqrt(n: bigint): bigint {
  if (n < _0n) throw new RangeError('sqrt: input must be a non-negative bigint');
  // The integer square-root contract includes zero: 0 is the largest b with
  // b * b <= 0. Return before Newton iteration so it cannot divide by zero.
  if (n <= _1n) return n;
  // Initial guess must be >= sqrt(n): n < 2^bitLen implies sqrt(n) < 2^(bitLen/2 + 1).
  // Binary toString is much cheaper than the decimal one for big values, and the
  // tighter guess saves Newton iterations.
  const bitLen = n.toString(2).length;
  let b: bigint = _1n << BigInt((bitLen >> 1) + 1);
  for (let a: bigint = (n / b + b) >> _1n; b !== a && b !== a - _1n; ) {
    b = a;
    a = (n / b + b) >> _1n;
  }
  return b;
}

// Random utils

/**
 * Generates a random bigint with a specific number of bits using a secure PRNG function.
 *
 * @param bits - The desired number of bits in the generated bigint.
 * @param randFn - Secure PRNG function used to generate random bytes.
 * @returns A random bigint with the specified number of bits, in big-endian format.
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Draw a fresh random bigint with a specific bit length.
 * ```ts
 * import { randomBits } from 'micro-rsa-dsa-dh/utils.js';
 * randomBits(128);
 * ```
 */
export function randomBits(bits: number, randFn: TArg<RandFn> = randomBytes): bigint {
  // Downstream FIPS callers use integer bit lengths for Miller-Rabin bases and
  // RSA prime candidates; reject invalid public helper inputs before RNG reads.
  if (!Number.isSafeInteger(bits) || bits <= 0)
    throw new RangeError('randomBits: expected positive safe integer bits');
  const bytes = Math.ceil(bits / 8);
  const n = BigInt('0x' + bytesToHex(randFn(bytes)));
  return n & ((_1n << BigInt(bits)) - _1n); // Strip the leftmost bits by masking the number
}

/**
 * Converts a hex string to bigint.
 * @param hex - Hex string without a `0x` prefix.
 * @returns Big-endian bigint value.
 * @throws On wrong hex input types. {@link TypeError}
 * @example
 * Decode a hex string into its bigint value.
 * ```ts
 * import { hexToNumber } from 'micro-rsa-dsa-dh/utils.js';
 * hexToNumber('ff');
 * ```
 */
export function hexToNumber(hex: string): bigint {
  if (typeof hex !== 'string') throw new TypeError('hex string expected, got ' + typeof hex);
  // Big Endian
  return BigInt(hex === '' ? '0' : `0x${hex}`);
}

/**
 * Encodes a bigint into even-length big-endian hex.
 * @param num - Number to encode.
 * @returns Big-endian hex string.
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Encode a scalar into hex without a `0x` prefix.
 * ```ts
 * numberToHexUnpadded(255n);
 * ```
 */
export function numberToHexUnpadded(num: number | bigint): string {
  const hex = abignumber(num).toString(16);
  return hex.length & 1 ? '0' + hex : hex;
}

/**
 * Encodes a bigint into fixed-length big-endian bytes.
 * @param n - Number to encode.
 * @param len - Output length in bytes.
 * @returns Big-endian byte array.
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Serialize a scalar into a 32-byte field element.
 * ```ts
 * numberToBytesBE(255n, 2);
 * ```
 */
export function numberToBytesBE(n: number | bigint, len: number): TRet<Uint8Array> {
  anumber(len);
  n = abignumber(n);
  const res = hexToBytes(n.toString(16).padStart(len * 2, '0'));
  if (res.length !== len) throw new RangeError('number too large');
  return res as TRet<Uint8Array>;
}

/**
 * Encodes a bigint into variable-length big-endian bytes.
 * @param n - Number to encode.
 * @returns Variable-length big-endian bytes.
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Serialize a bigint without fixed-width padding.
 * ```ts
 * numberToVarBytesBE(255n);
 * ```
 */
export function numberToVarBytesBE(n: number | bigint): TRet<Uint8Array> {
  return hexToBytes(numberToHexUnpadded(n)) as TRet<Uint8Array>; // validates n internally
}

/**
 * Converts bytes to bigint.
 * @param bytes - Big-endian byte array.
 * @returns Bigint representation of `bytes`.
 * @throws On wrong byte-array input types. {@link TypeError}
 * @example
 * Parse bytes into the bigint form used by the math helpers.
 * ```ts
 * import { bytesToNumber } from 'micro-rsa-dsa-dh/utils.js';
 * bytesToNumber(Uint8Array.from([1, 2]));
 * ```
 */
export function bytesToNumber(bytes: TArg<Uint8Array>): bigint {
  return hexToNumber(bytesToHex(bytes));
}

/**
 * Returns the byte length required to encode a field element.
 * @param fieldOrder - Field order or modulus.
 * @returns Byte length needed to encode values below `fieldOrder`.
 * @throws On wrong field-order input types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Work out how many bytes are needed for elements below a modulus.
 * ```ts
 * import { getFieldBytesLength } from 'micro-rsa-dsa-dh/utils.js';
 * getFieldBytesLength(65535n);
 * ```
 */
export function getFieldBytesLength(fieldOrder: bigint): number {
  if (typeof fieldOrder !== 'bigint') throw new TypeError('field order must be bigint');
  // FIPS 186-5 Appendix A.4.1 requires n >= 2 before reducing modulo n - 1.
  // Valid field elements are < fieldOrder, so the maximal encoded element is fieldOrder - 1.
  if (fieldOrder <= _1n) throw new RangeError('field order must be greater than 1');
  const bitLength = (fieldOrder - _1n).toString(2).length;
  return Math.ceil(bitLength / 8);
}

/**
 * Returns minimal amount of bytes that can be safely reduced
 * by field order.
 * Should be 2^-128 for 128-bit curve such as P256.
 * @param fieldOrder - Number of field elements.
 * @returns Byte length of the target hash.
 * @throws On wrong field-order input types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Choose the minimum hash size that still covers the field order.
 * ```ts
 * import { getMinHashLength } from 'micro-rsa-dsa-dh/utils.js';
 * getMinHashLength(65535n);
 * ```
 */
export function getMinHashLength(fieldOrder: bigint): number {
  // RFC 9380 §5 / §8.9 motivate this 1.5x byte rule by choosing
  // k = ceil(log2(r) / 2); getFieldBytesLength() enforces the FIPS 186-5
  // Appendix A.4.1 n >= 2 reduction domain before computing that width.
  const length = getFieldBytesLength(fieldOrder);
  return length + Math.ceil(length / 2);
}

/**
 * "Constant-time" private key generation utility.
 * Can take (n + n/2) or more bytes of uniform input e.g. from CSPRNG or KDF
 * and convert them into private scalar, with the modulo bias being negligible.
 * Needs at least 48 bytes of input for 32-byte private key.
 * See {@link https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/ | modulo bias guide},
 * {@link https://csrc.nist.gov/publications/detail/fips/186/5/final | FIPS 186-5 A.2},
 * and {@link https://www.rfc-editor.org/rfc/rfc9380#section-5 | RFC 9380 section 5}.
 * @param key - Hash output from SHA-3 or a similar function.
 * @param fieldOrder - Size of the subgroup.
 * @param min - Optional inclusive lower bound; defaults to `1n`, producing `[1, fieldOrder - 1]`.
 * @returns Valid private scalar encoding.
 * @throws On wrong field-order input types. {@link TypeError}
 * @throws On hash outputs that are too short to reduce safely. {@link RangeError}
 * @example
 * Turn uniform hash output into a valid private scalar encoding.
 * ```ts
 * import { randomBytes } from '@noble/hashes/utils.js';
 * import { mapHashToField } from 'micro-rsa-dsa-dh/utils.js';
 * const key = randomBytes(16);
 * mapHashToField(key, 23n);
 * ```
 */
export function mapHashToField(
  key: TArg<Uint8Array>,
  fieldOrder: bigint,
  min: bigint = _1n
): TRet<Uint8Array> {
  const len = key.length;
  const fieldLen = getFieldBytesLength(fieldOrder);
  const minLen = getMinHashLength(fieldOrder);
  // No small numbers: need to understand bias story. No huge numbers: easier to detect JS timings.
  // Extra bytes reduce modulo bias further, but runtime still scales with the supplied key length.
  if (len < 16 || len < minLen)
    throw new RangeError(`expected at least ${minLen} bytes of input, got ${len}`);
  const num = bytesToNumber(key);
  if (typeof min !== 'bigint') throw new TypeError('field minimum must be bigint');
  // FIPS 186-5 Appendix A.4.1 requires n >= 2 before reducing modulo n - 1;
  // with default min = 1n this range is exactly n - 1.
  // DH uses min = 2n for the same endpoint-exclusion shape: [2, p - 2].
  const range = fieldOrder - _2n * min + _1n;
  if (min < _1n || range < _1n) throw new RangeError('invalid field range');
  const reduced = mod(num, range) + min;
  return numberToBytesBE(reduced, fieldLen);
}
