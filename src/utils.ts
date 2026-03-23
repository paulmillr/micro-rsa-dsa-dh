/*! micro-rsa-dsa-dh - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';

/** Secure PRNG function like `randomBytes()` from `@noble/hashes/utils`. */
export type RandFn = (bytes: number) => Uint8Array;

/** Hash function with noble-style metadata and incremental API. */
export type Hash = {
  /** Hash one message in a single call. */
  (message: Uint8Array): Uint8Array;
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

function isBytes(a: unknown): a is Uint8Array {
  return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
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
export function ensureBytes(title: string, hex: Hex, expectedLength?: number): Uint8Array {
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
    res = Uint8Array.from(hex);
  } else {
    throw new TypeError(`${title} must be hex string or Uint8Array`);
  }
  const len = res.length;
  if (typeof expectedLength === 'number' && len !== expectedLength)
    throw new RangeError(`${title} expected ${expectedLength} bytes, got ${len}`);
  return res;
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
export function I2OSP(x: bigint, xLen: number): Uint8Array {
  if (x >= 256n ** BigInt(xLen)) throw new RangeError('integer too large');
  const res = new Uint8Array(xLen);
  for (let i = xLen - 1; i >= 0; i--) {
    res[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return res;
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
export function OS2IP(X: Uint8Array): bigint {
  let x = 0n;
  for (let i = 0; i < X.length; i++) x = (x << 8n) + BigInt(X[i]);
  return x;
}

/**
 * Efficiently raise num to power and do modular division.
 * Unsafe in some contexts: uses ladder, so can expose bigint bits.
 * @param num - Base value.
 * @param power - Non-negative exponent.
 * @param modulo - Positive modulus.
 * @returns `num ** power mod modulo`.
 * @throws On negative powers or non-positive moduli. {@link RangeError}
 * @example
 * Modular exponentiation used by RSA, DSA, and DH math.
 * ```ts
 * import { pow } from 'micro-rsa-dsa-dh/utils.js';
 * pow(2n, 6n, 11n) // 64n % 11n == 9n
 * ```
 */
export function pow(num: bigint, power: bigint, modulo: bigint): bigint {
  if (modulo <= 0n || power < 0n) throw new RangeError('Expected power/modulo > 0');
  if (modulo === 1n) return 0n;
  let res = 1n;
  while (power > 0n) {
    if (power & 1n) res = (res * num) % modulo;
    num = (num * num) % modulo;
    power >>= 1n;
  }
  return res;
}

/**
 * Calculates a positive modulo result.
 * @param a - Dividend.
 * @param b - Positive modulus.
 * @returns Remainder in the range `[0, b)`.
 * @example
 * Keep a modulo result positive even for negative dividends.
 * ```ts
 * import { mod } from 'micro-rsa-dsa-dh/utils.js';
 * mod(-13n, 64n);
 * ```
 */
export function mod(a: bigint, b: bigint): bigint {
  const result = a % b;
  return result >= 0n ? result : b + result;
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
  while (b !== 0n) {
    let t = b;
    b = a % b;
    a = t;
  }
  // NOTE: GCD cannot be negative! it is greatest divisior and 1 is always greater than any negative number
  return a < 0n ? -a : a;
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
  if (number === 0n || modulo <= 0n)
    throw new RangeError(`invert: expected positive integers, got n=${number} mod=${modulo}`);
  // Euclidean GCD https://brilliant.org/wiki/extended-euclidean-algorithm/
  // Fermat's little theorem "CT-like" version inv(n) = n^(m-2) mod m is 30x slower.
  let a = mod(number, modulo);
  let b = modulo;
  // prettier-ignore
  let x = 0n, y = 1n, u = 1n, v = 0n;
  while (a !== 0n) {
    // JIT applies optimization if those two lines follow each other
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    // prettier-ignore
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (gcd !== 1n) throw new Error('invert: does not exist');
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
  if (n < 0n) throw new RangeError('sqrt: input must be a non-negative bigint');
  if (n === 1n) return n;
  let b: bigint = 1n << BigInt(2 * n.toString().length);
  for (let a: bigint = (n / b + b) >> 1n; b !== a && b !== a - 1n; ) {
    b = a;
    a = (n / b + b) >> 1n;
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
 * @example
 * Draw a fresh random bigint with a specific bit length.
 * ```ts
 * import { randomBits } from 'micro-rsa-dsa-dh/utils.js';
 * randomBits(128);
 * ```
 */
export function randomBits(bits: number, randFn: RandFn = randomBytes): bigint {
  const bytes = Math.ceil(bits / 8);
  const n = BigInt('0x' + bytesToHex(randFn(bytes)));
  return n & ((1n << BigInt(bits)) - 1n); // Strip the leftmost bits by masking the number
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
 * Converts a number to a big-endian byte array.
 * @param n - Number to encode.
 * @param len - Optional output length in bytes.
 * @returns Byte representation of `n`.
 * @example
 * Encode a bigint into its big-endian byte representation.
 * ```ts
 * import { numberToBytes } from 'micro-rsa-dsa-dh/utils.js';
 * numberToBytes(258n, 2);
 * ```
 */
export function numberToBytes(n: number | bigint, len?: number): Uint8Array {
  let hex = n.toString(16);
  if (len) hex = hex.padStart(len * 2, '0');
  if (hex.length & 1) hex = `0${hex}`;
  return hexToBytes(hex);
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
export function bytesToNumber(bytes: Uint8Array): bigint {
  return hexToNumber(bytesToHex(bytes));
}

/**
 * Returns the byte length required to encode a field element.
 * @param fieldOrder - Field order or modulus.
 * @returns Byte length needed to encode values below `fieldOrder`.
 * @throws On wrong field-order input types. {@link TypeError}
 * @example
 * Work out how many bytes are needed for elements below a modulus.
 * ```ts
 * import { getFieldBytesLength } from 'micro-rsa-dsa-dh/utils.js';
 * getFieldBytesLength(65535n);
 * ```
 */
export function getFieldBytesLength(fieldOrder: bigint): number {
  if (typeof fieldOrder !== 'bigint') throw new TypeError('field order must be bigint');
  const bitLength = fieldOrder.toString(2).length;
  return Math.ceil(bitLength / 8);
}

/**
 * Returns minimal amount of bytes that can be safely reduced
 * by field order.
 * Should be 2^-128 for 128-bit curve such as P256.
 * @param fieldOrder - Number of field elements.
 * @returns Byte length of the target hash.
 * @throws On wrong field-order input types. {@link TypeError}
 * @example
 * Choose the minimum hash size that still covers the field order.
 * ```ts
 * import { getMinHashLength } from 'micro-rsa-dsa-dh/utils.js';
 * getMinHashLength(65535n);
 * ```
 */
export function getMinHashLength(fieldOrder: bigint): number {
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
export function mapHashToField(key: Uint8Array, fieldOrder: bigint): Uint8Array {
  const len = key.length;
  const fieldLen = getFieldBytesLength(fieldOrder);
  const minLen = getMinHashLength(fieldOrder);
  // No small numbers: need to understand bias story. No huge numbers: easier to detect JS timings.
  if (len < 16 || len < minLen)
    throw new RangeError(`expected at least ${minLen} bytes of input, got ${len}`);
  const num = bytesToNumber(key);
  // `mod(x, 11)` can sometimes produce 0. `mod(x, 10) + 1` is the same, but no 0
  const reduced = mod(num, fieldOrder - 1n) + 1n;
  return numberToBytes(reduced, fieldLen);
}
