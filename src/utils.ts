/*! micro-rsa-dsa-dh - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';

/**
 * Secure PRNG function like 'randomBytes' from '@noble/hashes/utils'
 */
export type RandFn = (bytes: number) => Uint8Array;

export type Hash = {
  (message: Uint8Array): Uint8Array;
  outputLen: number;
  blockLen: number;
  create: () => any;
};

export type Hex = Uint8Array | string; // hex strings are accepted for simplicity

function isBytes(a: unknown): a is Uint8Array {
  return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
}

/**
 * Takes hex string or Uint8Array, converts to Uint8Array.
 * Validates output length.
 * Will throw error for other types.
 * @param title descriptive title for an error e.g. 'private key'
 * @param hex hex string or Uint8Array
 * @param expectedLength optional, will compare to result array's length
 * @returns
 */
export function ensureBytes(title: string, hex: Hex, expectedLength?: number): Uint8Array {
  let res: Uint8Array;
  if (typeof hex === 'string') {
    try {
      res = hexToBytes(hex);
    } catch (e) {
      throw new Error(`${title} must be valid hex string, got "${hex}". Cause: ${e}`);
    }
  } else if (isBytes(hex)) {
    // Uint8Array.from() instead of hash.slice() because node.js Buffer
    // is instance of Uint8Array, and its slice() creates **mutable** copy
    res = Uint8Array.from(hex);
  } else {
    throw new Error(`${title} must be hex string or Uint8Array`);
  }
  const len = res.length;
  if (typeof expectedLength === 'number' && len !== expectedLength)
    throw new Error(`${title} expected ${expectedLength} bytes, got ${len}`);
  return res;
}

/**
 * Integer-to-Octet-String Primitive (I2OSP)
 *
 * @param x - The nonnegative integer to be converted.
 * @param xLen - The intended length of the resulting octet string.
 * @returns The corresponding octet string of length xLen.
 */
export function I2OSP(x: bigint, xLen: number): Uint8Array {
  if (x >= 256n ** BigInt(xLen)) throw new Error('integer too large');
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
 */
export function OS2IP(X: Uint8Array): bigint {
  let x = 0n;
  for (let i = 0; i < X.length; i++) x = (x << 8n) + BigInt(X[i]);
  return x;
}

/**
 * Efficiently raise num to power and do modular division.
 * Unsafe in some contexts: uses ladder, so can expose bigint bits.
 * @example
 * pow(2n, 6n, 11n) // 64n % 11n == 9n
 */
export function pow(num: bigint, power: bigint, modulo: bigint): bigint {
  if (modulo <= 0n || power < 0n) throw new Error('Expected power/modulo > 0');
  if (modulo === 1n) return 0n;
  let res = 1n;
  while (power > 0n) {
    if (power & 1n) res = (res * num) % modulo;
    num = (num * num) % modulo;
    power >>= 1n;
  }
  return res;
}

// Calculates a modulo b
export function mod(a: bigint, b: bigint): bigint {
  const result = a % b;
  return result >= 0n ? result : b + result;
}

/**
 * Computes the greatest common divisor (GCD) using the Euclidean algorithm.
 * @param a First integer
 * @param b Second integer
 * @returns GCD of a and b (the largest positive integer that divides each of the integers)
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

// Inverses number over modulo
export function invert(number: bigint, modulo: bigint): bigint {
  if (number === 0n || modulo <= 0n)
    throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
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
 */
export function sqrt(n: bigint): bigint {
  if (n < 0n) throw new Error('sqrt: input must be a non-negative bigint');
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
 * @param The secure PRNG function to use for generating random bytes.
 * @returns A random bigint with the specified number of bits, in big-endian format.
 */
export function randomBits(bits: number, randFn: RandFn = randomBytes): bigint {
  const bytes = Math.ceil(bits / 8);
  const n = BigInt('0x' + bytesToHex(randFn(bytes)));
  return n & ((1n << BigInt(bits)) - 1n); // Strip the leftmost bits by masking the number
}

export function hexToNumber(hex: string): bigint {
  if (typeof hex !== 'string') throw new Error('hex string expected, got ' + typeof hex);
  // Big Endian
  return BigInt(hex === '' ? '0' : `0x${hex}`);
}

export function numberToBytes(n: number | bigint, len?: number): Uint8Array {
  let hex = n.toString(16);
  if (len) hex = hex.padStart(len * 2, '0');
  if (hex.length & 1) hex = `0${hex}`;
  return hexToBytes(hex);
}

export function bytesToNumber(bytes: Uint8Array): bigint {
  return hexToNumber(bytesToHex(bytes));
}

export function getFieldBytesLength(fieldOrder: bigint): number {
  if (typeof fieldOrder !== 'bigint') throw new Error('field order must be bigint');
  const bitLength = fieldOrder.toString(2).length;
  return Math.ceil(bitLength / 8);
}

/**
 * Returns minimal amount of bytes that can be safely reduced
 * by field order.
 * Should be 2^-128 for 128-bit curve such as P256.
 * @param fieldOrder number of field elements
 * @returns byte length of target hash
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
 * https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
 * FIPS 186-5, A.2 https://csrc.nist.gov/publications/detail/fips/186/5/final
 * RFC 9380, https://www.rfc-editor.org/rfc/rfc9380#section-5
 * @param key hash output from SHA3 or a similar function
 * @param fieldOrder size of subgroup
 * @returns valid private scalar
 */
export function mapHashToField(key: Uint8Array, fieldOrder: bigint): Uint8Array {
  const len = key.length;
  const fieldLen = getFieldBytesLength(fieldOrder);
  const minLen = getMinHashLength(fieldOrder);
  // No small numbers: need to understand bias story. No huge numbers: easier to detect JS timings.
  if (len < 16 || len < minLen)
    throw new Error(`expected at least ${minLen} bytes of input, got ${len}`);
  const num = bytesToNumber(key);
  // `mod(x, 11)` can sometimes produce 0. `mod(x, 10) + 1` is the same, but no 0
  const reduced = mod(num, fieldOrder - 1n) + 1n;
  return numberToBytes(reduced, fieldLen);
}
