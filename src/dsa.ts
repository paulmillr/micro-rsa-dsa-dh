import { hmac } from '@noble/hashes/hmac.js';
import { concatBytes, hexToBytes, isBytes, randomBytes } from '@noble/hashes/utils.js';
import { isProbablePrime } from './primality.ts';
import {
  bytesToNumber,
  getFieldBytesLength,
  getMinHashLength,
  type Hash,
  I2OSP,
  invert,
  mapHashToField,
  mod,
  numberToBytes,
  OS2IP,
  pow,
  type RandFn,
} from './utils.ts';

/**
 * DER parsing error for DSA signatures.
 * @param m - Error message describing the invalid DER input.
 * @example
 * Raise a DER parsing error for malformed signatures.
 * ```ts
 * import { DERErr } from 'micro-rsa-dsa-dh/dsa.js';
 * new DERErr('bad signature');
 * ```
 */
export class DERErr extends Error {
  constructor(m = '') {
    super(m);
  }
}

/**
 * Minimal ASN.1 DER helpers for DSA signatures.
 * @example
 * Convert an `(r, s)` pair into the DER form used on the wire.
 * ```ts
 * import { DER } from 'micro-rsa-dsa-dh/dsa.js';
 * DER.hexFromSig({ r: 1n, s: 2n });
 * ```
 */
export const DER = {
  // asn.1 DER encoding utils
  Err: DERErr satisfies typeof DERErr as typeof DERErr,
  _parseInt(data: Uint8Array): { d: bigint; l: Uint8Array } {
    const { Err: E } = DER;
    if (data.length < 2 || data[0] !== 0x02) throw new E('Invalid signature integer tag');
    const len = data[1];
    const res = data.subarray(2, len + 2);
    if (!len || res.length !== len) throw new E('Invalid signature integer: wrong length');
    // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
    // since we always use positive integers here. It must always be empty:
    // - add zero byte if exists
    // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
    if (res[0] & 0b10000000) throw new E('Invalid signature integer: negative');
    if (res[0] === 0x00 && !(res[1] & 0b10000000))
      throw new E('Invalid signature integer: unnecessary leading zero');
    return { d: bytesToNumber(res), l: data.subarray(len + 2) }; // d is data, l is left
  },
  toSig(hex: string | Uint8Array): { r: bigint; s: bigint } {
    // parse DER signature
    const { Err: E } = DER;
    const data = typeof hex === 'string' ? hexToBytes(hex) : hex;
    //ut.abytes(data);
    let l = data.length;
    if (l < 2 || data[0] != 0x30) throw new E('Invalid signature tag');
    if (data[1] !== l - 2) throw new E('Invalid signature: incorrect length');
    const { d: r, l: sBytes } = DER._parseInt(data.subarray(2));
    const { d: s, l: rBytesLeft } = DER._parseInt(sBytes);
    if (rBytesLeft.length) throw new E('Invalid signature: left bytes after parsing');
    return { r, s };
  },
  hexFromSig(sig: { r: bigint; s: bigint }): string {
    // Add leading zero if first byte has negative bit enabled. More details in '_parseInt'
    const slice = (s: string): string => (Number.parseInt(s[0], 16) & 0b1000 ? '00' + s : s);
    const h = (num: number | bigint) => {
      const hex = num.toString(16);
      return hex.length & 1 ? `0${hex}` : hex;
    };
    const s = slice(h(sig.s));
    const r = slice(h(sig.r));
    const shl = s.length / 2;
    const rhl = r.length / 2;
    const sl = h(shl);
    const rl = h(rhl);
    return `30${h(rhl + shl + 4)}02${rl}${r}02${sl}${s}`;
  },
};

// Table C.1. Minimum number of Miller-Rabin iterations for DSA
const isProbablePrimeDSA_P = (L: number, n: bigint, randFn: RandFn = randomBytes) =>
  isProbablePrime(n, L === 3072 ? 2 : 3, randFn);
const isProbablePrimeDSA_Q = (N: number, n: bigint, randFn: RandFn = randomBytes) =>
  isProbablePrime(n, N === 160 ? 19 : N === 224 ? 24 : 27, randFn);

/** DSA domain parameters and hash function. */
export type DSAParams = {
  /** Prime modulus for the DSA group, usually at least 1024 bits. */
  p: bigint;
  /** Prime-order subgroup size, usually at least 160 bits and dividing `p - 1`. */
  q: bigint;
  /** Generator for the multiplicative subgroup of order `q` of integers modulo `p`. */
  g: bigint;
  /** Hash function used for signatures and nonce derivation. */
  hash: Hash;
};

/** DSA domain parameters with the seed material used to derive them. */
export type DSAProvableParams = DSAParams & {
  /** Seed bytes used while deriving `p` and `q`. */
  domainParameterSeed: Uint8Array;
  /** Prime-search counter returned by the derivation procedure. */
  counter: number;
  /** Generator-derivation domain-separation index. */
  index: number;
};

/**
 * Based on FIPS186-4 (A.1.1.2 Generation of the Probable Primes p and q Using an Approved Hash Function)
 * @param L - The desired length of the prime p (in bits).
 * @param N - The desired length of the prime q (in bits).
 * @param seed - seed: Uint8Array or length in bits (greater or equal to N)
 * @param hash - hash function
 */
function genDSAPrimes(
  L: number,
  N: number,
  hash: Hash,
  seed?: Uint8Array | number,
  randFn: RandFn = randomBytes
) {
  if (!Number.isSafeInteger(L) || !Number.isSafeInteger(N)) throw new Error('wrong L/N params');
  // From FIPS186-4: 4.2 Selection of Parameter Sizes and Hash Functions for DSA
  const pairs: Record<number, number[]> = { 1024: [160], 2048: [224, 256], 3072: [256] };
  if (!pairs[L].includes(N)) throw new Error(`Invalid L/N pair: possible N=${pairs[L]}`);
  const outlen = hash.outputLen * 8;
  // NOTE: we ask user to provide seed instead
  if (!Number.isSafeInteger(seed) && !isBytes(seed) && seed !== undefined)
    throw new Error('wrong seed: should be number of bits or Uint8Array');
  const seedOrLen = seed || N;
  const seedlen = isBytes(seedOrLen) ? seedOrLen.length * 8 : seedOrLen;
  if (seedlen < N || seedlen % 8 !== 0) throw new Error('invalid seedlen');
  const seedBytesLen = seedlen / 8;
  const n = Math.ceil(L / outlen) - 1; // 3
  const b = L - 1 - n * outlen; // 4
  const mask = 2n ** BigInt(N - 1);
  while (true) {
    const domainParameterSeed = isBytes(seedOrLen) ? seedOrLen : randFn(seedBytesLen);
    const U = bytesToNumber(hash(domainParameterSeed)) % mask; // 6
    let q = mask + U + 1n - (U % 2n); // 7
    if (!isProbablePrimeDSA_Q(N, q, randFn)) {
      if (isBytes(seed)) throw new Error('Fixed seed, Q is not prime');
      continue; // 9
    }
    let offset = 1n; // 10
    for (let counter = 0; counter < 4 * L; counter++) {
      // 11.1
      const V: bigint[] = [];
      for (let j = 0; j <= n; j++) {
        const seedWithOffset =
          bytesToNumber(domainParameterSeed) + offset + (BigInt(j) % 2n ** BigInt(seedlen));
        V.push(bytesToNumber(hash(numberToBytes(seedWithOffset, seedBytesLen))));
      }
      let W = V[0];
      for (let i = 1; i < n; i++) W += V[i] * 2n ** BigInt(i * outlen);
      W += (V[n] % 2n ** BigInt(b)) * 2n ** BigInt(n * outlen); // 11.2
      const X = W + 2n ** BigInt(L - 1); // 11.3: 0 ≤ W < 2L–1; hence, 2L–1 ≤ X < 2L
      const c = X % (2n * q); // 11.4
      const p = X - (c - 1n); // 11.5: p ≡ 1 (mod 2q).
      if (p >= 2n ** BigInt(L - 1) && isProbablePrimeDSA_P(L, p, randFn)) {
        return { p, q, domainParameterSeed, counter, hash };
      }
      offset += BigInt(n) + 1n; // 11.9
    }
  }
}

/**
 * Based on FIPS186-4: A.2.3 Verifiable Canonical Generation of the Generator g
 * @param res - result of genDSAPrimes
 * @param hash - hash algorihm function
 * @param index - index (key separation, for example: index = 1 for digital signatures and with index = 2 for key establishment.)
 */
function genDSAGenerator(res: ReturnType<typeof genDSAPrimes>, index: number): bigint {
  if (!Number.isSafeInteger(index) || index < 1 || index > 255) throw new Error('invalid index');
  const { p, q, domainParameterSeed, hash } = res;
  if (
    typeof p !== 'bigint' ||
    typeof q !== 'bigint' ||
    !isBytes(domainParameterSeed) ||
    typeof hash !== 'function'
  ) {
    throw new Error('wrong params');
  }
  const e = (p - 1n) / q; // Step 3
  for (let count = 0; ; ) {
    count++; // Step 5
    count &= 0xffff; // 16 bit integer
    if (count === 0) throw new Error('counter wrapped'); // Step 6
    const U = concatBytes(
      domainParameterSeed,
      hexToBytes('6767656e'), // 'ggen' in ascii
      new Uint8Array([index]),
      new Uint8Array([count >> 8, count & 0xff])
    ); // Step 7
    const W = bytesToNumber(hash(U)); // Step 8
    const g = pow(W, e, p); // W ** e % P
    if (g >= 2n) return g;
  }
}

/**
 * Generate DSA domain parameters.
 * @param L - The desired length of the prime p (in bits).
 * @param N - The desired length of the prime q (in bits).
 * @param hash - Hash function used to derive the primes and generator.
 * @param index - Domain-separation index for generator derivation.
 * @param seed - Optional seed bytes or seed length in bits.
 * @param randFn - Random-byte generator used when `seed` is not fixed.
 * @returns Provable DSA parameters and derivation metadata.
 * @throws If the hash, seed, parameter sizes, or generator-derivation inputs are invalid. {@link Error}
 * @example
 * Generate parameters once, then reuse them when constructing a DSA helper.
 * ```ts
 * import { DSA, genDSAParams } from 'micro-rsa-dsa-dh/dsa.js';
 * import { sha1 } from '@noble/hashes/legacy.js';
 * const params = genDSAParams(1024, 160, sha1, 1, 160);
 * const dsa = DSA(params);
 * const privateKey = dsa.randomPrivateKey();
 * privateKey;
 * ```
 */
export function genDSAParams(
  L: number,
  N: number,
  hash: Hash,
  index: number,
  seed?: Uint8Array | number,
  randFn: typeof randomBytes = randomBytes
): DSAProvableParams {
  if (typeof hash !== 'function') throw new Error('wrong hash');
  const res = genDSAPrimes(L, N, hash, seed, randFn);
  const g = genDSAGenerator(res, index);
  return { ...res, index, g };
}

type Pred<T> = (v: Uint8Array) => T | undefined;
/**
 * Minimal HMAC-DRBG from NIST 800-90 for RFC6979 sigs.
 * @param hashLen - Output size of the HMAC function in bytes.
 * @param qByteLen - Target byte length for generated candidates.
 * @param hmacFn - HMAC-like function used to expand internal state.
 * @returns Deterministic generator that retries until the predicate accepts the output.
 * @throws If the hash length, output length, callback, or retry budget is invalid. {@link Error}
 * @example
 * Build the RFC6979 nonce generator from HMAC-SHA256.
 * ```ts
 * import { hmac } from '@noble/hashes/hmac.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * import { concatBytes } from '@noble/hashes/utils.js';
 * import { createHmacDrbg } from 'micro-rsa-dsa-dh/dsa.js';
 * const drbg = createHmacDrbg(32, 32, (key, ...msgs) => hmac(sha256, key, concatBytes(...msgs)));
 * const out = drbg(new Uint8Array([1, 2, 3]), (bytes) => bytes);
 * out;
 * ```
 */
export function createHmacDrbg<T>(
  hashLen: number,
  qByteLen: number,
  hmacFn: (key: Uint8Array, ...messages: Uint8Array[]) => Uint8Array
): (seed: Uint8Array, predicate: Pred<T>) => T {
  if (typeof hashLen !== 'number' || hashLen < 2) throw new Error('hashLen must be a number');
  if (typeof qByteLen !== 'number' || qByteLen < 2) throw new Error('qByteLen must be a number');
  if (typeof hmacFn !== 'function') throw new Error('hmacFn must be a function');
  const NULL = Uint8Array.of();
  const byte0 = Uint8Array.of(0);
  const byte1 = Uint8Array.of(1);
  const maxDrbgIters = 1000;
  // Step B, Step C: set hashLen to 8*ceil(hlen/8)
  let v: Uint8Array = new Uint8Array(hashLen); // Minimal non-full-spec HMAC-DRBG from NIST 800-90 for RFC6979 sigs.
  let k: Uint8Array = new Uint8Array(hashLen); // Steps B and C of RFC6979 3.2: set hashLen, in our case always same
  let i = 0; // Iterations counter, will throw when over 1000
  const reset = () => {
    v.fill(1);
    k.fill(0);
    i = 0;
  };
  const h = (...b: Uint8Array[]): Uint8Array => hmacFn(k, v, ...b); // hmac(k)(v, ...values)
  const reseed = (seed: Uint8Array = NULL) => {
    // HMAC-DRBG reseed() function. Steps D-G
    k = h(byte0, seed); // k = hmac(k || v || 0x00 || seed)
    v = h(); // v = hmac(k || v)
    if (seed.length === 0) return;
    k = h(byte1, seed); // k = hmac(k || v || 0x01 || seed)
    v = h(); // v = hmac(k || v)
  };
  const gen = () => {
    // HMAC-DRBG generate() function
    if (i++ >= maxDrbgIters) throw new Error('drbg: tried max iterations');
    let len = 0;
    const out: Uint8Array[] = [];
    while (len < qByteLen) {
      v = h();
      const sl = v.slice();
      out.push(sl);
      len += v.length;
    }
    return concatBytes(...out);
  };
  const genUntil = (seed: Uint8Array, pred: Pred<T>): T => {
    reset();
    reseed(seed); // Steps D-G
    let res: T | undefined = undefined; // Step H: grind until k is in [1..n-1]
    while (!(res = pred(gen()))) reseed();
    reset();
    return res;
  };
  return genUntil;
}

/**
 * Simplified DSA implementation focusing on simplicity and basic functionality.
 * @param params - DSA domain parameters and hash function. See {@link DSAParams}.
 * @returns DSA key generation, signing, and verification helpers.
 * @throws If the supplied DSA domain parameters or hash function are invalid. {@link Error}
 * @example
 * Generate a fresh DSA keypair and sign a message with it.
 * ```ts
 * import { deepStrictEqual } from 'node:assert';
 * import { DSA, genDSAParams } from 'micro-rsa-dsa-dh/dsa.js';
 * import { sha1 } from '@noble/hashes/legacy.js';
 * const dsa = DSA(genDSAParams(1024, 160, sha1, 1, 160));
 * const privateKey = dsa.randomPrivateKey();
 * const publicKey = dsa.getPublicKey(privateKey);
 * const msg = new Uint8Array([1, 2, 3]);
 * const sig = dsa.sign(privateKey, msg);
 * deepStrictEqual(dsa.verify(publicKey, msg, sig), true);
 * ```
 */
export const DSA = (params: DSAParams) => {
  const { p, q, g, hash } = params;
  if (typeof p !== 'bigint' || typeof q !== 'bigint' || typeof g !== 'bigint')
    throw new Error('wrong DSAParams');
  if (typeof hash !== 'function') throw new Error('wrong hash');
  const fieldBytes = getFieldBytesLength(q);
  const fieldBits = q.toString(2).length;
  // RFC6979: ensure ECDSA msg is X bytes and < N. RFC suggests optional truncating via bits2octets.
  // FIPS 186-4 4.6 suggests the leftmost min(nBitLen, outLen) bits, which matches bits2int.
  // bits2int can produce res>N, we can do mod(res, N) since the bitLen is the same.
  // int2octets can't be used; pads small msgs with 0: unacceptatble for trunc as per RFC vectors
  const bits2int = function (bytes: Uint8Array): bigint {
    // For curves with nBitLength % 8 !== 0: bits2octets(bits2octets(m)) !== bits2octets(m)
    // for some cases, since bytes.length * 8 is not actual bitLength.
    const num = bytesToNumber(bytes); // check for == u8 done here
    const delta = bytes.length * 8 - fieldBits; // truncate to fieldBits leftmost bits
    return delta > 0 ? num >> BigInt(delta) : num;
  };
  return {
    randomPrivateKey(): bigint {
      return bytesToNumber(mapHashToField(randomBytes(getMinHashLength(q)), q));
    },
    getPublicKey: (privateKey: bigint): bigint => {
      return pow(g, privateKey, p);
    },
    sign: (privateKey: bigint, message: Uint8Array): Uint8Array => {
      const mHash = hash(message);
      const hmacFn = (key: Uint8Array, ...msgs: Uint8Array[]) =>
        hmac(hash as any, key, concatBytes(...msgs));
      const drbg = createHmacDrbg(hash.outputLen, fieldBytes, hmacFn);
      const h = mod(bits2int(mHash), q);
      const seed = concatBytes(I2OSP(privateKey % q, fieldBytes), I2OSP(h, fieldBytes)); // Step D of RFC6979 3.2
      const k = drbg(seed, (kBytes) => {
        kBytes = kBytes.subarray(0, fieldBytes); // hash can be bigger than fieldBytes
        const k = OS2IP(kBytes);
        if (1n < k && k < q - 1n) return k;
        return;
      }) as bigint; // Steps B, C, D, E, F, G
      const r = pow(g, k, p) % q; // (g^k % p) % q
      const ik = invert(k, q); // k^-1 mod n
      const s = mod(ik * mod(h + r * privateKey, q), q);
      // compact (P1363)
      const res = concatBytes(numberToBytes(r, fieldBytes), numberToBytes(s, fieldBytes));
      return res;
    },
    verify: (publicKey: bigint, msg: Uint8Array, sig: Uint8Array): boolean => {
      let r, s;
      // Signature can be represented in 2 ways: compact (2*nByteLength) & DER (variable-length).
      // Since DER can also be 2*nByteLength bytes, we check for it first.
      try {
        ({ r, s } = DER.toSig(sig));
      } catch (derError) {
        if (!(derError instanceof DER.Err)) throw derError;
        r = bytesToNumber(sig.slice(0, fieldBytes));
        s = bytesToNumber(sig.slice(fieldBytes, 2 * fieldBytes));
      }
      if (r <= 0n || r >= q || s <= 0n || s >= q) return false;
      const h = mod(bits2int(hash(msg)), q);
      const is = invert(s, q); // s^-1
      const u1 = mod(h * is, q); // u1 = hs^-1 mod n
      const u2 = mod(r * is, q); // u2 = rs^-1 mod n
      const t0 = pow(g, u1, p);
      const t1 = pow(publicKey, u2, p);
      const v = ((t0 * t1) % p) % q;
      return v === r;
    },
  };
};

export const _TEST: any = {
  genDSAPrimes,
  genDSAGenerator,
};
