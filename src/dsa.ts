import { hmac } from '@noble/hashes/hmac.js';
import {
  ahash,
  type CHash,
  concatBytes,
  hexToBytes,
  isBytes,
  randomBytes,
} from '@noble/hashes/utils.js';
import { isProbablePrime } from './primality.ts';
import {
  bytesToNumber,
  ensureBytes,
  getFieldBytesLength,
  getMinHashLength,
  I2OSP,
  invert,
  mapHashToField,
  mod,
  numberToBytesBE,
  OS2IP,
  pow,
  type RandFn,
  type TArg,
  type TRet,
} from './utils.ts';

const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _2n = /* @__PURE__ */ BigInt(2);

type DERSig = { r: bigint; s: bigint };
type DERApi = {
  Err: typeof DERErr;
  _parseInt(data: Uint8Array): { d: bigint; l: Uint8Array };
  toSig(hex: string | Uint8Array): DERSig;
  hexFromSig(sig: DERSig): string;
};

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
 * RFC 3279 Dss-Sig-Value encodes DSA signatures as a SEQUENCE of two INTEGER values.
 * Supported DSA sizes keep the DER payload under 128 bytes, so short-form lengths are enough.
 * @example
 * Convert an `(r, s)` pair into the DER form used on the wire.
 * ```ts
 * import { DER } from 'micro-rsa-dsa-dh/dsa.js';
 * DER.hexFromSig({ r: 1n, s: 2n });
 * ```
 */
export const DER: TRet<DERApi> = /* @__PURE__ */ Object.freeze({
  // asn.1 DER encoding utils
  Err: DERErr satisfies typeof DERErr as typeof DERErr,
  _parseInt(data: TArg<Uint8Array>): TRet<{ d: bigint; l: Uint8Array }> {
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
    return { d: bytesToNumber(res), l: data.subarray(len + 2) } as TRet<{
      d: bigint;
      l: Uint8Array;
    }>; // d is data, l is left
  },
  toSig(hex: TArg<string | Uint8Array>): DERSig {
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
  hexFromSig(sig: DERSig): string {
    // Callers must pass positive nonzero signature values; this serializer only adds
    // DER sign-bit padding and does not sanitize invalid DSA components such as r = 0
    // or s = 0.
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
});

// Table C.1. Minimum number of Miller-Rabin iterations for DSA
// FIPS 186-5 no longer includes DSA prime-generation algorithms, so the legacy DSA
// helpers keep their supported Miller-Rabin round counts inline.
const isProbablePrimeDSA_P = (L: number, n: bigint, randFn: TArg<RandFn> = randomBytes) =>
  isProbablePrime(n, L === 3072 ? 2 : 3, randFn);
const isProbablePrimeDSA_Q = (N: number, n: bigint, randFn: TArg<RandFn> = randomBytes) =>
  isProbablePrime(n, N === 160 ? 19 : N === 224 ? 24 : 27, randFn);

const DSA_SIZE_PAIRS: Readonly<Record<number, readonly number[]>> = /* @__PURE__ */ Object.freeze({
  // 1024/160 is retained as an explicitly supported legacy pair (~80-bit strength).
  1024: /* @__PURE__ */ Object.freeze([160]),
  2048: /* @__PURE__ */ Object.freeze([224, 256]),
  3072: /* @__PURE__ */ Object.freeze([256]),
});

function requireDSASizePair(L: number, N: number): void {
  const possibleN = DSA_SIZE_PAIRS[L];
  if (!possibleN || !possibleN.includes(N))
    throw new Error(`Invalid L/N pair: possible N=${possibleN || 'none'}`);
}

type DSAValidatedPrimes = { p: bigint; q: bigint };
type DSAValidatedDomain = DSAValidatedPrimes & { g: bigint };
const DSA_VALIDATION_CACHE_SIZE = 16;
const validatedDSAPrimes: DSAValidatedPrimes[] = [];
const validatedDSADomains: DSAValidatedDomain[] = [];

function cacheValidated<T>(cache: T[], value: T): void {
  cache.push(value);
  if (cache.length > DSA_VALIDATION_CACHE_SIZE) cache.shift();
}

function validateDSADomain(p: bigint, q: bigint, g: bigint): void {
  if (validatedDSADomains.some((domain) => domain.p === p && domain.q === q && domain.g === g))
    return;
  const L = p.toString(2).length;
  const N = q.toString(2).length;
  requireDSASizePair(L, N);
  if (g <= _1n || g >= p) throw new Error('invalid DSA generator range');
  if ((p - _1n) % q !== _0n) throw new Error('invalid DSA domain relation');
  const primesCached = validatedDSAPrimes.some((primes) => primes.p === p && primes.q === q);
  if (!primesCached) {
    if (!isProbablePrimeDSA_Q(N, q) || !isProbablePrimeDSA_P(L, p))
      throw new Error('non-prime DSA parameters');
    cacheValidated(validatedDSAPrimes, { p, q });
  }
  if (pow(g, q, p) !== _1n) throw new Error('invalid DSA subgroup generator');
  cacheValidated(validatedDSADomains, { p, q, g });
}

/** DSA domain parameters and hash function. */
export type DSAParams = {
  /** Prime modulus for the DSA group, usually at least 1024 bits. */
  p: bigint;
  /** Prime-order subgroup size, usually at least 160 bits and dividing `p - 1`. */
  q: bigint;
  /** Generator for the multiplicative subgroup of order `q` of integers modulo `p`. */
  g: bigint;
  /** Hash function used for signatures and nonce derivation. */
  hash: CHash;
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
  hash: TArg<CHash>,
  seed?: TArg<Uint8Array | number>,
  randFn: TArg<RandFn> = randomBytes
) {
  if (!Number.isSafeInteger(L) || !Number.isSafeInteger(N)) throw new Error('wrong L/N params');
  ahash(hash);
  // This legacy FIPS 186-4 parameter table is finite; validate L before
  // checking N so unsupported sizes fail as input errors, not internal TypeErrors.
  requireDSASizePair(L, N);
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
  const mask = _1n << BigInt(N - 1);
  // Loop invariants of step 11, hoisted out of the prime search.
  const pow2seedlen = _1n << BigInt(seedlen);
  const pow2b = _1n << BigInt(b);
  const pMin = _1n << BigInt(L - 1); // 2^(L-1)
  const shifts = Array.from({ length: n + 1 }, (_, i) => BigInt(i * outlen));
  const offsetStep = BigInt(n + 1);
  while (true) {
    const domainParameterSeed = isBytes(seedOrLen)
      ? ensureBytes('seed', seedOrLen)
      : (randFn(seedBytesLen) as TRet<Uint8Array>);
    const seedNum = bytesToNumber(domainParameterSeed);
    const U = bytesToNumber(hash(domainParameterSeed)) % mask; // 6
    let q = mask + U + _1n - (U % _2n); // 7
    if (!isProbablePrimeDSA_Q(N, q, randFn)) {
      if (isBytes(seed)) throw new Error('Fixed seed, Q is not prime');
      continue; // 9
    }
    const q2 = _2n * q;
    let offset = _1n; // 10
    for (let counter = 0; counter < 4 * L; counter++) {
      // 11.1: Vj = Hash((domain_parameter_seed + offset + j) mod 2^seedlen)
      const V: bigint[] = [];
      for (let j = 0; j <= n; j++) {
        const seedWithOffset = (seedNum + offset + BigInt(j)) % pow2seedlen;
        V.push(bytesToNumber(hash(numberToBytesBE(seedWithOffset, seedBytesLen))));
      }
      let W = V[0];
      for (let i = 1; i < n; i++) W += V[i] << shifts[i];
      W += (V[n] % pow2b) << shifts[n]; // 11.2
      const X = W + pMin; // 11.3: 0 ≤ W < 2L–1; hence, 2L–1 ≤ X < 2L
      const c = X % q2; // 11.4
      const p = X - (c - _1n); // 11.5: p ≡ 1 (mod 2q).
      if (p >= pMin && isProbablePrimeDSA_P(L, p, randFn)) {
        return { p, q, domainParameterSeed, counter, hash };
      }
      offset += offsetStep; // 11.9
    }
    // Step 12 restarts from step 5 with a fresh seed; a fixed seed would
    // deterministically repeat the same failed search forever.
    if (isBytes(seed)) throw new Error('Fixed seed, no prime P found');
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
  const e = (p - _1n) / q; // Step 3
  const ggen = hexToBytes('6767656e'); // 'ggen' in ascii
  for (let count = 0; ;) {
    count++; // Step 5
    count &= 0xffff; // 16 bit integer
    if (count === 0) throw new Error('counter wrapped'); // Step 6
    const U = concatBytes(
      domainParameterSeed,
      ggen,
      new Uint8Array([index]),
      new Uint8Array([count >> 8, count & 0xff])
    ); // Step 7
    const W = bytesToNumber(hash(U)); // Step 8
    const g = pow(W, e, p); // W ** e % P
    if (g >= _2n) return g;
  }
}

/**
 * Generate DSA domain parameters.
 * The legacy 1024/160 pair remains supported for compatibility but provides only about 80 bits of
 * classical security. Prefer 2048/224, 2048/256, or 3072/256 for existing DSA interoperability;
 * FIPS 186-5 no longer approves DSA signature generation for new applications. Caller-selected
 * hashes are not policy-checked; SHA-1 remains accepted for compatibility but is collision-unsafe
 * and should be used only when reproducing legacy domains for old-signature verification.
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
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const params = genDSAParams(2048, 256, sha256, 1, 256);
 * const dsa = DSA(params);
 * const privateKey = dsa.randomPrivateKey();
 * privateKey;
 * ```
 */
export function genDSAParams(
  L: number,
  N: number,
  hash: TArg<CHash>,
  index: number,
  seed?: TArg<Uint8Array | number>,
  randFn: TArg<RandFn> = randomBytes
): TRet<DSAProvableParams> {
  ahash(hash);
  const res = genDSAPrimes(L, N, hash, seed, randFn);
  const g = genDSAGenerator(res, index);
  return { ...res, index, g } as TRet<DSAProvableParams>;
}

type Pred<T> = (v: Uint8Array) => T | undefined;
type HmacFn = (key: Uint8Array, ...messages: Uint8Array[]) => Uint8Array;
type Drbg<T> = (seed: Uint8Array, predicate: Pred<T>) => T;
type DSAApi = {
  randomPrivateKey(): bigint;
  getPublicKey(privateKey: bigint): bigint;
  sign(privateKey: bigint, message: Uint8Array): Uint8Array;
  verify(publicKey: bigint, msg: Uint8Array, sig: Uint8Array): boolean;
};
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
  hmacFn: TArg<HmacFn>
): TRet<Drbg<T>> {
  if (typeof hashLen !== 'number' || hashLen < 2) throw new Error('hashLen must be a number');
  if (typeof qByteLen !== 'number' || qByteLen < 2) throw new Error('qByteLen must be a number');
  if (typeof hmacFn !== 'function') throw new Error('hmacFn must be a function');
  const NULL = Uint8Array.of() as TRet<Uint8Array>;
  const byte0 = Uint8Array.of(0) as TRet<Uint8Array>;
  const byte1 = Uint8Array.of(1) as TRet<Uint8Array>;
  const maxDrbgIters = 1000;
  // Step B, Step C: set hashLen to 8*ceil(hlen/8)
  let v: TRet<Uint8Array> = new Uint8Array(hashLen) as TRet<Uint8Array>; // Minimal non-full-spec HMAC-DRBG from NIST 800-90 for RFC6979 sigs.
  let k: TRet<Uint8Array> = new Uint8Array(hashLen) as TRet<Uint8Array>; // Steps B and C of RFC6979 3.2: set hashLen, in our case always same
  let i = 0; // Iterations counter, will throw when over 1000
  const reset = () => {
    v.fill(1);
    k.fill(0);
    i = 0;
  };
  const h = (...b: TArg<Uint8Array[]>): TRet<Uint8Array> =>
    hmacFn(k, v, ...(b as TRet<Uint8Array>[])) as TRet<Uint8Array>; // hmac(k)(v, ...values)
  const reseed = (seed: TArg<Uint8Array> = NULL) => {
    const seedBytes = ensureBytes('seed', seed);
    // HMAC-DRBG reseed() function. Steps D-G
    k = h(byte0, seedBytes); // k = hmac(k || v || 0x00 || seed)
    v = h(); // v = hmac(k || v)
    if (seedBytes.length === 0) return;
    k = h(byte1, seedBytes); // k = hmac(k || v || 0x01 || seed)
    v = h(); // v = hmac(k || v)
  };
  const gen = (): TRet<Uint8Array> => {
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
  const genUntil = (seed: TArg<Uint8Array>, pred: TArg<Pred<T>>): T => {
    reset();
    reseed(seed); // Steps D-G
    let res: T | undefined = undefined; // RFC6979 3.2 step H: grind until the predicate accepts a candidate.
    // The predicate reports rejection with undefined; defined falsy values like 0 are valid generic outputs.
    while ((res = pred(gen()) as T | undefined) === undefined) reseed();
    reset();
    return res;
  };
  return genUntil as TRet<Drbg<T>>;
}

/**
 * Simplified DSA implementation focusing on simplicity and basic functionality.
 * The domain's caller-selected hash is not policy-checked. SHA-1 signing remains available for
 * compatibility but is collision-unsafe; use SHA-1 only to verify old signatures and use an
 * approved SHA-2/SHA-3 hash when existing DSA interoperability is unavoidable.
 * @param params - DSA domain parameters and hash function. See {@link DSAParams}.
 * @returns DSA key generation, signing, and verification helpers.
 * @throws If the supplied DSA size pair, primes, subgroup relation, generator, or hash is invalid.
 *   {@link Error}
 * @example
 * Generate a fresh DSA keypair and sign a message with it.
 * ```ts
 * import { deepStrictEqual } from 'node:assert';
 * import { DSA, genDSAParams } from 'micro-rsa-dsa-dh/dsa.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const dsa = DSA(genDSAParams(2048, 256, sha256, 1, 256));
 * const privateKey = dsa.randomPrivateKey();
 * const publicKey = dsa.getPublicKey(privateKey);
 * const msg = new Uint8Array([1, 2, 3]);
 * const sig = dsa.sign(privateKey, msg);
 * deepStrictEqual(dsa.verify(publicKey, msg, sig), true);
 * ```
 */
export const DSA = (params: TArg<DSAParams>): TRet<DSAApi> => {
  const { p, q, g, hash } = params;
  if (typeof p !== 'bigint' || typeof q !== 'bigint' || typeof g !== 'bigint')
    throw new Error('wrong DSAParams');
  ahash(hash);
  validateDSADomain(p, q, g);
  const fieldBytes = getFieldBytesLength(q);
  const fieldBits = q.toString(2).length;
  // RFC6979: ensure ECDSA msg is X bytes and < N. RFC suggests optional truncating via bits2octets.
  // FIPS 186-4 4.6 suggests the leftmost min(nBitLen, outLen) bits, which matches bits2int.
  // bits2int can produce res>N, we can do mod(res, N) since the bitLen is the same.
  // int2octets can't be used; pads small msgs with 0: unacceptatble for trunc as per RFC vectors
  const bits2int = function (bytes: TArg<Uint8Array>): bigint {
    // For curves with nBitLength % 8 !== 0: bits2octets(bits2octets(m)) !== bits2octets(m)
    // for some cases, since bytes.length * 8 is not actual bitLength.
    const num = bytesToNumber(bytes); // check for == u8 done here
    const delta = bytes.length * 8 - fieldBits; // truncate to fieldBits leftmost bits
    return delta > 0 ? num >> BigInt(delta) : num;
  };
  const validatePrivateKey = (privateKey: bigint) => {
    // RFC6979 2.2: the DSA private key x "shall not be 0" and is in [1, q-1].
    // Node/OpenSSL accepts crafted x=0 keys and derives y=1; keep this API on the RFC interval.
    if (typeof privateKey !== 'bigint' || privateKey <= _0n || privateKey >= q)
      throw new Error('invalid private key');
  };
  const isValidPublicKey = (publicKey: bigint): boolean => {
    // RFC6979 2.1 makes g an order-q generator; RFC6979 2.2 defines DSA public
    // keys as y = g^x mod p with x in [1, q-1]. Rejecting y=1 is derived, not
    // a direct quote: an order-q generator reaches identity only for exponents
    // congruent to 0 mod q, and that exponent is outside [1, q-1].
    // Node/OpenSSL accepts crafted y=1 DSA public keys; keep verification on
    // the RFC-derived key relation instead.
    return (
      typeof publicKey === 'bigint' &&
      _1n < publicKey &&
      publicKey < p &&
      pow(publicKey, q, p) === _1n
    );
  };
  return {
    randomPrivateKey(): bigint {
      return bytesToNumber(mapHashToField(randomBytes(getMinHashLength(q)), q));
    },
    getPublicKey: (privateKey: bigint): bigint => {
      validatePrivateKey(privateKey);
      return pow(g, privateKey, p);
    },
    sign: (privateKey: bigint, message: TArg<Uint8Array>): TRet<Uint8Array> => {
      validatePrivateKey(privateKey);
      const msg = ensureBytes('message', message);
      const mHash = hash(msg);
      const hmacFn = (key: TArg<Uint8Array>, ...msgs: TArg<Uint8Array[]>): TRet<Uint8Array> =>
        hmac(hash, key, concatBytes(...msgs));
      const drbg = createHmacDrbg(hash.outputLen, fieldBytes, hmacFn);
      const h = mod(bits2int(mHash), q);
      const seed = concatBytes(I2OSP(privateKey % q, fieldBytes), I2OSP(h, fieldBytes)); // Step D of RFC6979 3.2
      const q1 = q - _1n;
      const { r, s } = drbg(seed, (kBytes) => {
        kBytes = kBytes.subarray(0, fieldBytes); // hash can be bigger than fieldBytes
        const k = OS2IP(kBytes);
        if (!(_1n < k && k < q1)) return;
        // FIPS 186-4 §4.6 / RFC 6979 §2.4 step 5: if r = 0 or s = 0,
        // reject this k and generate a new one.
        const r = pow(g, k, p) % q; // (g^k % p) % q
        if (r === _0n) return;
        const ik = invert(k, q); // k^-1 mod q
        const s = mod(ik * mod(h + r * privateKey, q), q);
        if (s === _0n) return;
        return { r, s };
      }) as DERSig; // Steps B, C, D, E, F, G, H
      // compact (P1363)
      const res = concatBytes(numberToBytesBE(r, fieldBytes), numberToBytesBE(s, fieldBytes));
      return res;
    },
    verify: (publicKey: bigint, msg: TArg<Uint8Array>, sig: TArg<Uint8Array>): boolean => {
      const message = ensureBytes('message', msg);
      const signature = ensureBytes('signature', sig);
      let r, s;
      // Signature can be represented in 2 ways: compact (2*nByteLength) & DER (variable-length).
      // Since DER can also be 2*nByteLength bytes, we check for it first.
      try {
        ({ r, s } = DER.toSig(signature));
      } catch (derError) {
        if (!(derError instanceof DER.Err)) throw derError;
        // Compact (P1363) encoding is exactly 2*fieldBytes: reject other lengths
        // so a signature with appended garbage does not also verify.
        if (signature.length !== 2 * fieldBytes) return false;
        r = bytesToNumber(signature.subarray(0, fieldBytes));
        s = bytesToNumber(signature.subarray(fieldBytes));
      }
      if (!isValidPublicKey(publicKey)) return false;
      if (r <= _0n || r >= q || s <= _0n || s >= q) return false;
      const h = mod(bits2int(hash(message)), q);
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

export const _TEST: any = /* @__PURE__ */ Object.freeze({
  genDSAPrimes,
  genDSAGenerator,
});
