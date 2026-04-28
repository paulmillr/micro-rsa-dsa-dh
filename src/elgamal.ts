import { randomBytes } from '@noble/hashes/utils.js';
import { isProbablySafePrime } from './primality.ts';
import { bytesToNumber, gcd, getFieldBytesLength, invert, mod, pow } from './utils.ts';

const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _2n = /* @__PURE__ */ BigInt(2);
const _3n = /* @__PURE__ */ BigInt(3);

/** Returns random number in range [min, max) */
function randomBigInt(bytes: number, min: bigint, max: bigint, randFn = randomBytes) {
  let res;
  do res = bytesToNumber(randFn(bytes));
  while (res < min || res >= max); // Key [2, p-1)
  return res;
}

/** ElGamal group parameters. */
export type ElGamalParams = {
  /** Prime modulus for the ElGamal group. */
  p: bigint;
  /** Generator used by the group. */
  g: bigint;
};
type ElGamalCiphertext = { ct1: bigint; ct2: bigint };
type ElGamalSignature = { r: bigint; s: bigint };
type ElGamalApi = {
  randomPrivateKey(): bigint;
  getPublicKey(privateKey: bigint): bigint;
  encrypt(publicKey: bigint, message: bigint, nonce?: bigint): ElGamalCiphertext;
  decrypt(privateKey: bigint, ciphertext: ElGamalCiphertext): bigint;
  sign(privateKey: bigint, message: bigint, nonce?: bigint): ElGamalSignature;
  verify(publicKey: bigint, message: bigint, sig: ElGamalSignature): boolean;
};

/**
 * Generate a random safe-prime ElGamal group.
 * @param bits - Byte-aligned bit length for the generated prime.
 * @returns Random ElGamal group parameters.
 * @throws If the requested bit length is not a positive byte-aligned safe integer. {@link Error}
 * @example
 * Generate group parameters, then build an ElGamal helper from them.
 * ```ts
 * import { ElGamal, genElGamalParams } from 'micro-rsa-dsa-dh/elgamal.js';
 * const params = genElGamalParams(256);
 * const elgamal = ElGamal(params);
 * const privateKey = elgamal.randomPrivateKey();
 * privateKey;
 * ```
 */
export function genElGamalParams(bits: number): ElGamalParams {
  if (!Number.isSafeInteger(bits) || bits <= 0 || bits % 8 !== 0)
    throw new Error('number of bits should be positive integer aligned to byte boundary');
  // 512: 1s, 1024: 20s, 2048: 1046s
  let p: bigint = _0n;
  // Policy: `bits` is the width of random candidate material, not an exact
  // mathematical bit-length promise for p. RFC 4880 5.5.2 / RFC 9580 5.5.5.3
  // only define ElGamal key fields as "MPI of Elgamal prime p", "MPI of
  // Elgamal group generator g", and "MPI of Elgamal public key value
  // y (= g^x mod p where x is secret)"; they do not specify parameter
  // generation or exact modulus-length semantics. Do not force the top bit
  // here: leading-zero random draws are still `bits` random candidate bits,
  // while conditioning on a leading 1 would change the candidate distribution.
  do p = bytesToNumber(randomBytes(bits / 8));
  while (!isProbablySafePrime(p, 10)); // NOTE: this is very slow!
  const q = (p - _1n) >> _1n;
  while (true) {
    // g=2 -> Bleichenbacher's attack
    const g = randomBigInt(bits / 8, _3n, p);
    if (pow(g, _2n, p) === _1n) continue;
    if (pow(g, q, p) === _1n) continue;
    if ((p - _1n) % g === _0n) continue;
    const gInv = invert(g, p); // Khadir's attack
    if ((p - _1n) % gInv === _0n) continue;
    return { p, g };
  }
}

/**
 * Build ElGamal encryption and signing helpers for a specific group.
 * @param params - ElGamal group parameters. See {@link ElGamalParams}.
 * @returns ElGamal helpers for key generation, encryption, decryption, signing, and verification.
 * @throws If the supplied ElGamal group parameters are invalid. {@link Error}
 * @example
 * Encrypt, decrypt, sign, and verify inside a toy ElGamal group.
 * ```ts
 * import { deepStrictEqual } from 'node:assert';
 * import { ElGamal } from 'micro-rsa-dsa-dh/elgamal.js';
 * const elgamal = ElGamal({ p: 23n, g: 5n });
 * const alicePriv = 6n;
 * const alicePub = elgamal.getPublicKey(alicePriv);
 * const msg = 8n;
 * const encrypted = elgamal.encrypt(alicePub, msg, 7n);
 * deepStrictEqual(elgamal.decrypt(alicePriv, encrypted), msg);
 * deepStrictEqual(elgamal.verify(alicePub, msg, elgamal.sign(alicePriv, msg, 3n)), true);
 * ```
 */
export const ElGamal = (params: ElGamalParams): ElGamalApi => {
  const { p, g } = params;
  if (typeof p !== 'bigint' || typeof g !== 'bigint') throw new Error('wrong params');
  if (g <= _1n || g >= p) throw new Error('g should be in the range 1 < g < p');
  // Odd-width moduli such as 257 need whole-octet random material; dividing
  // hex length by 2 produces fractional byte lengths that randomBytes rejects.
  const pBytes = getFieldBytesLength(p);
  return {
    randomPrivateKey(): bigint {
      return randomBigInt(pBytes, _2n, p - _1n); // [2, p-1)
    },
    getPublicKey(privateKey: bigint): bigint {
      if (typeof privateKey !== 'bigint') throw new Error('privateKey should be bigint');
      // Policy: RFC 4880 5.5.2 / RFC 9580 5.5.5.3 define ElGamal `y` as
      // "g^x mod p where x is secret", and RFC 4880 5.5.3 / RFC 9580
      // 5.5.5.3 only encode `x` as the "MPI of Elgamal secret exponent x".
      // They do not set an exponent interval. Weak or predictable caller
      // exponents such as 0, 1, or 2 are not treated as RFC-invalid here.
      return pow(g, privateKey, p);
    },
    encrypt(publicKey: bigint, message: bigint, nonce?: bigint): { ct1: bigint; ct2: bigint } {
      if (typeof publicKey !== 'bigint') throw new Error('publicKey should be bigint');
      if (typeof message !== 'bigint') throw new Error('wrong message');
      if (nonce === undefined) nonce = randomBigInt(pBytes, _1n, p - _1n);
      if (typeof nonce !== 'bigint' || nonce <= _0n || nonce >= p - _1n)
        throw new Error(`invalid nonce=${nonce}`);
      const c1 = pow(g, nonce, p); // c1 = g^k mod p
      const yk = pow(publicKey, nonce, p); // c2 = m * (y^k mod p) mod p
      const c2 = (message * yk) % p;
      return { ct1: c1, ct2: c2 };
    },
    decrypt(privateKey: bigint, ciphertext: { ct1: bigint; ct2: bigint }): bigint {
      if (typeof privateKey !== 'bigint') throw new Error('privateKey should be bigint');
      if (typeof ciphertext.ct1 !== 'bigint' || typeof ciphertext.ct2 !== 'bigint')
        throw new Error('invalid ciphertext');
      // Decryption process
      const c1x = pow(ciphertext.ct1, privateKey, p); // c1^x mod p
      const invC1x = invert(c1x, p); // (c1^x)^-1 mod p
      const m = (ciphertext.ct2 * invC1x) % p; // (c2 * (c1^x)^-1) mod p

      return m;
    },
    sign(privateKey: bigint, message: bigint, nonce?: bigint): { r: bigint; s: bigint } {
      if (typeof privateKey !== 'bigint') throw new Error('privateKey should be bigint');
      if (typeof message !== 'bigint') throw new Error('wrong message');
      if (nonce === undefined) {
        do nonce = randomBigInt(pBytes, _1n, p - _1n);
        while (gcd(nonce, p - _1n) !== _1n); // there is no invert otherwise
      }
      if (typeof nonce !== 'bigint' || nonce <= _0n || nonce >= p - _1n)
        throw new Error(`invalid nonce=${nonce}`);
      const r = pow(g, nonce, p);
      const kInv = invert(nonce, p - _1n);
      const s = mod(kInv * (message - privateKey * r), p - _1n);
      return { r, s };
    },
    verify(publicKey: bigint, message: bigint, sig: { r: bigint; s: bigint }): boolean {
      if (typeof publicKey !== 'bigint') throw new Error('publicKey should be bigint');
      // Policy: RFC 4880 5.5.2 / RFC 9580 5.5.5.3 define ElGamal `y` as
      // "g^x mod p where x is secret"; RFC 2440 12.5 legacy signature
      // guidance calls out `r` and `s` bounds, not a public-key interval.
      // Weak or predictable caller-supplied public keys such as 1 are not
      // treated as RFC-invalid here without an explicit OpenPGP rule.
      if (typeof sig.r !== 'bigint' || typeof sig.s !== 'bigint')
        throw new Error('invalid signature');
      const gH = pow(g, message, p);
      const yR = pow(publicKey, sig.r, p);
      const rS = pow(sig.r, sig.s, p);
      const yRrS = mod(yR * rS, p);
      return gH === yRrS;
    },
  };
};
