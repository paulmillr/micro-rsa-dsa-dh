import { sha1 } from '@noble/hashes/legacy.js';
import { sha224, sha256, sha384, sha512, sha512_224, sha512_256 } from '@noble/hashes/sha2.js';
import { sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256 } from '@noble/hashes/sha3.js';
import { concatBytes, createView, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { isProbablePrimeRSA } from './primality.ts';
import {
  type Hash,
  I2OSP,
  OS2IP,
  type RandFn,
  type TArg,
  type TRet,
  ensureBytes,
  gcd,
  invert,
  pow,
  randomBits,
  sqrt,
} from './utils.ts';

const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _2n = /* @__PURE__ */ BigInt(2);
const _3n = /* @__PURE__ */ BigInt(3);
const _8n = /* @__PURE__ */ BigInt(8);
const _16n = /* @__PURE__ */ BigInt(16);
const _100n = /* @__PURE__ */ BigInt(100);
const _256n = /* @__PURE__ */ BigInt(256);
const _65537n = /* @__PURE__ */ BigInt(65537);

/** Variable-output hash or XOF helper. */
// Can be mgf(sha256).
export type VarLenHash = (msg: TArg<Uint8Array>, opts: { dkLen: number }) => TRet<Uint8Array>;

/** XOF helper with noble-style metadata. */
export type HashXOF = VarLenHash & {
  /** Input block size in bytes. */
  blockLen: number;
  /**
   * Creates a fresh incremental XOF instance.
   * @param opts - Requested output length for the XOF instance.
   * @returns New XOF object ready for `update(...).digest()`.
   */
  create: (opts: { dkLen: number }) => any;
};

/** RSA encryption scheme interface. */
export type KEM = {
  /**
   * Encrypts one plaintext with the RSA public key.
   * @param publicKey - RSA public key used for encryption.
   * @param plaintext - Message bytes to encrypt.
   * @returns Ciphertext bytes ready for transport.
   */
  encrypt(publicKey: PublicKey, plaintext: TArg<Uint8Array>): TRet<Uint8Array>;
  /**
   * Decrypts one ciphertext with the RSA private key.
   * @param privateKey - RSA private key used for decryption.
   * @param ciphertext - Ciphertext bytes to decrypt.
   * @returns Decrypted plaintext bytes.
   */
  decrypt(privateKey: PrivateKey, ciphertext: TArg<Uint8Array>): TRet<Uint8Array>;
};

/** RSA signature scheme interface. */
export type Signer = {
  /**
   * Verifies one signature against the message and public key.
   * @param publicKey - RSA public key used for verification.
   * @param message - Message bytes that were signed.
   * @param signature - Signature bytes to verify.
   * @returns `true` when the signature is valid.
   */
  verify(publicKey: PublicKey, message: TArg<Uint8Array>, signature: TArg<Uint8Array>): boolean;
  /**
   * Signs one message with the RSA private key.
   * @param privateKey - RSA private key used for signing.
   * @param message - Message bytes to sign.
   * @returns Signature bytes.
   */
  sign(privateKey: PrivateKey, message: TArg<Uint8Array>): TRet<Uint8Array>;
};

const hashOutputLen = (hash: TArg<HashXOF>, dkLen: number): TRet<Hash> => {
  // RFC 8017 OAEP/PSS define hLen as a fixed octet length, so XOF helpers
  // are wrapped with a fixed dkLen before those schemes read hash.outputLen.
  const res = (msg: TArg<Uint8Array>) => hash(ensureBytes('message', msg), { dkLen });
  res.outputLen = dkLen;
  res.blockLen = hash.blockLen;
  res.create = () => hash.create({ dkLen });
  return res as TRet<Hash>;
};

/**
 * Generate the RSA primes p and q according to the FIPS 186-5 standard.
 * See A.1.3, Generation of Random Primes that are Probably Prime.
 * @param nlen - Bit length of the modulus.
 * @param e - Public exponent. Must be an odd positive integer
 * @param a - Optional parameter for p ≡ a mod 8.
 * @param b - Optional parameter for q ≡ b mod 8.
 * @param randFn - Random-byte generator used to search for primes.
 * @returns Probable RSA primes `p` and `q`.
 * @throws If the modulus size, public exponent, or prime search fails validation. {@link Error}
 * @example
 * Generate the two primes that will back an RSA modulus.
 * ```ts
 * import { IFCPrimes } from 'micro-rsa-dsa-dh/rsa.js';
 * const { p, q } = IFCPrimes(2048);
 * const modulus = p * q;
 * modulus.toString(16);
 * ```
 */
export function IFCPrimes(
  nlen: number,
  e: bigint = _65537n,
  a?: number,
  b?: number,
  randFn: TArg<RandFn> = randomBytes
): { p: bigint; q: bigint } {
  if (nlen % 8 !== 0) throw new Error(`expected bit length aligned to byte boundary, got ${nlen}`);
  if (nlen < 2048) throw new Error(`wrong nlen=${nlen}, expected at least 2048`); // Step 1: Check nlen
  if (e <= _2n ** _16n || e >= _2n ** _256n || e % _2n === _0n)
    throw new Error(`Wrong public exponent e=${e}`); // Step 2: Check e
  const limit = sqrt(_1n << BigInt(nlen - 1));
  // Step 4: Generate p
  // FIPS 186-5 A.1.3 steps 4.2 and 5.2 require both candidate draws to come from the selected DRBG, i.e. randFn in this API.
  for (let i = 0; i < 5 * nlen; i++) {
    // Step 4.1 and Step 4.7
    let p = randomBits(nlen / 2, randFn); // Step 4.2
    if (a !== undefined)
      p += BigInt((a - Number(p % _8n)) % 8); // Step 4.3
    else if (p % _2n === _0n) p += _1n; // Step 4.3
    if (p < limit) continue; // Step 4.4
    if (gcd(p - _1n, e) === _1n) {
      // Step 4.5
      if (isProbablePrimeRSA(p, randFn)) {
        // Step 4.5.1 and Step 4.5.2
        // Proceed to Step 5 if p is probably prime
        for (let j = 0; j < 10 * nlen; j++) {
          let q = randomBits(nlen / 2, randFn); // Step 5.2
          if (b !== undefined)
            q += BigInt((b - Number(q % _8n)) % 8); // Step 5.3
          else if (q % _2n === _0n) q += _1n; // Step 5.3
          if (q < limit) continue; // Step 5.4
          let distance = p - q;
          if (distance < _0n) distance = -distance;
          if (distance <= _2n ** ((BigInt(nlen) >> _1n) - _100n)) continue; // Step 5.5
          if (gcd(q - _1n, e) === _1n && isProbablePrimeRSA(q, randFn)) return { p, q }; // Step 5.6
        }
        throw new Error('failed to find q after max iterations');
      }
    }
  }
  throw new Error('failed to find p after max iterations');
}

// Compares 2 u8a-s in kinda constant time
// The loop is constant-shape only when lengths already match; RSA callers use it on fixed-length hashes or encoded messages.
function equalBytes(a: TArg<Uint8Array>, b: TArg<Uint8Array>) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Build the PKCS#1 MGF1 mask-generation function from a hash.
 * @param hash - Hash function used for the underlying digest rounds.
 * @returns Mask-generation function with variable output length.
 * @example
 * Expand a short seed into the mask used by OAEP or PSS.
 * ```ts
 * import { mgf1 } from 'micro-rsa-dsa-dh/rsa.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * mgf1(sha256)(new Uint8Array([1, 2, 3]), { dkLen: 4 });
 * ```
 */
export function mgf1(hash: TArg<Hash>): TRet<VarLenHash> {
  // From noble-post-quantum
  const counterB = new Uint8Array(4);
  const counterV = createView(counterB);
  return (msg: TArg<Uint8Array>, opts: { dkLen: number }) => {
    const { dkLen } = opts;
    // RFC 8017 Appendix B.2.1: maskLen is an octet length and the output has exactly that many octets, so reject values JS would otherwise coerce or truncate.
    if (!Number.isSafeInteger(dkLen) || dkLen < 0)
      throw new Error('mgf1: expected non-negative safe integer dkLen');
    if (dkLen > 2 ** 32) throw new Error('mask too long');
    const out = new Uint8Array(Math.ceil(dkLen / hash.outputLen) * hash.outputLen);
    for (let counter = 0, o = out; o.length; counter++) {
      counterV.setUint32(0, counter, false);
      hash.create().update(msg).update(counterB).digestInto(o);
      o = o.subarray(hash.outputLen);
    }
    out.subarray(dkLen).fill(0);
    return out.subarray(0, dkLen) as TRet<Uint8Array>;
  };
}
/** Represents an RSA public key. */
export type PublicKey = {
  /** RSA modulus used for encryption and signature verification. */
  n: bigint;
  /** RSA public exponent, usually `65537`. */
  e: bigint;
};

// RFC 8017 §3.1 requires a valid RSA public exponent in [3, n - 1]
// with GCD(e, lambda(n)) = 1; oddness is the checkable consequence for
// RSA moduli made from odd primes. Node/OpenSSL accepts crafted e=1
// public keys and verifies matching PKCS#1 v1.5 encodings, but this API
// follows the RFC public-key domain more strictly.
const validatePublicKey = (key: PublicKey) => {
  if (
    key === null ||
    typeof key !== 'object' ||
    typeof key.n !== 'bigint' ||
    typeof key.e !== 'bigint'
  )
    throw new Error('wrong public key');
  if (key.e < _3n || key.e >= key.n || key.e % _2n === _0n)
    throw new Error('RSA: invalid public key exponent');
};

/** Represents a simplified RSA private key with basic components. */
export type PrivateKey = {
  /** RSA modulus shared with the public key. */
  n: bigint;
  /** RSA private exponent used for decryption and signing. */
  d: bigint;
};

// RFC 8017 §3.2 requires d to be positive, below n, and satisfy
// e*d ≡ 1 (mod λ(n)); RSADP/RSASP1 assume that valid key. This simplified
// key type lacks e,p,q, so full congruence and the FIPS 186-5 A.1.1
// d > 2^(nlen/2) bound cannot be checked here. Still, d=1 is below that
// FIPS bound, d>=n violates RFC 8017 §3.2, and even d cannot satisfy the
// RFC congruence for RSA moduli made from odd primes. Node/OpenSSL accepts
// crafted d=1 private keys and signs with them; this API follows the
// RFC/FIPS private-key domain more strictly.
const validatePrivateKey = (key: PrivateKey) => {
  if (
    key === null ||
    typeof key !== 'object' ||
    typeof key.n !== 'bigint' ||
    typeof key.d !== 'bigint'
  )
    throw new Error('wrong private key');
  if (key.n <= _0n || key.d <= _1n || key.d >= key.n || key.d % _2n === _0n)
    throw new Error('RSA: invalid private key exponent');
};

/**
 * RSA Encryption Primitive (RSAEP)
 *
 * @param publicKey - An object containing RSA public key components.
 * @param m - The message representative.
 * @returns The ciphertext representative.
 */
function RSAEP(publicKey: PublicKey, m: bigint): bigint {
  const { n, e } = publicKey;
  if (m < _0n || m >= n) throw new Error('message representative out of range');
  return pow(m, e, n); // c = m^e mod n
}

/**
 * RSA Decryption Primitive (RSADP)
 *
 * @param privateKey - An object containing RSA private key components.
 * @param c - The ciphertext representative.
 * @returns The message representative.
 * @throws Will throw an error if the ciphertext representative is out of range.
 */
function RSADP(privateKey: PrivateKey, c: bigint): bigint {
  const { n } = privateKey;
  if (c < _0n || c >= n) throw new Error('ciphertext representative out of range'); // Step 1
  return pow(c, privateKey.d, n); // m = c^d mod n
}

/**
 * RSA Signature Primitive (RSASP1)
 *
 * @param privateKey - An object containing RSA private key components.
 * @param m - The message representative.
 * @returns The signature representative.
 */
function RSASP1(privateKey: PrivateKey, m: bigint): bigint {
  const { n } = privateKey;
  // Step 1: Check if m is between 0 and n - 1
  if (m < _0n || m >= n) throw new Error('message representative out of range'); // Step 1
  return pow(m, privateKey.d, n); // s = m^d mod n
}

/**
 * RSAVP1
 *
 * RSA Verification Primitive.
 *
 * @param publicKey - RSA public key containing modulus (n) and exponent (e)
 * @param s - Signature representative, an integer between 0 and n - 1
 * @returns Message representative, an integer between 0 and n - 1
 */
function RSAVP1(publicKey: { n: bigint; e: bigint }, s: bigint): bigint | false {
  const { n, e } = publicKey;
  // Internal variant: higher-level RFC 8017 verify paths map this step-1 failure to "invalid signature", so this helper returns false instead of throwing.
  if (s < _0n || s >= n) return false; // Step 1
  return pow(s, e, n); // Step 2
}

// Exported API
/**
 * Generates an RSA key pair.
 *
 * @param nlen - Bit length of the RSA modulus to generate.
 * @param e - Public exponent for the key pair.
 * @param randFn - Random-byte generator used during prime search.
 * @returns Generated RSA public and private key pair.
 * @throws If the modulus size, public exponent, or prime generation inputs are invalid. {@link Error}
 * @example
 * Generate one RSA keypair for both encryption and signatures.
 * ```ts
 * import { keygen } from 'micro-rsa-dsa-dh/rsa.js';
 * const alice = keygen(2048);
 * alice.publicKey.n === alice.privateKey.n;
 * ```
 */
export function keygen(
  nlen: number,
  e: bigint = _65537n,
  randFn: TArg<RandFn> = randomBytes
): { publicKey: { e: bigint; n: bigint }; privateKey: { d: bigint; n: bigint } } {
  if (!Number.isSafeInteger(nlen) || nlen <= 0) throw new Error('wrong nlen');
  for (;;) {
    const { p, q } = IFCPrimes(nlen, e, undefined, undefined, randFn);
    const n = p * q;
    const p1 = p - _1n;
    const q1 = q - _1n;
    const lambda = (p1 * q1) / gcd(p1, q1);
    const d = invert(e, lambda);
    // FIPS 186-5 Appendix A.1.1 requires `d = e^-1 mod LCM(p - 1, q - 1)`
    // and `2^(nlen/2) < d`; in the rare small-d case it says new p, q, and d shall be determined.
    if (d <= _2n ** BigInt(nlen / 2)) continue;
    return { publicKey: { e, n }, privateKey: { d, n } };
  }
}

/**
 * RSAES-OAEP key encapsulation helper.
 * @param hash - Hash function used for OAEP label and message digests.
 * @param mgfHash - Mask-generation function used to derive OAEP masks.
 * @param label - Optional label bound to every encryption/decryption operation.
 * @returns OAEP encryption and decryption helpers.
 * @example
 * Encrypt with the public key and decrypt with the private key.
 * ```ts
 * import { deepStrictEqual } from 'node:assert';
 * import { OAEP, keygen, mgf1 } from 'micro-rsa-dsa-dh/rsa.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const alice = keygen(2048);
 * const kem = OAEP(sha256, mgf1(sha256));
 * const msg = new Uint8Array([1, 2, 3]);
 * const encrypted = kem.encrypt(alice.publicKey, msg);
 * deepStrictEqual(kem.decrypt(alice.privateKey, encrypted), msg);
 * ```
 */
export const OAEP = (
  hash: TArg<Hash>,
  mgfHash: TArg<VarLenHash>,
  label: TArg<Uint8Array> = Uint8Array.of()
): TRet<KEM> => {
  const labelBytes = ensureBytes('label', label);
  return {
    encrypt(publicKey: PublicKey, M: TArg<Uint8Array>): TRet<Uint8Array> {
      validatePublicKey(publicKey);
      const msg = ensureBytes('message', M);
      const { n } = publicKey;
      const k = Math.ceil(n.toString(16).length / 2);
      const mLen = msg.length;
      if (mLen > k - 2 * hash.outputLen - 2) throw new Error('message too long');
      const lHash = hash(labelBytes); // Step 2a
      const PS = new Uint8Array(k - mLen - 2 * hash.outputLen - 2); // Step 2b
      const DB = concatBytes(lHash, PS, new Uint8Array([0x01]), msg); // Step 2c: DB = lHash || PS || 0x01 || M
      const seed = randomBytes(hash.outputLen); // Step 2d
      const dbMask = mgfHash(seed, { dkLen: k - hash.outputLen - 1 }); // Step 2e
      const maskedDB = DB.map((byte, idx) => byte ^ dbMask[idx]) as TRet<Uint8Array>; // Step 2f
      const seedMask = mgfHash(maskedDB, { dkLen: hash.outputLen }); // Step 2g
      const maskedSeed = seed.map((byte, idx) => byte ^ seedMask[idx]) as TRet<Uint8Array>; // Step 2h
      const EM = concatBytes(new Uint8Array([0x00]), maskedSeed, maskedDB); // Step 2i
      const m = OS2IP(EM); // Step 3a
      const c = RSAEP(publicKey, m); // Step 3b
      return I2OSP(c, k); // Step 3c
    },
    decrypt(privateKey: PrivateKey, C: TArg<Uint8Array>): TRet<Uint8Array> {
      validatePrivateKey(privateKey);
      const ciphertext = ensureBytes('ciphertext', C);
      const { n } = privateKey;
      const k = Math.ceil(n.toString(16).length / 2); // Length of the RSA modulus in bytes
      // RFC 8017 §7.1.2 steps 1b, 1c, and 2b say ciphertext length mismatch,
      // `k < 2hLen + 2`, and RSADP "ciphertext representative out of range"
      // all output "decryption error", keeping public OAEP failures indistinguishable.
      if (ciphertext.length !== k) throw new Error('decryption error');
      if (k < 2 * hash.outputLen + 2) throw new Error('decryption error');
      const c = OS2IP(ciphertext); // Step 2a
      if (c >= n) throw new Error('decryption error');
      const m = RSADP(privateKey, c); // Step 2b
      const EM = I2OSP(m, k); // Step 2c
      const lHash = hash(labelBytes); // Step 3a
      // Step 3b
      const Y = EM[0];
      const maskedSeed = EM.subarray(1, 1 + hash.outputLen) as TRet<Uint8Array>;
      const maskedDB = EM.subarray(1 + hash.outputLen) as TRet<Uint8Array>;
      const seedMask = mgfHash(maskedDB, { dkLen: hash.outputLen }); // Step 3c
      const seed = maskedSeed.map((byte, idx) => byte ^ seedMask[idx]) as TRet<Uint8Array>; // Step 3d
      const dbMask = mgfHash(seed, { dkLen: k - hash.outputLen - 1 }); // Step 3e
      const DB = maskedDB.map((byte, idx) => byte ^ dbMask[idx]); // Step 3f
      const lHashPrime = DB.subarray(0, hash.outputLen); // Step 3g
      const rest = DB.subarray(hash.outputLen);
      let idx = rest.indexOf(0x01);
      if (idx === -1 || !equalBytes(lHash, lHashPrime) || Y !== 0x00)
        throw new Error('decryption error');
      // PS should be zeros
      for (let i = 0; i < idx; i++) if (rest[i] !== 0) throw new Error('decryption error');
      return rest.subarray(idx + 1) as TRet<Uint8Array>;
    },
  };
};

// PSS
type PSSOpts = { hash: TArg<Hash>; mgfHash: TArg<VarLenHash>; sLen: number };

function fixShake(hash: TArg<Hash>) {
  // TODO: find better solution.
  // Problem is that spec requires different outputLen for shake, so we patch it here
  // FIPS 186-5 §5.4(b): RSASSA-PSS uses SHAKE128/SHAKE256 with fixed 32/64-byte Hash output, so the built-in SHAKE helpers are wrapped before RFC 8017 EMSA-PSS reads hash.outputLen.
  if (hash !== shake128 && hash !== shake256) return hash;
  const dkLen = hash === shake128 ? 32 : 64;
  return hashOutputLen(hash, dkLen);
}

function EMSA_PSS_ENCODE(
  M: TArg<Uint8Array>,
  emBits: number,
  opts: TArg<PSSOpts>
): TRet<Uint8Array> {
  let { hash, mgfHash, sLen } = opts;
  hash = fixShake(hash);
  const msg = ensureBytes('message', M);
  const emLen = Math.ceil(emBits / 8);
  // RFC 8017 §9.1.1 step 3 only rejects salts that do not fit `emLen`;
  // FIPS 186-5 §5.4(g) additionally requires approved RSASSA-PSS signing to check `0 <= sLen <= hLen`.
  if (!Number.isSafeInteger(sLen) || sLen < 0 || sLen > hash.outputLen)
    throw new Error('PSS: invalid salt length');
  const mHash = hash(msg); // Step 2
  if (emLen < hash.outputLen + sLen + 2) throw new Error('encoding error'); // Step 3
  const salt = sLen === 0 ? Uint8Array.of() : randomBytes(sLen); // Step 4
  // Step 5: Let M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
  const Mprime = concatBytes(new Uint8Array(8), mHash, salt); // Step 5
  const H = hash(Mprime) as TRet<Uint8Array>; // Step 6
  const PS = new Uint8Array(emLen - sLen - hash.outputLen - 2); // Step 7
  const DB = concatBytes(PS, new Uint8Array([0x01]), salt); // Step 8: DB = PS || 0x01 || salt
  const dbMask = mgfHash(H, { dkLen: emLen - hash.outputLen - 1 }); // Step 9
  const maskedDB = DB.map((byte, idx) => byte ^ dbMask[idx]); // Step 10
  const leftmostBits = 8 * emLen - emBits; // Step 11
  maskedDB[0] &= 0xff >> leftmostBits;
  return concatBytes(maskedDB, H, new Uint8Array([0xbc])); // Step 12: EM = maskedDB || H || 0xbc
}

function EMSA_PSS_VERIFY(
  M: TArg<Uint8Array>,
  EM: TArg<Uint8Array>,
  emBits: number,
  opts: TArg<PSSOpts>
): boolean {
  let { hash, mgfHash, sLen } = opts;
  hash = fixShake(hash);
  const msg = ensureBytes('message', M);
  const encoded = ensureBytes('encoded message', EM);
  const emLen = Math.ceil(emBits / 8);
  // RFC 8017 §9.1.2 step 3 only returns "inconsistent" when the requested salt
  // does not fit `emLen`; FIPS 186-5 §5.4(g) says `0 <= sLen <= hLen` shall also be checked during verification.
  if (!Number.isSafeInteger(sLen) || sLen < 0 || sLen > hash.outputLen) return false;
  const mHash = hash(msg); // Step 2
  if (emLen < hash.outputLen + sLen + 2) return false; // Step 3
  if (encoded[encoded.length - 1] !== 0xbc) return false; // Step 4
  const maskedDB = encoded.subarray(0, emLen - hash.outputLen - 1) as TRet<Uint8Array>; // Step 5
  const H = encoded.subarray(emLen - hash.outputLen - 1, emLen - 1) as TRet<Uint8Array>; // Step 5
  // Step 6: Check the leftmost bits of maskedDB
  const leftmostBits = 8 * emLen - emBits;
  if (maskedDB[0] >> (8 - leftmostBits) !== 0) return false;
  const dbMask = mgfHash(H, { dkLen: emLen - hash.outputLen - 1 }); // Step 7
  const DB = maskedDB.map((byte, idx) => byte ^ dbMask[idx]); // Step 8
  DB[0] &= 0xff >> leftmostBits; // Step 9
  // Step 10: Check the leftmost octets and the 0x01 separator
  const psLen = emLen - hash.outputLen - sLen - 2;
  for (let i = 0; i < psLen; i++) if (DB[i] !== 0x00) return false;
  if (DB[psLen] !== 0x01) return false;
  const salt = sLen > 0 ? DB.subarray(-sLen) : new Uint8Array(0); // Step 11
  const Mprime = concatBytes(new Uint8Array(8), mHash, salt); // Step 12: M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
  const Hprime = hash(Mprime); // Step 13
  return equalBytes(H, Hprime); // Step 14: Compare H and H'
}

/**
 * EMSA-PSS: improved EMSA, based on the probabilistic signature scheme
 * @param hash - Hash function used to digest the message.
 * @param mgfHash - Mask-generation function used inside PSS encoding.
 * @param sLen - Salt length in bytes.
 * @returns RSA-PSS signing and verification helpers.
 * @example
 * Sign a message with RSA-PSS and verify it with the public key.
 * ```ts
 * import { deepStrictEqual } from 'node:assert';
 * import { PSS, keygen, mgf1 } from 'micro-rsa-dsa-dh/rsa.js';
 * import { sha256 } from '@noble/hashes/sha2.js';
 * const alice = keygen(2048);
 * const signer = PSS(sha256, mgf1(sha256));
 * const msg = new Uint8Array([1, 2, 3]);
 * const sig = signer.sign(alice.privateKey, msg);
 * deepStrictEqual(signer.verify(alice.publicKey, msg, sig), true);
 * ```
 */
export const PSS = (
  hash: TArg<Hash>,
  mgfHash: TArg<VarLenHash>,
  sLen: number = 0
): TRet<Signer> => ({
  sign(privateKey: PrivateKey, M: TArg<Uint8Array>): TRet<Uint8Array> {
    validatePrivateKey(privateKey);
    M = ensureBytes('message', M);
    const { n, d } = privateKey;
    const k = Math.ceil(n.toString(16).length / 2);
    const emBits = n.toString(2).length - 1;
    const EM = EMSA_PSS_ENCODE(M, emBits, { hash, mgfHash, sLen });
    const m = OS2IP(EM); // Step 2a
    const s = RSASP1({ n, d }, m); // Step 2b
    // RFC 8017 §8.1.1 step 2c serializes the signature representative to k octets; emLen only describes the EMSA-PSS encoded message width.
    return I2OSP(s, k); // Step 2c
  },
  verify(publicKey: PublicKey, M: TArg<Uint8Array>, S: TArg<Uint8Array>): boolean {
    validatePublicKey(publicKey);
    M = ensureBytes('message', M);
    S = ensureBytes('signature', S);
    const { n, e } = publicKey;
    const k = Math.ceil(n.toString(16).length / 2);
    const emBits = n.toString(2).length - 1;
    const emLen = Math.ceil(emBits / 8);
    if (S.length !== k) return false; // Step 1
    const s = OS2IP(S); // Step 2a
    const m = RSAVP1({ n, e }, s); // Step 2b
    if (m === false) return false;
    // RFC 8017 §8.1.2 step 2c: if I2OSP(m, emLen) outputs "integer too large",
    // output "invalid signature" instead of leaking the conversion error.
    if (m >= _256n ** BigInt(emLen)) return false;
    const EM = I2OSP(m, emLen); // Step 2c
    return EMSA_PSS_VERIFY(M, EM, emBits, { hash, mgfHash, sLen }); // Step 3
  },
});

// RSAES-PKCS1-v1_5

/**
 * EMSA-PKCS1-v1_5-ENCODE function
 *
 * @param M - Message to be encoded.
 * @param emLen - Intended length in octets of the encoded message.
 * @param hash - Hash function to be used.
 * @returns Encoded message.
 * @throws Will throw an error if the message is too long or intended encoded message length is too short.
 */
function EMSA_PKCS1_V1_5_ENCODE(
  hash: TArg<Hash>,
  prefix: string,
  M: TArg<Uint8Array>,
  emLen: number
): TRet<Uint8Array> {
  const H = hash(ensureBytes('message', M));
  // RFC 8017 §9.2 step 2: prefix is the DER DigestInfo prefix for this hash; the built-in SHA-1/SHA-2 PKCS#1 v1.5 variants use the Appendix B.1 NULL-parameter encodings.
  const T = concatBytes(hexToBytes(prefix), H);
  const tLen = T.length;
  if (emLen < tLen + 11) throw new Error('intended encoded message length too short');
  const PS = new Uint8Array(emLen - tLen - 3).fill(0xff); // Step 4
  return concatBytes(new Uint8Array([0x00, 0x01]), PS, new Uint8Array([0x00]), T); // Step 5
}

/**
 * RSAES-PKCS1-v1_5: older Encryption/decryption Scheme (ES) as first standardized in version 1.5 of PKCS #1. Known-vulnerable.
 * @example
 * Older PKCS#1 v1.5 encryption still round-trips through the same keypair.
 * ```ts
 * import { deepStrictEqual } from 'node:assert';
 * import { PKCS1_KEM, keygen } from 'micro-rsa-dsa-dh/rsa.js';
 * const alice = keygen(2048);
 * const msg = new Uint8Array([1, 2, 3]);
 * const encrypted = PKCS1_KEM.encrypt(alice.publicKey, msg);
 * deepStrictEqual(PKCS1_KEM.decrypt(alice.privateKey, encrypted), msg);
 * ```
 */
export const PKCS1_KEM: TRet<KEM> = /* @__PURE__ */ Object.freeze({
  encrypt(publicKey: PublicKey, M: TArg<Uint8Array>): TRet<Uint8Array> {
    validatePublicKey(publicKey);
    M = ensureBytes('message', M);
    const { n } = publicKey;
    const k = Math.ceil(n.toString(16).length / 2); // Length of the RSA modulus in bytes
    const mLen = M.length;
    if (mLen > k - 11) throw new Error('message too long'); // Step 1
    const psLen = k - mLen - 3;
    const PS = new Uint8Array(psLen); // Step 2a
    // RFC 8017 §7.2.1 step 2a: PS must contain only nonzero random octets; the step-1 length bound guarantees PS is at least 8 bytes long here.
    for (let i = 0; i < psLen; i++) {
      let rnd = 0;
      while (rnd === 0) rnd = randomBytes(1)[0];
      PS[i] = rnd;
    }
    const EM = concatBytes(new Uint8Array([0x00, 0x02]), PS, new Uint8Array([0x00]), M); // Step 2b
    const m = OS2IP(EM); // Step 3a
    const c = RSAEP(publicKey, m); // Step 3b
    return I2OSP(c, k); // Step 3c
  },
  decrypt(privateKey: PrivateKey, C: TArg<Uint8Array>): TRet<Uint8Array> {
    validatePrivateKey(privateKey);
    C = ensureBytes('ciphertext', C);
    const { n } = privateKey;
    const k = Math.ceil(n.toString(16).length / 2);
    if (C.length !== k || k < 11) throw new Error('decryption error'); // Step 1
    const c = OS2IP(C); // Step 2a
    // RFC 8017 §7.2.2 steps 1, 2b, and 3 say ciphertext length mismatch,
    // `k < 11`, RSADP "ciphertext representative out of range", and
    // PKCS#1 v1.5 padding failures all output "decryption error".
    if (c >= n) throw new Error('decryption error');
    const m = RSADP(privateKey, c); // Step 2b
    if (m >= n) throw new Error('decryption error');
    const EM = I2OSP(m, k); // Step 2c
    // Step 3: EME-PKCS1-v1_5 decoding
    if (EM[0] !== 0x00 || EM[1] !== 0x02) throw new Error('decryption error');
    // Find the position of the 0x00 byte that separates PS from M
    let sepIdx = -1;
    for (let i = 2; i < EM.length; i++) {
      if (EM[i] === 0x00) {
        sepIdx = i;
        break;
      }
    }
    // PS length must be at least 8 octets
    if (sepIdx === -1 || sepIdx < 10) throw new Error('decryption error');
    return EM.subarray(sepIdx + 1) as TRet<Uint8Array>; // Step 4
  },
});

/** PKCS#1 v1.5 signing interface. */
export interface IPKCS {
  /**
   * Verifies a PKCS#1 v1.5 signature.
   * @param publicKey - RSA public key used for verification.
   * @param M - Message bytes that were signed.
   * @param S - Signature bytes to verify.
   * @returns `true` when the signature is valid.
   */
  verify(publicKey: PublicKey, M: TArg<Uint8Array>, S: TArg<Uint8Array>): boolean;
  /**
   * Signs one message with PKCS#1 v1.5.
   * @param privateKey - RSA private key used for signing.
   * @param M - Message bytes to sign.
   * @returns Signature bytes.
   */
  sign(privateKey: PrivateKey, M: TArg<Uint8Array>): TRet<Uint8Array>;
}
/** RSASSA-PKCS1-v1_5: old Signature Scheme with Appendix (SSA) as first standardized in version 1.5 of PKCS #1. */
const PKCS1 = (hash: TArg<Hash>, prefix: string): TRet<IPKCS> =>
  /* @__PURE__ */ Object.freeze({
    // RFC 8017 §8.2 uses EMSA-PKCS1-v1_5 as a scheme parameter, so hash and prefix must stay paired for the same DigestInfo encoding.
    verify(publicKey: PublicKey, M: TArg<Uint8Array>, S: TArg<Uint8Array>): boolean {
      validatePublicKey(publicKey);
      M = ensureBytes('message', M);
      S = ensureBytes('signature', S);
      const { n, e } = publicKey;
      const k = Math.ceil(n.toString(16).length / 2);
      if (S.length !== k) return false; // Step 1
      const s = OS2IP(S); // Step 2a
      const m = RSAVP1({ n, e }, s); // Step 2b
      if (m === false) return false;
      const EM = I2OSP(m, k); // Step 2c
      if (EM.length !== k) return false;
      const EMprime = EMSA_PKCS1_V1_5_ENCODE(hash, prefix, M, k); // Step 3
      return equalBytes(EM, EMprime); // Step 4
    },
    sign(privateKey: PrivateKey, M: TArg<Uint8Array>): TRet<Uint8Array> {
      validatePrivateKey(privateKey);
      M = ensureBytes('message', M);
      const { n, d } = privateKey;
      const k = Math.ceil(n.toString(16).length / 2);
      const EM = EMSA_PKCS1_V1_5_ENCODE(hash, prefix, M, k); // Step 1
      const m = OS2IP(EM); // Step 2a
      const s = RSASP1({ n, d }, m); // Step 2b
      return I2OSP(s, k); // Step 2c
    },
  });

// Encoded OIDs
/** PKCS#1 v1.5 signer using SHA-1. */
// RFC 8017 §9.2 note 1 / Appendix B.1: `3021300906052b0e03021a05000414` is the DER DigestInfo prefix for id-sha1 with NULL parameters and a 20-byte digest.
export const PKCS1_SHA1: TRet<IPKCS> = /* @__PURE__ */ PKCS1(
  sha1,
  '3021300906052b0e03021a05000414'
);
/** PKCS#1 v1.5 signer using SHA-224. */
// RFC 8017 §9.2 note 1 / Appendix B.1: `302d300d06096086480165030402040500041c` is the DER DigestInfo prefix for id-sha224 with NULL parameters and a 28-byte digest.
export const PKCS1_SHA224: TRet<IPKCS> = /* @__PURE__ */ PKCS1(
  sha224,
  '302d300d06096086480165030402040500041c'
);
/** PKCS#1 v1.5 signer using SHA-256. */
// RFC 8017 §9.2 note 1 / Appendix B.1: `3031300d060960864801650304020105000420` is the DER DigestInfo prefix for id-sha256 with NULL parameters and a 32-byte digest.
export const PKCS1_SHA256: TRet<IPKCS> = /* @__PURE__ */ PKCS1(
  sha256,
  '3031300d060960864801650304020105000420'
);
/** PKCS#1 v1.5 signer using SHA-384. */
// RFC 8017 §9.2 note 1 / Appendix B.1: `3041300d060960864801650304020205000430` is the DER DigestInfo prefix for id-sha384 with NULL parameters and a 48-byte digest.
export const PKCS1_SHA384: TRet<IPKCS> = /* @__PURE__ */ PKCS1(
  sha384,
  '3041300d060960864801650304020205000430'
);
/** PKCS#1 v1.5 signer using SHA-512. */
// RFC 8017 §9.2 note 1 / Appendix B.1: `3051300d060960864801650304020305000440` is the DER DigestInfo prefix for id-sha512 with NULL parameters and a 64-byte digest.
export const PKCS1_SHA512: TRet<IPKCS> = /* @__PURE__ */ PKCS1(
  sha512,
  '3051300d060960864801650304020305000440'
);
/** PKCS#1 v1.5 signer using SHA-512/224. */
// RFC 8017 §9.2 note 1 / Appendix B.1: `302d300d06096086480165030402050500041c` is the DER DigestInfo prefix for id-sha512-224 with NULL parameters and a 28-byte digest.
export const PKCS1_SHA512_224: TRet<IPKCS> = /* @__PURE__ */ PKCS1(
  sha512_224,
  '302d300d06096086480165030402050500041c'
);
/** PKCS#1 v1.5 signer using SHA-512/256. */
// RFC 8017 §9.2 note 1 / Appendix B.1: `3031300d060960864801650304020605000420` is the DER DigestInfo prefix for id-sha512-256 with NULL parameters and a 32-byte digest.
export const PKCS1_SHA512_256: TRet<IPKCS> = /* @__PURE__ */ PKCS1(
  sha512_256,
  '3031300d060960864801650304020605000420'
);
// https://github.com/usnistgov/ACVP-Server/issues/257#issuecomment-1502669140
// RFC 9688 §2 says SHA3-224/256/384/512 AlgorithmIdentifier parameters
// "MUST be absent, not NULL". Policy: keep the NULL-parameter DigestInfo
// prefixes for the SHA3 PKCS#1 v1.5 variants below because OpenSSL/Node
// emit them, and switching would break compatibility with that ecosystem.
/** PKCS#1 v1.5 signer using SHA3-224. */
// RFC 9688 §2 / module mda-sha3-224 says the DigestInfo hash AlgorithmIdentifier should omit parameters; policy above keeps the NULL-parameter prefix for OpenSSL/Node compatibility.
export const PKCS1_SHA3_224: TRet<IPKCS> = /* @__PURE__ */ PKCS1(
  sha3_224,
  '302d300d06096086480165030402070500041c'
);
/** PKCS#1 v1.5 signer using SHA3-256. */
// RFC 9688 §2 / module mda-sha3-256 says the DigestInfo hash AlgorithmIdentifier should omit parameters; policy above keeps the NULL-parameter prefix for OpenSSL/Node compatibility.
export const PKCS1_SHA3_256: TRet<IPKCS> = /* @__PURE__ */ PKCS1(
  sha3_256,
  '3031300d060960864801650304020805000420'
);
/** PKCS#1 v1.5 signer using SHA3-384. */
// RFC 9688 §2 / module mda-sha3-384 says the DigestInfo hash AlgorithmIdentifier should omit parameters; policy above keeps the NULL-parameter prefix for OpenSSL/Node compatibility.
export const PKCS1_SHA3_384: TRet<IPKCS> = /* @__PURE__ */ PKCS1(
  sha3_384,
  '3041300d060960864801650304020905000430'
);
/** PKCS#1 v1.5 signer using SHA3-512. */
// RFC 9688 §2 / module mda-sha3-512 says the DigestInfo hash AlgorithmIdentifier should omit parameters; policy above keeps the NULL-parameter prefix for OpenSSL/Node compatibility.
export const PKCS1_SHA3_512: TRet<IPKCS> = /* @__PURE__ */ PKCS1(
  sha3_512,
  '3051300d060960864801650304020a05000440'
);

export const _TEST: any = /* @__PURE__ */ Object.freeze({ RSAEP, RSADP, RSASP1 });
