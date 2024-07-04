import { sha1 } from '@noble/hashes/sha1';
import { sha224, sha256 } from '@noble/hashes/sha256';
import { sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256 } from '@noble/hashes/sha3';
import { sha384, sha512, sha512_224, sha512_256 } from '@noble/hashes/sha512';
import { concatBytes, createView, hexToBytes, randomBytes } from '@noble/hashes/utils';
import { isProbablePrimeRSA } from './primality.js';
import {
  Hash,
  I2OSP,
  OS2IP,
  RandFn,
  ensureBytes,
  gcd,
  invert,
  pow,
  randomBits,
  sqrt,
} from './utils.js';

export type VarLenHash = (msg: Uint8Array, opts: { dkLen: number }) => Uint8Array; // can be mgf(sha256)

export type HashXOF = VarLenHash & {
  blockLen: number;
  create: (opts: { dkLen: number }) => any;
};

export type KEM = {
  encrypt(publicKey: PublicKey, plaintext: Uint8Array): Uint8Array;
  decrypt(privateKey: PrivateKey, ciphertext: Uint8Array): Uint8Array;
};

export type Signer = {
  verify(publicKey: PublicKey, message: Uint8Array, signature: Uint8Array): boolean;
  sign(privateKey: PrivateKey, message: Uint8Array): Uint8Array;
};

const hashOutputLen = (hash: HashXOF, dkLen: number): Hash => {
  const res = (msg: Uint8Array) => hash(msg, { dkLen });
  res.outputLen = dkLen;
  res.blockLen = hash.blockLen;
  res.create = () => hash.create({ dkLen });
  return res;
};

/**
 * Generate the RSA primes p and q according to the FIPS 186-5 standard (A.1.3 Generation of Random Primes that are Probably Prime)
 * @param nlen - Bit length of the modulus.
 * @param e - Public exponent. Must be an odd positive integer
 * @param a - Optional parameter for p ≡ a mod 8.
 * @param b - Optional parameter for q ≡ b mod 8.
 */
export function IFCPrimes(
  nlen: number,
  e: bigint = 65537n,
  a?: number,
  b?: number,
  randFn: RandFn = randomBytes
): { p: bigint; q: bigint } {
  if (nlen % 8 !== 0) throw new Error(`expected bit length aligned to byte boundary, got ${nlen}`);
  if (nlen < 2048) throw new Error(`wrong nlen=${nlen}, expected at least 2048`); // Step 1: Check nlen
  if (e <= 2n ** 16n || e >= 2n ** 256n || e % 2n === 0n)
    throw new Error(`Wrong public exponent e=${e}`); // Step 2: Check e
  const limit = sqrt(1n << BigInt(nlen - 1));
  // Step 4: Generate p
  for (let i = 0; i < 5 * nlen; i++) {
    // Step 4.1 and Step 4.7
    let p = randomBits(nlen / 2); // Step 4.2
    if (a !== undefined) p += BigInt((a - Number(p % 8n)) % 8); // Step 4.3
    else if (p % 2n === 0n) p += 1n; // Step 4.3
    if (p < limit) continue; // Step 4.4
    if (gcd(p - 1n, e) === 1n) {
      // Step 4.5
      if (isProbablePrimeRSA(p, randFn)) {
        // Step 4.5.1 and Step 4.5.2
        // Proceed to Step 5 if p is probably prime
        for (let j = 0; j < 10 * nlen; j++) {
          let q = randomBits(nlen / 2); // Step 5.2
          if (b !== undefined) q += BigInt((b - Number(q % 8n)) % 8); // Step 5.3
          else if (q % 2n === 0n) q += 1n; // Step 5.3
          if (q < limit) continue; // Step 5.4
          let distance = p - q;
          if (distance < 0n) distance = -distance;
          if (distance <= 2n ** ((BigInt(nlen) >> 1n) - 100n)) continue; // Step 5.5
          if (gcd(q - 1n, e) === 1n && isProbablePrimeRSA(q, randFn)) return { p, q }; // Step 5.6
        }
        throw new Error('failed to find q after max iterations');
      }
    }
  }
  throw new Error('failed to find p after max iterations');
}

// Compares 2 u8a-s in kinda constant time
function equalBytes(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// Takes Hash, returns VarLenHash
export function mgf1(hash: Hash): VarLenHash {
  // From noble-post-quantum
  const counterB = new Uint8Array(4);
  const counterV = createView(counterB);
  return (msg: Uint8Array, opts: { dkLen: number }) => {
    const { dkLen } = opts;
    const out = new Uint8Array(Math.ceil(dkLen / hash.outputLen) * hash.outputLen);
    if (dkLen > 2 ** 32) throw new Error('mask too long');
    for (let counter = 0, o = out; o.length; counter++) {
      counterV.setUint32(0, counter, false);
      hash.create().update(msg).update(counterB).digestInto(o);
      o = o.subarray(hash.outputLen);
    }
    out.subarray(dkLen).fill(0);
    return out.subarray(0, dkLen);
  };
}
/**
 * Represents an RSA public key.
 * @param n - The RSA modulus, a positive integer which is the product
 *            of two or more primes used in the RSA private key. This value
 *            is public and used in both encryption and signature verification.
 * @param e - The RSA public exponent, a positive integer (usually 65537). Must be coprime to the totient of the modulus.
 */
export type PublicKey = {
  n: bigint;
  e: bigint;
};

const validatePublicKey = (key: PublicKey) => {
  if (
    key === null ||
    typeof key !== 'object' ||
    typeof key.n !== 'bigint' ||
    typeof key.e !== 'bigint'
  )
    throw new Error('wrong private key');
};

/**
 * Represents a simplified RSA private key with basic components.
 * @param n - The RSA modulus, a positive integer which is the product of two primes.
 * @param d - The RSA private exponent, a positive integer used in the decryption algorithm.
 */
export type PrivateKey = {
  n: bigint;
  d: bigint;
};

const validatePrivateKey = (key: PrivateKey) => {
  if (
    key === null ||
    typeof key !== 'object' ||
    typeof key.n !== 'bigint' ||
    typeof key.d !== 'bigint'
  )
    throw new Error('wrong private key');
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
  if (m < 0n || m >= n) throw new Error('message representative out of range');
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
  if (c < 0n || c >= n) throw new Error('ciphertext representative out of range'); // Step 1
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
  if (m < 0n || m >= n) throw new Error('message representative out of range'); // Step 1
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
  if (s < 0n || s >= n) return false; // Step 1
  return pow(s, e, n); // Step 2
}

// Exported API
/**
 * Generates an RSA key pair.
 *
 * This function generates an RSA key pair using the given prime numbers `p` and `q`, and the public exponent `e`.
 * Output:
 *
 * @param p - A prime number.
 * @param q - A prime number.
 * @param e - The public exponent.
 * @returns An object containing the public key and the private key.
 */
export function keygen(nlen: number, e: bigint = 0x10001n, randFn: RandFn = randomBytes) {
  if (!Number.isSafeInteger(nlen) || nlen <= 0) throw new Error('wrong nlen');
  const { p, q } = IFCPrimes(nlen, e, undefined, undefined, randFn);
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  const d = invert(e, phi);
  return { publicKey: { e, n }, privateKey: { d, n } };
}

/**
 * improved ES; based on the optimal asymmetric encryption padding
 * @param hash
 * @param mgfHash
 * @param label optional label to be associated with the message
 */
export const OAEP = (
  hash: Hash,
  mgfHash: VarLenHash,
  label: Uint8Array = new Uint8Array()
): KEM => ({
  encrypt(publicKey: PublicKey, M: Uint8Array): Uint8Array {
    validatePublicKey(publicKey);
    const { n } = publicKey;
    const k = Math.ceil(n.toString(16).length / 2);
    const mLen = M.length;
    if (mLen > k - 2 * hash.outputLen - 2) throw new Error('message too long');
    const lHash = hash(label); // Step 2a
    const PS = new Uint8Array(k - mLen - 2 * hash.outputLen - 2); // Step 2b
    const DB = concatBytes(lHash, PS, new Uint8Array([0x01]), M); // Step 2c: DB = lHash || PS || 0x01 || M
    const seed = randomBytes(hash.outputLen); // Step 2d
    const dbMask = mgfHash(seed, { dkLen: k - hash.outputLen - 1 }); // Step 2e
    const maskedDB = DB.map((byte, idx) => byte ^ dbMask[idx]); // Step 2f
    const seedMask = mgfHash(maskedDB, { dkLen: hash.outputLen }); // Step 2g
    const maskedSeed = seed.map((byte, idx) => byte ^ seedMask[idx]); // Step 2h
    const EM = concatBytes(new Uint8Array([0x00]), maskedSeed, maskedDB); // Step 2i
    const m = OS2IP(EM); // Step 3a
    const c = RSAEP(publicKey, m); // Step 3b
    return I2OSP(c, k); // Step 3c
  },
  decrypt(privateKey: PrivateKey, C: Uint8Array): Uint8Array {
    validatePrivateKey(privateKey);
    const { n } = privateKey;
    const k = Math.ceil(n.toString(16).length / 2); // Length of the RSA modulus in bytes
    if (C.length !== k) throw new Error('incorrect ciphertext length');
    if (k < 2 * hash.outputLen + 2) throw new Error('RSA modulus too short');
    const c = OS2IP(C); // Step 2a
    const m = RSADP(privateKey, c); // Step 2b
    const EM = I2OSP(m, k); // Step 2c
    const lHash = hash(label); // Step 3a
    // Step 3b
    const Y = EM[0];
    const maskedSeed = EM.subarray(1, 1 + hash.outputLen);
    const maskedDB = EM.subarray(1 + hash.outputLen);
    const seedMask = mgfHash(maskedDB, { dkLen: hash.outputLen }); // Step 3c
    const seed = maskedSeed.map((byte, idx) => byte ^ seedMask[idx]); // Step 3d
    const dbMask = mgfHash(seed, { dkLen: k - hash.outputLen - 1 }); // Step 3e
    const DB = maskedDB.map((byte, idx) => byte ^ dbMask[idx]); // Step 3f
    const lHashPrime = DB.subarray(0, hash.outputLen); // Step 3g
    const rest = DB.subarray(hash.outputLen);
    let idx = rest.indexOf(0x01);
    if (idx === -1 || !equalBytes(lHash, lHashPrime) || Y !== 0x00)
      throw new Error('decryption error');
    // PS should be zeros
    for (let i = 0; i < idx; i++) if (rest[i] !== 0) throw new Error('decryption error');
    return rest.subarray(idx + 1);
  },
});

// PSS
type PSSOpts = { hash: Hash; mgfHash: VarLenHash; sLen: number };

function fixShake(hash: any) {
  // TODO: find better solution.
  // Problem is that spec requires different outputLen for shake, so we patch it here
  if (hash !== shake128 && hash !== shake256) return hash;
  const dkLen = hash === shake128 ? 32 : 64;
  return hashOutputLen(hash, dkLen);
}

function EMSA_PSS_ENCODE(M: Uint8Array, emBits: number, opts: PSSOpts): Uint8Array {
  let { hash, mgfHash, sLen } = opts;
  hash = fixShake(hash);
  const emLen = Math.ceil(emBits / 8);
  const mHash = hash(M); // Step 2
  if (emLen < hash.outputLen + sLen + 2) throw new Error('encoding error'); // Step 3
  const salt = sLen === 0 ? new Uint8Array() : randomBytes(sLen); // Step 4
  // Step 5: Let M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
  const Mprime = concatBytes(new Uint8Array(8), mHash, salt); // Step 5
  const H = hash(Mprime); // Step 6
  const PS = new Uint8Array(emLen - sLen - hash.outputLen - 2); // Step 7
  const DB = concatBytes(PS, new Uint8Array([0x01]), salt); // Step 8: DB = PS || 0x01 || salt
  const dbMask = mgfHash(H, { dkLen: emLen - hash.outputLen - 1 }); // Step 9
  const maskedDB = DB.map((byte, idx) => byte ^ dbMask[idx]); // Step 10
  const leftmostBits = 8 * emLen - emBits; // Step 11
  maskedDB[0] &= 0xff >> leftmostBits;
  return concatBytes(maskedDB, H, new Uint8Array([0xbc])); // Step 12: EM = maskedDB || H || 0xbc
}

function EMSA_PSS_VERIFY(M: Uint8Array, EM: Uint8Array, emBits: number, opts: PSSOpts): boolean {
  let { hash, mgfHash, sLen } = opts;
  hash = fixShake(hash);
  const emLen = Math.ceil(emBits / 8);
  const mHash = hash(M); // Step 2
  if (emLen < hash.outputLen + sLen + 2) return false; // Step 3
  if (EM[EM.length - 1] !== 0xbc) return false; // Step 4
  const maskedDB = EM.subarray(0, emLen - hash.outputLen - 1); // Step 5
  const H = EM.subarray(emLen - hash.outputLen - 1, emLen - 1); // Step 5
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
 * @param opts
 * @returns
 */
export const PSS = (hash: Hash, mgfHash: VarLenHash, sLen: number = 0): Signer => ({
  sign(privateKey: PrivateKey, M: Uint8Array): Uint8Array {
    validatePrivateKey(privateKey);
    M = ensureBytes('message', M);
    const { n, d } = privateKey;
    const emBits = n.toString(2).length - 1;
    const EM = EMSA_PSS_ENCODE(M, emBits, { hash, mgfHash, sLen });
    const emLen = Math.ceil(emBits / 8);
    const m = OS2IP(EM); // Step 2a
    const s = RSASP1({ n, d }, m); // Step 2b
    return I2OSP(s, emLen); // Step 2c
  },
  verify(publicKey: PublicKey, M: Uint8Array, S: Uint8Array): boolean {
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
    const EM = I2OSP(m, emLen); // Step 2c
    if (EM.length !== emLen) return false;
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
  hash: Hash,
  prefix: string,
  M: Uint8Array,
  emLen: number
): Uint8Array {
  const H = hash(M);
  const T = concatBytes(hexToBytes(prefix), H);
  const tLen = T.length;
  if (emLen < tLen + 11) throw new Error('intended encoded message length too short');
  const PS = new Uint8Array(emLen - tLen - 3).fill(0xff); // Step 4
  return concatBytes(new Uint8Array([0x00, 0x01]), PS, new Uint8Array([0x00]), T); // Step 5
}

/**
 * RSAES-PKCS1-v1_5: older Encryption/decryption Scheme (ES) as first standardized in version 1.5 of PKCS #1. Known-vulnerable.
 */
export const PKCS1_KEM: KEM = {
  encrypt(publicKey: PublicKey, M: Uint8Array): Uint8Array {
    validatePublicKey(publicKey);
    M = ensureBytes('message', M);
    const { n } = publicKey;
    const k = Math.ceil(n.toString(16).length / 2); // Length of the RSA modulus in bytes
    const mLen = M.length;
    if (mLen > k - 11) throw new Error('message too long'); // Step 1
    const psLen = k - mLen - 3;
    const PS = new Uint8Array(psLen); // Step 2a
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
  decrypt(privateKey: PrivateKey, C: Uint8Array): Uint8Array {
    validatePrivateKey(privateKey);
    C = ensureBytes('ciphertext', C);
    const { n } = privateKey;
    const k = Math.ceil(n.toString(16).length / 2);
    if (C.length !== k || k < 11) throw new Error('decryption error'); // Step 1
    const c = OS2IP(C); // Step 2a
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
    return EM.subarray(sepIdx + 1); // Step 4
  },
};

/**
 * RSASSA-PKCS1-v1_5: old Signature Scheme with Appendix (SSA) as first standardized in version 1.5 of PKCS #1.
 */
const PKCS1 = (hash: Hash, prefix: string) => ({
  verify(publicKey: PublicKey, M: Uint8Array, S: Uint8Array): boolean {
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
  sign(privateKey: PrivateKey, M: Uint8Array): Uint8Array {
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
export const PKCS1_SHA1 = /* @__PURE__ */ PKCS1(sha1, '3021300906052b0e03021a05000414');
export const PKCS1_SHA224 = /* @__PURE__ */ PKCS1(sha224, '302d300d06096086480165030402040500041c');
export const PKCS1_SHA256 = /* @__PURE__ */ PKCS1(sha256, '3031300d060960864801650304020105000420');
export const PKCS1_SHA384 = /* @__PURE__ */ PKCS1(sha384, '3041300d060960864801650304020205000430');
export const PKCS1_SHA512 = /* @__PURE__ */ PKCS1(sha512, '3051300d060960864801650304020305000440');
export const PKCS1_SHA512_224 = /* @__PURE__ */ PKCS1(
  sha512_224,
  '302d300d06096086480165030402050500041c'
);
export const PKCS1_SHA512_256 = /* @__PURE__ */ PKCS1(
  sha512_256,
  '3031300d060960864801650304020605000420'
);
// https://github.com/usnistgov/ACVP-Server/issues/257#issuecomment-1502669140
export const PKCS1_SHA3_224 = /* @__PURE__ */ PKCS1(
  sha3_224,
  '302d300d06096086480165030402070500041c'
);
export const PKCS1_SHA3_256 = /* @__PURE__ */ PKCS1(
  sha3_256,
  '3031300d060960864801650304020805000420'
);
export const PKCS1_SHA3_384 = /* @__PURE__ */ PKCS1(
  sha3_384,
  '3041300d060960864801650304020905000430'
);
export const PKCS1_SHA3_512 = /* @__PURE__ */ PKCS1(
  sha3_512,
  '3051300d060960864801650304020a05000440'
);

export const _TEST = { RSAEP, RSADP, RSASP1 };
