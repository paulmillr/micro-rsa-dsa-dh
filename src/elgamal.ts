import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ahash, type CHash, concatBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { isProbablySafePrime } from './primality.ts';
import {
  bytesToNumber,
  ensureBytes,
  gcd,
  getFieldBytesLength,
  I2OSP,
  invert,
  mod,
  OS2IP,
  pow,
  type RandFn,
  type TArg,
  type TRet,
} from './utils.ts';

const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _2n = /* @__PURE__ */ BigInt(2);
const _3n = /* @__PURE__ */ BigInt(3);
const KEM_VERSION = 1 as const;
const KEM_NONCE_LENGTH = 24;
const KEM_TAG_LENGTH = 16;
const KEM_KEY_LENGTH = 32;
const MAX_ELGAMAL_BITS = 16384;
const MAX_GENERATOR_ATTEMPTS = 256;
const KEM_LABEL = /* @__PURE__ */ utf8ToBytes('micro-rsa-dsa-dh/elgamal-kem-xchacha20poly1305-v1');

/** Returns random number in range [min, max) */
function randomBigInt(bytes: number, min: bigint, max: bigint, randFn: TArg<RandFn> = randomBytes) {
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
/** Authenticated, versioned ElGamal KEM ciphertext. */
export type ElGamalCiphertext = {
  /** Ciphertext format version. */
  version: 1;
  /** Fixed-width order-q ephemeral group element. */
  ephemeral: TRet<Uint8Array>;
  /** XChaCha20-Poly1305 nonce. */
  nonce: TRet<Uint8Array>;
  /** Encrypted message followed by its Poly1305 tag. */
  ciphertext: TRet<Uint8Array>;
};

/** Insecure legacy textbook-ElGamal ciphertext. */
export type UnsafeElGamalCiphertext = {
  /** Legacy ephemeral group element. */
  ct1: bigint;
  /** Legacy masked field-element plaintext. */
  ct2: bigint;
};
type ElGamalSignature = { r: bigint; s: bigint };
type ElGamalSigningApi<Message> = {
  randomPrivateKey(): bigint;
  getPublicKey(privateKey: bigint): bigint;
  sign(privateKey: bigint, message: TArg<Message>, nonce?: bigint): ElGamalSignature;
  verify(publicKey: bigint, message: TArg<Message>, sig: ElGamalSignature): boolean;
};
type SafeElGamalApi<Message> = ElGamalSigningApi<Message> & {
  encrypt(publicKey: bigint, message: TArg<Uint8Array>): ElGamalCiphertext;
  decrypt(privateKey: bigint, ciphertext: TArg<ElGamalCiphertext>): TRet<Uint8Array>;
};
type UnsafeElGamalApi<Message> = ElGamalSigningApi<Message> & {
  encrypt(publicKey: bigint, message: bigint, nonce?: bigint): UnsafeElGamalCiphertext;
  decrypt(privateKey: bigint, ciphertext: TArg<UnsafeElGamalCiphertext>): bigint;
};
/** Options for hashed ElGamal signatures. */
export type ElGamalPrehashOptions = {
  /** Hash applied to byte messages before signing or verification. Defaults to SHA-256. */
  prehash?: TArg<CHash>;
  /** Keep prehashing enabled. Use the unsafe options type to restore raw bigint signatures. */
  unsafeDisablePrehash?: false;
};

/** Explicit compatibility option for the forgeable legacy bigint signature API. */
export type ElGamalUnsafeOptions = {
  /** A prehash cannot be supplied while prehashing is disabled. */
  prehash?: never;
  /** Disable message hashing and restore legacy bigint signing. This is insecure. */
  unsafeDisablePrehash: true;
};

/** Default authenticated ElGamal encryption configuration. */
export type ElGamalSafeEncryptionOptions = {
  /** Keep authenticated byte encryption enabled. */
  unsafeAllowRawEncryption?: false;
};

/** Explicit compatibility option for insecure textbook ElGamal encryption. */
export type ElGamalRawEncryptionOptions = {
  /** Restore the legacy bigint API, ciphertext format, and permissive parameter/key handling. */
  unsafeAllowRawEncryption: true;
};

/** ElGamal configuration. */
export type ElGamalOptions = (ElGamalPrehashOptions | ElGamalUnsafeOptions) &
  (ElGamalSafeEncryptionOptions | ElGamalRawEncryptionOptions);

/**
 * Generate a random safe-prime ElGamal group for legacy or educational use.
 * Small, breakable sizes remain accepted for compatibility. The candidate high bit is not forced,
 * so `bits` is the random candidate-input width and not a guaranteed modulus bit length. RFC 9580
 * prohibits generating or using ElGamal keys in modern OpenPGP; do not use this helper for new
 * production protocols.
 * @param bits - Byte-aligned random candidate-input width.
 * @param randFn - Random-byte generator used to search for a safe prime and generator.
 * @returns Random ElGamal group parameters.
 * @throws If the requested bit length or random-byte generator is invalid. {@link Error}
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
export function genElGamalParams(bits: number, randFn: TArg<RandFn> = randomBytes): ElGamalParams {
  if (!Number.isSafeInteger(bits) || bits <= 0 || bits % 8 !== 0)
    throw new Error('number of bits should be positive integer aligned to byte boundary');
  if (typeof randFn !== 'function') throw new Error('randFn should be function');
  // 512: 1s, 1024: 20s, 2048: 1046s
  // Policy: `bits` is the width of random candidate material, not an exact
  // mathematical bit-length promise for p. RFC 4880 5.5.2 / RFC 9580 5.5.5.3
  // only define ElGamal key fields as "MPI of Elgamal prime p", "MPI of
  // Elgamal group generator g", and "MPI of Elgamal public key value
  // y (= g^x mod p where x is secret)"; they do not specify parameter
  // generation or exact modulus-length semantics. Do not force the top bit
  // here: leading-zero random draws are still `bits` random candidate bits,
  // while conditioning on a leading 1 would change the candidate distribution.
  while (true) {
    let p: bigint = _0n;
    do p = bytesToNumber(randFn(bits / 8));
    while (!isProbablySafePrime(p, 10, randFn)); // NOTE: this is very slow!
    const p1 = p - _1n;
    const q = p1 >> _1n;
    for (let attempt = 0; attempt < MAX_GENERATOR_ATTEMPTS; attempt++) {
      // g=2 -> Bleichenbacher's attack
      const g = randomBigInt(bits / 8, _3n, p, randFn);
      if (pow(g, _2n, p) === _1n) continue;
      if (pow(g, q, p) === _1n) continue;
      if (p1 % g === _0n) continue;
      const gInv = invert(g, p); // Khadir's attack
      if (p1 % gInv === _0n) continue;
      return { p, g };
    }
    // p=5 and p=7 have no generator accepted by the filters above. Resample the
    // safe prime instead of pinning the event loop in a permanent generator search.
  }
}

/**
 * Build ElGamal encryption and signing helpers for a specific group.
 * @param params - ElGamal group parameters. See {@link ElGamalParams}.
 * @param options - Signature and encryption options. See {@link ElGamalOptions}. Raw signatures
 *   and textbook encryption require separate explicit unsafe compatibility flags.
 * @returns ElGamal helpers for key generation, encryption, decryption, signing, and verification.
 * @throws On wrong argument types. {@link TypeError}
 * @throws If the supplied ElGamal group parameters, hash, or options are invalid. {@link Error}
 * @example
 * Encrypt, decrypt, sign, and verify inside a toy ElGamal group.
 * ```ts
 * import { deepStrictEqual } from 'node:assert';
 * import { ElGamal } from 'micro-rsa-dsa-dh/elgamal.js';
 * const elgamal = ElGamal({ p: 23n, g: 5n });
 * const alicePriv = 6n;
 * const alicePub = elgamal.getPublicKey(alicePriv);
 * const plaintext = new Uint8Array([8]);
 * const encrypted = elgamal.encrypt(alicePub, plaintext);
 * deepStrictEqual(elgamal.decrypt(alicePriv, encrypted), plaintext);
 * const message = new Uint8Array([8]);
 * deepStrictEqual(elgamal.verify(alicePub, message, elgamal.sign(alicePriv, message, 3n)), true);
 * ```
 */
export function ElGamal(
  params: ElGamalParams,
  options: ElGamalUnsafeOptions & ElGamalRawEncryptionOptions
): TRet<UnsafeElGamalApi<bigint>>;
export function ElGamal(
  params: ElGamalParams,
  options: ElGamalUnsafeOptions & ElGamalSafeEncryptionOptions
): TRet<SafeElGamalApi<bigint>>;
export function ElGamal(
  params: ElGamalParams,
  options: ElGamalPrehashOptions & ElGamalRawEncryptionOptions
): TRet<UnsafeElGamalApi<Uint8Array>>;
export function ElGamal(
  params: ElGamalParams,
  options?: ElGamalPrehashOptions & ElGamalSafeEncryptionOptions
): TRet<SafeElGamalApi<Uint8Array>>;
export function ElGamal(
  params: ElGamalParams,
  options: ElGamalOptions
): TRet<SafeElGamalApi<bigint | Uint8Array> | UnsafeElGamalApi<bigint | Uint8Array>>;
export function ElGamal(params: ElGamalParams, options: ElGamalOptions = {}): TRet<unknown> {
  const { p, g } = params;
  if (typeof p !== 'bigint' || typeof g !== 'bigint') throw new Error('wrong params');
  if (g <= _1n || g >= p) throw new Error('g should be in the range 1 < g < p');
  if (options === null || typeof options !== 'object' || Array.isArray(options))
    throw new TypeError('options should be object');
  const {
    prehash: customPrehash,
    unsafeDisablePrehash = false,
    unsafeAllowRawEncryption = false,
  } = options;
  if (typeof unsafeDisablePrehash !== 'boolean')
    throw new TypeError('unsafeDisablePrehash should be boolean');
  if (typeof unsafeAllowRawEncryption !== 'boolean')
    throw new TypeError('unsafeAllowRawEncryption should be boolean');
  if (unsafeDisablePrehash && customPrehash !== undefined)
    throw new Error('prehash and unsafeDisablePrehash cannot be used together');
  const prehash = unsafeDisablePrehash ? undefined : (customPrehash ?? sha256);
  if (prehash !== undefined) ahash(prehash);
  // Odd-width moduli such as 257 need whole-octet random material; dividing
  // hex length by 2 produces fractional byte lengths that randomBytes rejects.
  const pBytes = getFieldBytesLength(p);
  const p1 = p - _1n; // signature/nonce modulus, hoisted out of the methods
  const q = p1 >> _1n;
  let subgroupGenerator: bigint | undefined;
  if (!unsafeAllowRawEncryption) {
    if (p.toString(2).length > MAX_ELGAMAL_BITS)
      throw new Error(`ElGamal modulus must not exceed ${MAX_ELGAMAL_BITS} bits`);
    if (q <= _2n || !isProbablySafePrime(p, 10))
      throw new Error('authenticated encryption requires a safe-prime modulus');
    subgroupGenerator = pow(g, _2n, p); // cofactor-clear g into the order-q subgroup
    // genElGamalParams() selects a full-order generator for legacy signatures. For a
    // safe prime, g^q = -1 proves order 2q, while g^2 then has prime order q for the KEM.
    if (subgroupGenerator === _1n || pow(g, q, p) !== p1)
      throw new Error('invalid ElGamal generator');
    const gInv = invert(g, p);
    if (p1 % g === _0n || p1 % gInv === _0n) throw new Error('invalid ElGamal generator');
  }
  const validatePrivateKey = (privateKey: bigint): void => {
    if (typeof privateKey !== 'bigint') throw new Error('privateKey should be bigint');
    if (!unsafeAllowRawEncryption && (privateKey < _2n || privateKey >= q))
      throw new Error('invalid private key');
  };
  const validatePublicKey = (publicKey: bigint): void => {
    if (typeof publicKey !== 'bigint') throw new Error('publicKey should be bigint');
    if (!unsafeAllowRawEncryption && (publicKey <= _1n || publicKey >= p - _1n))
      throw new Error('invalid public key');
  };
  const safePublicKey = (publicKey: bigint): bigint => {
    validatePublicKey(publicKey);
    // Existing keys are y=g^x. Squaring maps both cosets into the prime-order subgroup
    // without requiring separate encryption and signature public keys. Since p is a
    // validated safe prime, the square is in the order-q subgroup by construction;
    // rejecting the identity completes validation without another full exponentiation.
    const cleared = pow(publicKey, _2n, p);
    if (cleared === _1n) throw new Error('invalid public key');
    return cleared;
  };
  const kemContext = (publicKey: bigint, ephemeral: TArg<Uint8Array>): TRet<Uint8Array> =>
    concatBytes(
      KEM_LABEL,
      Uint8Array.of(KEM_VERSION),
      I2OSP(p, pBytes),
      I2OSP(g, pBytes),
      I2OSP(publicKey, pBytes),
      ephemeral
    );
  const kemKey = (shared: bigint, context: TArg<Uint8Array>): TRet<Uint8Array> =>
    hkdf(sha256, I2OSP(shared, pBytes), KEM_LABEL, context, KEM_KEY_LENGTH);
  const messageRepresentative = (message: TArg<bigint | Uint8Array>): bigint => {
    if (unsafeDisablePrehash) {
      if (typeof message !== 'bigint') throw new Error('wrong message');
      return message;
    }
    return OS2IP(prehash!(ensureBytes('message', message as TArg<Uint8Array>)));
  };
  return {
    randomPrivateKey(): bigint {
      // Raw compatibility retains the historical [2, p-1) distribution. The
      // safe mode excludes q, whose public key cofactor-clears to the identity.
      return randomBigInt(pBytes, _2n, unsafeAllowRawEncryption ? p1 : q);
    },
    getPublicKey(privateKey: bigint): bigint {
      validatePrivateKey(privateKey);
      // Safe mode uses the same [2, q) interval as randomPrivateKey(). Explicit raw
      // compatibility retains the historical unrestricted-exponent behavior.
      return pow(g, privateKey, p);
    },
    encrypt(
      publicKey: bigint,
      message: TArg<bigint | Uint8Array>,
      nonce?: bigint
    ): TRet<ElGamalCiphertext | UnsafeElGamalCiphertext> {
      if (unsafeAllowRawEncryption) {
        if (typeof publicKey !== 'bigint') throw new Error('publicKey should be bigint');
        if (typeof message !== 'bigint') throw new Error('wrong message');
        // Plaintext is a field element: values outside [0, p) cannot round-trip
        // through decrypt(), which reduces mod p.
        if (message < _0n || message >= p) throw new Error('message must be in range [0, p)');
        if (nonce === undefined) nonce = randomBigInt(pBytes, _1n, p1);
        if (typeof nonce !== 'bigint' || nonce <= _0n || nonce >= p1)
          throw new Error(`invalid nonce=${nonce}`);
        const ct1 = pow(g, nonce, p);
        const ct2 = (message * pow(publicKey, nonce, p)) % p;
        return { ct1, ct2 };
      }
      if (nonce !== undefined) throw new Error('custom nonces require unsafe raw encryption');
      const plaintext = ensureBytes('message', message as TArg<Uint8Array>);
      const clearedPublicKey = safePublicKey(publicKey);
      const ephemeralSecret = randomBigInt(pBytes, _1n, q);
      const ephemeral = I2OSP(pow(subgroupGenerator!, ephemeralSecret, p), pBytes);
      const shared = pow(clearedPublicKey, ephemeralSecret, p);
      const context = kemContext(publicKey, ephemeral);
      const aeadNonce = randomBytes(KEM_NONCE_LENGTH);
      const ciphertext = xchacha20poly1305(kemKey(shared, context), aeadNonce, context).encrypt(
        plaintext
      );
      return { version: KEM_VERSION, ephemeral, nonce: aeadNonce, ciphertext };
    },
    decrypt(
      privateKey: bigint,
      ciphertext: TArg<ElGamalCiphertext | UnsafeElGamalCiphertext>
    ): TRet<bigint | TRet<Uint8Array>> {
      if (unsafeAllowRawEncryption) {
        validatePrivateKey(privateKey);
        const { ct1, ct2 } = ciphertext as UnsafeElGamalCiphertext;
        if (typeof ct1 !== 'bigint' || typeof ct2 !== 'bigint')
          throw new Error('invalid ciphertext');
        if (ct1 < _0n || ct1 >= p || ct2 < _0n || ct2 >= p) throw new Error('invalid ciphertext');
        return (ct2 * invert(pow(ct1, privateKey, p), p)) % p;
      }
      validatePrivateKey(privateKey);
      // Structural, subgroup, wrong-key, and authentication failures are deliberately
      // collapsed to one error. Safe mode never auto-detects or falls back to raw ciphertexts.
      try {
        const safeCiphertext = ciphertext as ElGamalCiphertext;
        if (safeCiphertext === null || typeof safeCiphertext !== 'object')
          throw new Error('invalid');
        if (safeCiphertext.version !== KEM_VERSION) throw new Error('invalid');
        const ephemeral = ensureBytes('ephemeral', safeCiphertext.ephemeral, pBytes);
        const aeadNonce = ensureBytes('nonce', safeCiphertext.nonce, KEM_NONCE_LENGTH);
        const encrypted = ensureBytes('ciphertext', safeCiphertext.ciphertext);
        if (encrypted.length < KEM_TAG_LENGTH) throw new Error('invalid');
        const ephemeralElement = OS2IP(ephemeral);
        if (ephemeralElement <= _1n || ephemeralElement >= p || pow(ephemeralElement, q, p) !== _1n)
          throw new Error('invalid');
        const publicKey = pow(g, privateKey, p);
        safePublicKey(publicKey);
        const shared = pow(ephemeralElement, privateKey, p);
        if (shared === _1n) throw new Error('invalid');
        const context = kemContext(publicKey, ephemeral);
        return xchacha20poly1305(kemKey(shared, context), aeadNonce, context).decrypt(encrypted);
      } catch {
        throw new Error('invalid ciphertext');
      }
    },
    sign(
      privateKey: bigint,
      message: TArg<bigint | Uint8Array>,
      nonce?: bigint
    ): { r: bigint; s: bigint } {
      validatePrivateKey(privateKey);
      const h = messageRepresentative(message);
      const isFixedNonce = nonce !== undefined;
      for (;;) {
        let k = nonce;
        if (k === undefined) {
          do k = randomBigInt(pBytes, _1n, p1);
          while (gcd(k, p1) !== _1n); // there is no invert otherwise
        }
        if (typeof k !== 'bigint' || k <= _0n || k >= p1) throw new Error(`invalid nonce=${k}`);
        const r = pow(g, k, p);
        const kInv = invert(k, p1);
        const s = mod(kInv * (h - privateKey * r), p1);
        // s = 0 cannot pass the range check in verify(); a fresh nonce is required.
        if (s === _0n) {
          if (isFixedNonce) throw new Error('sign: s = 0, use a different nonce');
          continue;
        }
        return { r, s };
      }
    },
    verify(
      publicKey: bigint,
      message: TArg<bigint | Uint8Array>,
      sig: { r: bigint; s: bigint }
    ): boolean {
      validatePublicKey(publicKey);
      // Safe mode rejects the identity and order-2 public elements. Explicit raw
      // compatibility retains the historical unrestricted-public-key behavior.
      if (typeof sig.r !== 'bigint' || typeof sig.s !== 'bigint')
        throw new Error('invalid signature');
      // RFC 2440 §12.5: verifiers must check 0 < r < p and 0 < s < p - 1.
      // Without this, valid signatures are malleable (s + (p-1) also passes)
      // and Bleichenbacher's CRT forgery transforms one valid signature into
      // signatures over arbitrary messages.
      if (sig.r <= _0n || sig.r >= p || sig.s <= _0n || sig.s >= p1) return false;
      const h = messageRepresentative(message);
      const gH = pow(g, h, p);
      const yR = pow(publicKey, sig.r, p);
      const rS = pow(sig.r, sig.s, p);
      const yRrS = mod(yR * rS, p);
      return gH === yRrS;
    },
  };
}
