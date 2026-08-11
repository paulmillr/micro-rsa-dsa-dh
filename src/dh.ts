import { randomBytes } from '@noble/hashes/utils.js';
import {
  bytesToNumber,
  ensureBytes,
  getFieldBytesLength,
  getMinHashLength,
  mapHashToField,
  numberToBytesBE,
  pow,
  type TArg,
  type TRet,
} from './utils.ts';

const _1n = /* @__PURE__ */ BigInt(1);
const _2n = /* @__PURE__ */ BigInt(2);

/** Classic finite-field Diffie-Hellman group parameters. */
export type DHGroup = {
  /** Finite-field prime modulus for the DH group. */
  p: bigint;
  /** Generator for the chosen subgroup. */
  g: bigint;
};

const group = (p: bigint, g: bigint): Readonly<DHGroup> => /* @__PURE__ */ Object.freeze({ p, g });

/** Short names of the built-in MODP groups. */
export type DHGroupName =
  | 'modp1'
  | 'modp2'
  | 'modp5'
  | 'modp14'
  | 'modp15'
  | 'modp16'
  | 'modp17'
  | 'modp18';
type DHApi = {
  randomPrivateKey(): Uint8Array;
  getPublicKey(privateKey: Uint8Array): Uint8Array;
  getSharedSecret(privateA: Uint8Array, publicB: Uint8Array): Uint8Array;
};

/**
 * Built-in MODP groups keyed by their short names.
 * RFC 2412 Appendix E and RFC 3526 §§3-7: these property names follow
 * the Oakley/IKE group numbers for the published MODP parameters.
 * @example
 * Pick one of the built-in MODP groups before deriving keys.
 * ```ts
 * import { DH, DHGroups } from 'micro-rsa-dsa-dh/dh.js';
 * const group = DHGroups.modp14;
 * const dh = DH(group);
 * const privateKey = dh.randomPrivateKey();
 * privateKey;
 * ```
 */
export const DHGroups: Readonly<Record<DHGroupName, Readonly<DHGroup>>> =
  /* @__PURE__ */ Object.freeze({
    modp1: group(
      BigInt(
        '0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1' +
          '29024e088a67cc74020bbea63b139b22514a08798e3404dd' +
          'ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245' +
          'e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff'
      ),
      _2n
    ),
    modp2: group(
      BigInt(
        '0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1' +
          '29024e088a67cc74020bbea63b139b22514a08798e3404dd' +
          'ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245' +
          'e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed' +
          'ee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381' +
          'ffffffffffffffff'
      ),
      _2n
    ),
    modp5: group(
      BigInt(
        '0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1' +
          '29024e088a67cc74020bbea63b139b22514a08798e3404dd' +
          'ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245' +
          'e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed' +
          'ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d' +
          'c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f' +
          '83655d23dca3ad961c62f356208552bb9ed529077096966d' +
          '670c354e4abc9804f1746c08ca237327ffffffffffffffff'
      ),
      _2n
    ),
    modp14: group(
      BigInt(
        '0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1' +
          '29024e088a67cc74020bbea63b139b22514a08798e3404dd' +
          'ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245' +
          'e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed' +
          'ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d' +
          'c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f' +
          '83655d23dca3ad961c62f356208552bb9ed529077096966d' +
          '670c354e4abc9804f1746c08ca18217c32905e462e36ce3b' +
          'e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9' +
          'de2bcbf6955817183995497cea956ae515d2261898fa0510' +
          '15728e5a8aacaa68ffffffffffffffff'
      ),
      _2n
    ),
    modp15: group(
      BigInt(
        '0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1' +
          '29024e088a67cc74020bbea63b139b22514a08798e3404dd' +
          'ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245' +
          'e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed' +
          'ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d' +
          'c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f' +
          '83655d23dca3ad961c62f356208552bb9ed529077096966d' +
          '670c354e4abc9804f1746c08ca18217c32905e462e36ce3b' +
          'e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9' +
          'de2bcbf6955817183995497cea956ae515d2261898fa0510' +
          '15728e5a8aaac42dad33170d04507a33a85521abdf1cba64' +
          'ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7' +
          'abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6b' +
          'f12ffa06d98a0864d87602733ec86a64521f2b18177b200c' +
          'bbe117577a615d6c770988c0bad946e208e24fa074e5ab31' +
          '43db5bfce0fd108e4b82d120a93ad2caffffffffffffffff'
      ),
      _2n
    ),
    modp16: group(
      BigInt(
        '0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1' +
          '29024e088a67cc74020bbea63b139b22514a08798e3404dd' +
          'ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245' +
          'e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed' +
          'ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d' +
          'c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f' +
          '83655d23dca3ad961c62f356208552bb9ed529077096966d' +
          '670c354e4abc9804f1746c08ca18217c32905e462e36ce3b' +
          'e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9' +
          'de2bcbf6955817183995497cea956ae515d2261898fa0510' +
          '15728e5a8aaac42dad33170d04507a33a85521abdf1cba64' +
          'ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7' +
          'abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6b' +
          'f12ffa06d98a0864d87602733ec86a64521f2b18177b200c' +
          'bbe117577a615d6c770988c0bad946e208e24fa074e5ab31' +
          '43db5bfce0fd108e4b82d120a92108011a723c12a787e6d7' +
          '88719a10bdba5b2699c327186af4e23c1a946834b6150bda' +
          '2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6' +
          '287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed' +
          '1f612970cee2d7afb81bdd762170481cd0069127d5b05aa9' +
          '93b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199' +
          'ffffffffffffffff'
      ),
      _2n
    ),
    modp17: group(
      BigInt(
        '0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1' +
          '29024e088a67cc74020bbea63b139b22514a08798e3404dd' +
          'ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245' +
          'e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed' +
          'ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d' +
          'c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f' +
          '83655d23dca3ad961c62f356208552bb9ed529077096966d' +
          '670c354e4abc9804f1746c08ca18217c32905e462e36ce3b' +
          'e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9' +
          'de2bcbf6955817183995497cea956ae515d2261898fa0510' +
          '15728e5a8aaac42dad33170d04507a33a85521abdf1cba64' +
          'ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7' +
          'abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6b' +
          'f12ffa06d98a0864d87602733ec86a64521f2b18177b200c' +
          'bbe117577a615d6c770988c0bad946e208e24fa074e5ab31' +
          '43db5bfce0fd108e4b82d120a92108011a723c12a787e6d7' +
          '88719a10bdba5b2699c327186af4e23c1a946834b6150bda' +
          '2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6' +
          '287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed' +
          '1f612970cee2d7afb81bdd762170481cd0069127d5b05aa9' +
          '93b4ea988d8fddc186ffb7dc90a6c08f4df435c934028492' +
          '36c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bd' +
          'f8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831' +
          '179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1b' +
          'db7f1447e6cc254b332051512bd7af426fb8f401378cd2bf' +
          '5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6' +
          'd55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f3' +
          '23a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aa' +
          'cc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be328' +
          '06a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55c' +
          'da56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee' +
          '12bf2d5b0b7474d6e694f91e6dcc4024ffffffffffffffff'
      ),
      _2n
    ),
    modp18: group(
      BigInt(
        '0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1' +
          '29024e088a67cc74020bbea63b139b22514a08798e3404dd' +
          'ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245' +
          'e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed' +
          'ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d' +
          'c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f' +
          '83655d23dca3ad961c62f356208552bb9ed529077096966d' +
          '670c354e4abc9804f1746c08ca18217c32905e462e36ce3b' +
          'e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9' +
          'de2bcbf6955817183995497cea956ae515d2261898fa0510' +
          '15728e5a8aaac42dad33170d04507a33a85521abdf1cba64' +
          'ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7' +
          'abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6b' +
          'f12ffa06d98a0864d87602733ec86a64521f2b18177b200c' +
          'bbe117577a615d6c770988c0bad946e208e24fa074e5ab31' +
          '43db5bfce0fd108e4b82d120a92108011a723c12a787e6d7' +
          '88719a10bdba5b2699c327186af4e23c1a946834b6150bda' +
          '2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6' +
          '287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed' +
          '1f612970cee2d7afb81bdd762170481cd0069127d5b05aa9' +
          '93b4ea988d8fddc186ffb7dc90a6c08f4df435c934028492' +
          '36c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bd' +
          'f8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831' +
          '179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1' +
          'bdb7f1447e6cc254b332051512bd7af426fb8f401378cd2' +
          'bf5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74f' +
          'ef6d55e702f46980c82b5a84031900b1c9e59e7c97fbec7' +
          'e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4' +
          '154aacc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef2' +
          '9be32806a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a' +
          '313d55cda56c9ec2ef29632387fe8d76e3c0468043e8f66' +
          '3f4860ee12bf2d5b0b7474d6e694f91e6dbe115974a3926' +
          'f12fee5e438777cb6a932df8cd8bec4d073b931ba3bc832' +
          'b68d9dd300741fa7bf8afc47ed2576f6936ba424663aab6' +
          '39c5ae4f5683423b4742bf1c978238f16cbe39d652de3fd' +
          'b8befc848ad922222e04a4037c0713eb57a81a23f0c7347' +
          '3fc646cea306b4bcbc8862f8385ddfa9d4b7fa2c087e879' +
          '683303ed5bdd3a062b3cf5b3a278a66d2a13f83f44f82dd' +
          'f310ee074ab6a364597e899a0255dc164f31cc50846851d' +
          'f9ab48195ded7ea1b1d510bd7ee74d73faf36bc31ecfa26' +
          '8359046f4eb879f924009438b481c6cd7889a002ed5ee38' +
          '2bc9190da6fc026e479558e4475677e9aa9e3050e276569' +
          '4dfc81f56e880b96e7160c980dd98edd3dfffffffffffff' +
          'ffff'
      ),
      _2n
    ),
  });

/**
 * Basic Diffie Hellman implementation with focus on simplicity.
 * For now: non-constant time operations, no precomputes.
 *
 * We can speed up operations the same way as in `@noble/curves`,
 * but if re-key happens often it could be slow.
 * @param group - Built-in MODP group name or explicit `{ p, g }` parameters.
 * @returns Diffie-Hellman helpers for key generation and shared-secret derivation.
 * @throws If the group selector or supplied group parameters are invalid. {@link Error}
 * @example
 * Derive the same shared secret on both sides of a toy DH group.
 * ```ts
 * import { deepStrictEqual } from 'node:assert';
 * import { DH } from 'micro-rsa-dsa-dh/dh.js';
 * const dh = DH({ p: 23n, g: 5n });
 * const alice = Uint8Array.of(6);
 * const bob = Uint8Array.of(15);
 * const alicePub = dh.getPublicKey(alice);
 * const bobPub = dh.getPublicKey(bob);
 * deepStrictEqual(dh.getSharedSecret(alice, bobPub), dh.getSharedSecret(bob, alicePub));
 * ```
 */
export const DH = (group: DHGroupName | DHGroup): TRet<DHApi> => {
  if (typeof group === 'string') group = DHGroups[group];
  if (!group) throw new Error('DH: wrong group');
  const { p, g } = group;
  if (typeof p !== 'bigint' || typeof g !== 'bigint') throw new Error('DH: wrong group params');
  const bytesLen = getFieldBytesLength(p);
  // Interval endpoints for key validation, hoisted out of the per-call helpers.
  const pm1 = p - _1n;
  const pm2 = p - _2n;
  const privateKeyNum = (key: TArg<Uint8Array>) => {
    const priv = bytesToNumber(ensureBytes('private key', key, bytesLen));
    // RFC 7919 §5.2: FFDHE peers choose a "secret exponent from the range [2, p-2]".
    // RFC 2785 §1.2 and RFC 2631 §2.1.5 use [2, q-2] for X9.42 groups; this p/g-only API
    // enforces the generic finite-field endpoint guard before exponentiation.
    // Node crypto accepts private exponent 1 here, but this helper follows
    // the RFC interval more strictly.
    if (priv < _2n || priv > pm2) throw new Error('DH: invalid private key');
    return priv;
  };
  const publicKeyNum = (key: TArg<Uint8Array>) => {
    const pub = bytesToNumber(ensureBytes('public key', key, bytesLen));
    // RFC 7919 §5.1: FFDHE peers MUST validate public keys with "1 < Y < p-1".
    // RFC 2631 §2.1.5 and RFC 2785 §3.1 also reject received public keys outside [2, p-1];
    // excluding p-1 follows the stricter FFDHE endpoint check and matches Node crypto.
    if (pub < _2n || pub >= pm1) throw new Error('DH: invalid public key');
    return pub;
  };
  return {
    randomPrivateKey(): TRet<Uint8Array> {
      // RFC 7919 §5.2: FFDHE peers choose a "secret exponent from the range [2, p-2]".
      // RFC 2785 §1.2 and RFC 2631 §2.1.5 use [2, q-2] for X9.42 private keys;
      // this p/g-only API maps generated exponents into the same endpoint-excluding shape.
      return mapHashToField(randomBytes(getMinHashLength(p)), p, _2n);
    },
    getPublicKey(privateKey: TArg<Uint8Array>): TRet<Uint8Array> {
      const privNum = privateKeyNum(privateKey);
      const n = pow(g, privNum, p); // g^privateKey mod p
      // Public keys must stay fixed-width so they can round-trip into getSharedSecret()
      // even when the modular exponentiation result has leading zero bytes.
      return numberToBytesBE(n, bytesLen);
    },
    getSharedSecret(privateA: TArg<Uint8Array>, publicB: TArg<Uint8Array>): TRet<Uint8Array> {
      const privNum = privateKeyNum(privateA);
      const pubNum = publicKeyNum(publicB);
      const n = pow(pubNum, privNum, p); // publicB^privateA mod p
      return numberToBytesBE(n, bytesLen);
    },
  };
};

/**
 * Alias for `DH()`.
 * @param group - Built-in MODP group name or explicit `{ p, g }` parameters.
 * @returns Diffie-Hellman helpers for key generation and shared-secret derivation.
 * @example
 * Use the friendlier alias for the same DH helper.
 * ```ts
 * import { deepStrictEqual } from 'node:assert';
 * import { diffieHellman } from 'micro-rsa-dsa-dh/dh.js';
 * const dh = diffieHellman({ p: 23n, g: 5n });
 * const alice = Uint8Array.of(6);
 * const bob = Uint8Array.of(15);
 * const alicePub = dh.getPublicKey(alice);
 * const bobPub = dh.getPublicKey(bob);
 * deepStrictEqual(dh.getSharedSecret(alice, bobPub), dh.getSharedSecret(bob, alicePub));
 * ```
 */
export const diffieHellman: typeof DH = DH;
