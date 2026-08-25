# micro-rsa-dsa-dh

Minimal implementation of older cryptography algorithms: RSA, DSA, DH.

- 🔻 Tree-shakeable: unused code is excluded from your builds
- 🔑 RSA (Rivest-Shamir-Adleman) public-key cryptosystem, with OAEP, PSS, PKCS1
- ✍️ DSA (Digital Signature Algorithm) signatures
- 🤝 DH (Diffie-Hellman) key exchange
- 📦 ElGamal encryption
- 5️⃣ Primality tests
- 🪶 16KB (gzipped)

> [!WARNING]
> Like in all JS implementations, keep in mind [timing leaks](#security)

## Usage

> `npm install micro-rsa-dsa-dh`

> `deno add jsr:@paulmillr/micro-rsa-dsa-dh`

We support all major platforms and runtimes.

A standalone file [micro-rsa-dsa-dh.js](https://github.com/paulmillr/micro-rsa-dsa-dh/releases) is also available.

- [All imports](#all-imports)
- [RSA](#rsa)
  - [OAEP](#oaep)
  - [PSS](#pss)
  - [PKCS1](#pkcs1)
- [DSA](#dsa)
- [DH](#dh)
- [ElGamal](#elgamal)
- [Primality tests](#primality-tests)
- [Security](#security)

## All imports

```js
import { DH, DHGroups, LegacyDHGroups } from 'micro-rsa-dsa-dh/dh.js';
import { DSA } from 'micro-rsa-dsa-dh/dsa.js';
import { ElGamal, genElGamalParams } from 'micro-rsa-dsa-dh/elgamal.js';
import {
  millerRabin,
  jacobi,
  lucas,
  bailliePSW,
  isProbablePrime,
  isProbablePrimeRSA,
  isProbablySafePrime,
} from 'micro-rsa-dsa-dh/primality.js';
import {
  IFCPrimes,
  keygen,
  mgf1,
  OAEP,
  PSS,
  PKCS1_KEM,
  PKCS1_SHA1,
  PKCS1_SHA224,
  PKCS1_SHA256,
  PKCS1_SHA384,
  PKCS1_SHA512,
  PKCS1_SHA512_224,
  PKCS1_SHA512_256,
  PKCS1_SHA3_224,
  PKCS1_SHA3_256,
  PKCS1_SHA3_384,
  PKCS1_SHA3_512,
} from 'micro-rsa-dsa-dh/rsa.js';
```

## RSA

RSA is most common example of integer factorization cryptography (IFC).

KEM version of RSA (encrypt/decrypt) is slow and usually used to exchange AES/ChaCha keys.

> [!WARNING]
> `keygen()` requires a modulus of at least 2048 bits, but imported `PublicKey` and `PrivateKey`
> values have no minimum-size check for compatibility. Consequently, encryption, decryption,
> signing, and verification will accept weak sub-2048-bit imported keys. Applications must require
> `key.n.toString(2).length >= 2048` before active RSA operations. If old signatures require a weak
> key, isolate that key to legacy verification and never use it for new signatures or ciphertexts.
> See [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) and
> [NIST's RSA modulus guidance](https://csrc.nist.gov/projects/cryptographic-module-validation-program/notices).

### OAEP

OAEP is Optimal Asymmetric Encryption Padding.

Use if you need KEM (encrypt/decrypt).

```ts
import { deepStrictEqual } from 'node:assert';
import * as rsa from 'micro-rsa-dsa-dh/rsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
const alice = rsa.keygen(2048);
const oaep = rsa.OAEP(sha256, rsa.mgf1(sha256));
const msg = new Uint8Array([1, 2, 3]);
const encrypted = oaep.encrypt(alice.publicKey, msg);
deepStrictEqual(oaep.decrypt(alice.privateKey, encrypted), msg);
```

### PSS

Use if you need signatures (sign/verify).

> [!WARNING]
> `PSS()` accepts caller-selected hashes and does not reject SHA-1. SHA-1 collision resistance is
> broken, so do not use it to create signatures; use SHA-256 or stronger. SHA-1 should be retained
> only where old signatures must be verified. `PKCS1_SHA1` likewise still exposes both `sign()` and
> `verify()` for compatibility: do not call its `sign()` method. Prefer RSA-PSS with SHA-256 or
> stronger for new signatures. See [NIST's SHA-1 policy](https://csrc.nist.gov/projects/hash-functions/nist-policy-on-hash-functions).

```ts
import { deepStrictEqual } from 'node:assert';
import * as rsa from 'micro-rsa-dsa-dh/rsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
const alice = rsa.keygen(2048);
const pss = rsa.PSS(sha256, rsa.mgf1(sha256));
const msg = new Uint8Array([1, 2, 3]);
const sig = pss.sign(alice.privateKey, msg);
deepStrictEqual(pss.verify(alice.publicKey, msg, sig), true);
```

### PKCS1

This is old standard, OAEP/PSS is better.

Signatures:

```ts
import { deepStrictEqual } from 'node:assert';
import * as rsa from 'micro-rsa-dsa-dh/rsa.js';
const alice = rsa.keygen(2048);
const pkcs = rsa.PKCS1_SHA256;
const msg = new Uint8Array([1, 2, 3]);
const sig = pkcs.sign(alice.privateKey, msg);
deepStrictEqual(pkcs.verify(alice.publicKey, msg, sig), true);
```

KEM (vulnerable [[1]](https://crypto.stackexchange.com/questions/12688/can-you-explain-bleichenbachers-cca-attack-on-pkcs1-v1-5),
[[2]](https://security.stackexchange.com/questions/183179/what-is-rsa-oaep-rsa-pss-in-simple-terms)
):

> [!WARNING]
> `PKCS1_KEM.decrypt()` returns plaintext for valid padding and throws for invalid padding. A service
> that exposes this distinction is a Bleichenbacher oracle and can allow adaptive plaintext recovery.
> Use OAEP for new protocols. Legacy online protocols need fixed-length implicit rejection rather
> than this generic variable-length decryption API.

```ts
import { deepStrictEqual } from 'node:assert';
import * as rsa from 'micro-rsa-dsa-dh/rsa.js';
const alice = rsa.keygen(2048);
const pkcs = rsa.PKCS1_KEM;
const msg = new Uint8Array([1, 2, 3]);
const encrypted = pkcs.encrypt(alice.publicKey, msg);
deepStrictEqual(pkcs.decrypt(alice.privateKey, encrypted), msg);
```

## DH

Same as ECDH. Use the predefined groups in `DHGroups`, which are all at least 2048 bits. Cons:

- Long keys
- Harder to protect from timing attacks
- Using custom non-standard groups can make algorithm weak

```ts
import { deepStrictEqual } from 'node:assert';
import { DH, DHGroups } from 'micro-rsa-dsa-dh/dh.js';
const dh = DH('modp18');
const alicePriv = dh.randomPrivateKey();
const alicePub = dh.getPublicKey(alicePriv);

const bobPriv = dh.randomPrivateKey();
const bobPub = dh.getPublicKey(bobPriv);

deepStrictEqual(dh.getSharedSecret(alicePriv, bobPub), dh.getSharedSecret(bobPriv, alicePub));
```

The obsolete 768-, 1024-, and 1536-bit groups are separated into `LegacyDHGroups`. They are unsafe
for new protocols and require an explicit opt-in:

```ts
import { DH, LegacyDHGroups } from 'micro-rsa-dsa-dh/dh.js';

const legacyParams = LegacyDHGroups.modp5;
const legacyDH = DH(legacyParams, { allowUnsafeLegacy: true });
```

Safe custom groups must provide `{ p, q, g }`. Construction validates size bounds, primality,
`q | p - 1`, and generator order; peer public keys are checked for subgroup membership before
secret exponentiation. Private exponents use `[2, q - 2]`. Existing unvalidated `{ p, g }` groups
can be opened only for migration with `{ unsafeAllowUnvalidatedGroup: true }`, which restores the
old `[2, p - 2]` and range-only behavior.

## DSA

> [!NOTE]
> DSA was deprecated in FIPS186-5. Imported domains are validated for supported sizes, primality,
> the `q | p - 1` relation, and generator order. The supported 1024/160 pair is retained only for
> legacy compatibility and provides roughly 80-bit classical security; prefer 2048/224, 2048/256,
> or 3072/256 when existing DSA interoperability is unavoidable. DSA also accepts caller-selected
> hashes, including SHA-1, for compatibility. SHA-1 collision resistance is broken: do not use it
> to generate parameters or new signatures, and retain it only to verify old signatures. Use an
> approved SHA-2/SHA-3 hash when existing DSA interoperability is unavoidable. See
> [NIST's SHA-1 policy](https://csrc.nist.gov/projects/hash-functions/nist-policy-on-hash-functions).

Same as ECDSA, but with big numbers. Cons:

- Deprecated
- No pre-defined groups: need to generate and send params
- Long keys
- Harder to protect from timing attacks

```ts
import { deepStrictEqual } from 'node:assert';
import * as dsa from 'micro-rsa-dsa-dh/dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
// 1. Params
// Carol generates random params
const carolParams = dsa.genDSAParams(2048, 256, sha256, 1);
// Instead of sending primes to Alice and Bob (which can be insecure), she sends seed
// This ensures that params are not constructed primes, but generated randomly:
// Alice and Bob can use these params without trusting Carol.
const seed = carolParams.domainParameterSeed;

const aliceParams = dsa.genDSAParams(2048, 256, sha256, 1, seed);
deepStrictEqual(aliceParams, carolParams); // Same params as Carol!

const bobParams = dsa.genDSAParams(2048, 256, sha256, 1, seed);
deepStrictEqual(aliceParams, bobParams); // Now Bob has same params too!

// 2. Keys
const aliceDSA = dsa.DSA(aliceParams);
const alicePrivKey = aliceDSA.randomPrivateKey();
const alicePubKey = aliceDSA.getPublicKey(alicePrivKey); // Alice generates public key and sends to Bob
const msg = new Uint8Array([1, 2, 3, 4, 5]);
const sig = aliceDSA.sign(alicePrivKey, msg); // Alice signs message

const bobDSA = dsa.DSA(bobParams);
// Now Bob can verify that message was sent by Alice (and not Carol for example).
deepStrictEqual(bobDSA.verify(alicePubKey, msg, sig), true);
```

## ElGamal

Mostly for educational purpose: almost nobody uses it.

> [!WARNING]
> `genElGamalParams()` is a legacy educational helper, not a safe production key generator. It
> continues to accept breakable sizes for compatibility and does not force the candidate's high
> bit, so `bits` is only the random candidate-input width—not a guaranteed modulus size. The small
> values below are intentionally fast, breakable examples. Generator search is bounded for each
> candidate safe prime and restarts parameter sampling if none is acceptable. [RFC 9580 §§12.6 and
> 12.8](https://www.rfc-editor.org/rfc/rfc9580.html#section-12.6) prohibits generating or using
> ElGamal keys, encryption, and signatures in modern OpenPGP; do not use this API for new protocols.

```ts
import { deepStrictEqual } from 'node:assert';
import { sha256 } from '@noble/hashes/sha2.js';
import { ElGamal, genElGamalParams } from 'micro-rsa-dsa-dh/elgamal.js';
// NOTE: this is super slow! 512: 1s, 1024: 20s, 2048: 1046s
const params = genElGamalParams(512);
const elgamal = ElGamal(params, { prehash: sha256 }); // SHA-256 is also the default

const alicePriv = elgamal.randomPrivateKey();
const alicePub = elgamal.getPublicKey(alicePriv);
// Encryption
const msg = new TextEncoder().encode('secret message');
const cipherText = elgamal.encrypt(alicePub, msg); // Somebody encrypts message using Alice public key
deepStrictEqual(elgamal.decrypt(alicePriv, cipherText), msg); // Alice can decrypt message using private key
// Sign
const signedMsg = new TextEncoder().encode('message');
const sig = elgamal.sign(alicePriv, signedMsg); // The helper prehashes this byte message
deepStrictEqual(elgamal.verify(alicePub, signedMsg, sig), true); // Other parties can verify it
```

Encryption uses an order-`q` subgroup KEM, HKDF-SHA-256, and XChaCha20-Poly1305. Its versioned
ciphertext authenticates arbitrary byte messages and does not expose the plaintext's Legendre
symbol. Decryption never auto-detects legacy ciphertexts.

Default construction validates a safe-prime group, a full-order signing generator, imported
private keys in `[2, q)`, public-key ranges, and encryption subgroup elements. It deliberately does
not impose a 2048-bit minimum because legacy and educational groups remain supported; size policy
is the caller's responsibility. The unsafe raw-encryption option also restores permissive legacy
parameter and key handling.

Textbook ElGamal's raw bigint ciphertext leaks a plaintext predicate and is malleable. The exact
legacy API and `{ ct1, ct2 }` format remain available only through
`ElGamal(params, { unsafeAllowRawEncryption: true })`; use a separately constructed instance to
decrypt old data during migration. The raw-bigint signature behavior is forgeable and separately
requires `{ unsafeDisablePrehash: true }`. Set both flags only to recreate the complete legacy API.

## Primality tests

A bunch of primality tests.

```ts
import { deepStrictEqual } from 'node:assert';
import * as primality from 'micro-rsa-dsa-dh/primality.js';
deepStrictEqual(primality.millerRabin(7n, 10), true);
deepStrictEqual(primality.lucas(7n), true);
deepStrictEqual(primality.bailliePSW(7n), true);
deepStrictEqual(primality.isProbablePrime(7n, 30), true); // Tests 30 random bases
deepStrictEqual(primality.isProbablySafePrime(7n, 10), true);
```

|                     | Reliable | Deterministic | Approx. 2048-bit prime | Performance and use                                                                                                                                                |
| ------------------- | -------- | ------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| millerRabin         | No       | No            | 68 ms (10 rounds)      | Cost scales approximately linearly with the requested iteration count. Random bases may expose pseudoprimes; increasing the count reduces that probability.        |
| lucas               | No       | Yes           | 20 ms                  | One deterministic Lucas pass. Faster here than 10 Miller–Rabin rounds, but known Lucas pseudoprimes exist.                                                         |
| bailliePSW          | Yes      | Yes           | 27 ms                  | One fixed-base Miller–Rabin pass plus Lucas. No false positives are known.                                                                                          |
| isProbablePrime     | Yes      | No            | 88 ms (10 rounds)      | Runs the requested random Miller–Rabin rounds followed by Lucas, so its cost is approximately the sum of those tests.                                               |
| isProbablySafePrime | Yes      | No            | 176 ms (10 rounds)     | Runs `isProbablePrime` for both `p` and `(p - 1) / 2`; a safe-prime candidate therefore costs roughly twice a probable-prime test.                                   |

Performance values are median wall times from seven warmed runs on Node.js 26.6.0, using the
2048-bit RFC 3526 MODP group 14 safe prime. They are comparative rather than portable: hardware and
runtime versions matter, larger inputs become substantially slower, and composite or small values
often return much earlier through trial division or the first failed round.

- _Reliable:_ no false positives are known
- _Deterministic:_ it does not rely on randomness

## Security

All algorithms use JS bigints, which are not constant-time. When timing attacks could be mounted, they will reveal sensitive information.

Generated RSA private keys include the public exponent `e`, and RSA private operations use it for
multiplicative blinding and result verification. Legacy `{ n, d }` private keys remain accepted for
compatibility but use the previous unblinded path; imported keys should include their matching `e`.
Blinding reduces RSA's input-dependent timing exposure, but it does not make JavaScript bigint
arithmetic constant-time. DSA, DH, ElGamal, and legacy RSA private operations retain the timing risk.

That generally means:

- Document, mail, messaging encryption, like PGP, is probably OK. It's hard for an attacker to measure timings: they don't know how long it took to create a msg
- Public APIs are NOT safe. Consider something like "send us document and we will auto-sign it". These cases can leak private keys

For comparison, bigint-based elliptic curve implementations will leak much less info. That's because they operate over much smaller numbers: think 2^256, instead of 2^2048.

RSA operations reject moduli wider than 16384 bits and public exponents at or above 2^256 to bound the cost of attacker-controlled bigint arithmetic. This happens after callers construct the bigint values; applications that parse untrusted serialized keys must also limit input and integer lengths before decoding them. See [badrsa](https://github.com/jedisct1/badrsa) for examples of why parsing, key validation, and operation-cost policy are separate checks.

## Links

- [RFC 3447](https://datatracker.ietf.org/doc/html/rfc3447) - old RSA
- [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017) - OAEP/PSS/PKCS1
- [RFC 8702](https://datatracker.ietf.org/doc/html/rfc8702) - RSA-PSS + Shake
- [FIPS 186-5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) - Prime generation
- [FIPS 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) - DSA
- [RFC 2631](https://datatracker.ietf.org/doc/html/rfc2631) - DH
- [RFC 3526](https://datatracker.ietf.org/doc/html/rfc3526) - DH groups
- [RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979) - DSA

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
