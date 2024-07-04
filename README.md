# micro-rsa-dsa-dh

Minimal implementation of older cryptography algorithms: RSA, DSA, DH.

- 🔻 Tree-shakeable: unused code is excluded from your builds
- 🔑 RSA (Rivest-Shamir-Adleman) public-key cryptosystem, with OAEP, PSS, PKCS1
- ✍️ DSA (Digital Signature Algorithm) signatures
- 🤝 DH (Diffie-Hellman) key exchange
- 📦 ElGamal encryption
- 5️⃣ Primality tests

> [!WARNING]
> Like in all JS implementations, keep in mind [timing leaks](#security)

## Usage

> npm install micro-rsa-dsa-dh

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
import { DH, DHGroups } from 'micro-rsa-dsa-dh/dh.js';
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
  IFCPrimes,
} from 'micro-rsa-dsa-dh/primality.js';
import {
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

### OAEP

OAEP is Optimal Asymmetric Encryption Padding.

Use if you need KEM (encrypt/decrypt).

```ts
import * as rsa from 'micro-rsa-dsa-dh/rsa.js';
import { sha256 } from '@noble/hashes/sha2';
const alice = rsa.keygen(2048);
const oaep = rsa.OAEP(sha256, rsa.mgf1(sha256));
const msg = new Uint8Array([1, 2, 3]);
const encrypted = oaep.encrypt(alice.publicKey, msg);
deepStrictEqual(oaep.decrypt(alice.privateKey, encrypted), msg);
```

### PSS

Use if you need signatures (sign/verify).

```ts
import * as rsa from 'micro-rsa-dsa-dh/rsa.js';
import { sha256 } from '@noble/hashes/sha2';
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

```ts
import * as rsa from 'micro-rsa-dsa-dh/rsa.js';
const alice = rsa.keygen(2048);
const pkcs = rsa.PKCS1_KEM;
const msg = new Uint8Array([1, 2, 3]);
const encrypted = pkcs.encrypt(alice.publicKey, msg);
deepStrictEqual(pkcs.decrypt(alice.privateKey, encrypted), msg);
```

## DH

Same as ECDH, seems safe if pre-defined groups are used. Cons:

- Long keys
- Harder to protect from timing attacks
- Using custom non-standard groups can make algorithm weak

```ts
import { DH, DHGroups } from 'micro-rsa-dsa-dh/dh.js';
const dh = DH('modp18');
const alicePriv = dh.randomPrivateKey();
const alicePub = dh.getPublicKey(alicePriv);

const bobPriv = dh.randomPrivateKey();
const bobPub = dh.getPublicKey(bobPriv);

deepStrictEqual(
  dh.getSharedSecret(alicePriv, bobPub),
  dh.getSharedSecret(bobPriv, alicePub)
);
```

## DSA

> [!NOTE]
> DSA was deprecated in FIPS186-5.

Same as ECDSA, but with big numbers. Cons:

- Deprecated
- No pre-defined groups: need to generate and send params
- Long keys
- Harder to protect from timing attacks

```ts
import * as dsa from 'micro-rsa-dsa-dh/dsa.js';
import { sha256 } from '@noble/hashes/sha2';
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

```ts
import { ElGamal, genElGamalParams } from 'micro-rsa-dsa-dh/elgamal.js';
// NOTE: this is super slow! 512: 1s, 1024: 20s, 2048: 1046s
const params = genElGamalParams(512);
const elgamal = ElGamal(params);

const alicePriv = elgamal.randomPrivateKey();
const alicePub = elgamal.getPublicKey(alicePriv);
// Encryption
const msg = 12345n; // bigint, because there is not spec for padding/hashing
const cipherText = elgamal.encrypt(alicePub, msg); // Somebody encrypts message using Alice public key
deepStrictEqual(elgamal.decrypt(alicePriv, cipherText), msg); // Alice can decrypt message using private key
// Sign
const sig = elgamal.sign(alicePriv, msg); // Alice sings message using private key
deepStrictEqual(elgamal.verify(alicePub, msg, sig), true); // Other parties can verify it using Alice public key
```

## Primality tests

A bunch of primality tests.

```ts
import * as primality from 'micro-rsa-dsa-dh/primality.js';
deepStrictEqual(primality.millerRabin(7n, 10), true);
deepStrictEqual(primality.lucas(7n), true);
deepStrictEqual(primality.bailliePSW(7n), true);
deepStrictEqual(primality.isProbablePrime(7n, 30), true); // Tests 30 random bases
deepStrictEqual(primality.isProbablySafePrime(7n, 10), true);
```

|                     | Reliable | Deterministic | Note                                                                                                                                                                      |
|---------------------|----------|---------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| millerRabin         | No       | No            | Non-deterministic Miller-Rabin test over random bases (multiple iterations).                                                                                              |
| lucas               | No       | Yes           | Deterministic Lucas test. Generally slower than the Miller-Rabin test but can be more reliable for certain numbers.                                                       |
| bailliePSW          | Yes      | Yes           | Deterministic test which consists of Miller-Rabin with base 2 and Lucas test. Suitable for critical applications where the highest reliability is required.               |
| isProbablePrime     | Yes      | No            | Non-deterministic test from FIPS186-5. This is an enhanced version of the Baillie-PSW test, incorporating multiple rounds of the Miller-Rabin test with random bases      |
| isProbablySafePrime | Yes       | No            | Non-deterministic safe prime test. Slow. Tests if a number is a probable safe prime. A safe prime is a prime number of the form p = 2q + 1, where both p and q are prime. |

* *Reliable:* no false positives are known
* *Deterministic:* it does not rely on randomness

## Security

All algorithms use JS bigints, which are not constant-time. When timing attacks could be mounted, they will reveal sensitive information.

That generally means:

- Document, mail, messaging encryption, like PGP, is probably OK. It's hard for an attacker to measure timings: they don't know how long it took to create a msg
- Public APIs are NOT safe. Consider something like "send us document and we will auto-sign it". These cases can leak private keys

For comparison, bigint-based elliptic curve implementations will leak much less info. That's because they operate over much smaller numbers: think 2^256, instead of 2^2048.

## Links

- https://datatracker.ietf.org/doc/html/rfc3447 - old RSA
- https://datatracker.ietf.org/doc/html/rfc8017 - OAEP/PSS/PKCS1
- https://datatracker.ietf.org/doc/html/rfc8702 - RSA-PSS + Shake
- https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf - Prime generation
- https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf - DSA
- https://datatracker.ietf.org/doc/html/rfc2631 - DH
- https://datatracker.ietf.org/doc/html/rfc3526 - DH groups
- https://datatracker.ietf.org/doc/html/rfc6979 - DSA

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
