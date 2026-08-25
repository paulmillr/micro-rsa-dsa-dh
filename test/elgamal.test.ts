import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, notDeepStrictEqual, throws } from 'node:assert';
import * as elg from '../src/elgamal.ts';
import { invert, mod, OS2IP, pow } from '../src/utils.ts';

// Tests from 'https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/SelfTest/PublicKey/test_ElGamal.py'
// There is no real test vectors, nobody uses it.
const ENCRYPTION = [
  // 256 bits
  {
    p: 'BA4CAEAAED8CBE952AFD2126C63EB3B345D65C2A0A73D2A3AD4138B6D09BD933',
    g: '05',
    y: '60D063600ECED7C7C55146020E7A31C4476E9793BEAED420FEC9E77604CAE4EF',
    x: '1D391BA2EE3C37FE1BA175A69B2C73A11238AD77675932',
    k: 'F5893C5BAB4131264066F57AB3D8AD89E391A0B68A68A1',
    pt: '48656C6C6F207468657265',
    ct1: '32BFD5F487966CEA9E9356715788C491EC515E4ED48B58F0F00971E93AAA5EC7',
    ct2: '7BE8FBFF317C93E82FCEF9BD515284BA506603FEA25D01C0CB874A31F315EE68',
  },
  // 512 bits
  {
    p: 'F1B18AE9F7B4E08FDA9A04832F4E919D89462FD31BF12F92791A93519F75076D6CE3942689CDFF2F344CAFF0F82D01864F69F3AECF566C774CBACF728B81A227',
    g: '07',
    y: '688628C676E4F05D630E1BE39D0066178CA7AA83836B645DE5ADD359B4825A12B02EF4252E4E6FA9BEC1DB0BE90F6D7C8629CABB6E531F472B2664868156E20C',
    x: '14E60B1BDFD33436C0DA8A22FDC14A2CCDBBED0627CE68',
    k: '38DBF14E1F319BDA9BAB33EEEADCAF6B2EA5250577ACE7',
    pt: '48656C6C6F207468657265',
    ct1: '290F8530C2CC312EC46178724F196F308AD4C523CEABB001FACB0506BFED676083FE0F27AC688B5C749AB3CB8A80CD6F7094DBA421FB19442F5A413E06A9772B',
    ct2: '1D69AAAD1DC50493FB1B8E8721D621D683F3BF1321BE21BC4A43E11B40C9D4D9C80DE3AAC2AB60D31782B16B61112E68220889D53C4C3136EE6F6CE61F8A23A0',
  },
];

const SIGNATURE = [
  // 256 bits
  {
    p: 'D2F3C41EA66530838A704A48FFAC9334F4701ECE3A97CEE4C69DD01AE7129DD7',
    g: '05',
    y: 'C3F9417DC0DAFEA6A05C1D2333B7A95E63B3F4F28CC962254B3256984D1012E7',
    x: '165E4A39BE44D5A2D8B1332D416BC559616F536BC735BB',
    k: 'C7F0C794A7EAD726E25A47FF8928013680E73C51DD3D7D99BFDA8F492585928F',
    h: '48656C6C6F207468657265',
    sig1: '35CA98133779E2073EF31165AFCDEB764DD54E96ADE851715495F9C635E1E7C2',
    sig2: '0135B88B1151279FE5D8078D4FC685EE81177EE9802AB123A73925FC1CB059A7',
  },
  // 512 bits
  {
    p: 'E24CF3A4B8A6AF749DCA6D714282FE4AABEEE44A53BB6ED15FBE32B5D3C3EF9CC4124A2ECA331F3C1C1B667ACA3766825217E7B5F9856648D95F05330C6A19CF',
    g: '0B',
    y: '2AD3A1049CA5D4ED207B2431C79A8719BB4073D4A94E450EA6CEE8A760EB07ADB67C0D52C275EE85D7B52789061EE45F2F37D9B2AE522A51C28329766BFE68AC',
    x: '16CBB4F46D9ECCF24FF9F7E63CAA3BD8936341555062AB',
    k: '8A3D89A4E429FD2476D7D717251FB79BF900FFE77444E6BB8299DC3F84D0DD57ABAB50732AE158EA52F5B9E7D8813E81FD9F79470AE22F8F1CF9AEC820A78C69',
    h: '48656C6C6F207468657265',
    sig1: 'BE001AABAFFF976EC9016198FBFEA14CBEF96B000CCC0063D3324016F9E91FE80D8F9325812ED24DDB2B4D4CF4430B169880B3CE88313B53255BD4EC0378586F',
    sig2: '5E266F3F837BA204E3BBB6DBECC0611429D96F8C7CE8F4EFDF9D4CB681C2A954468A357BF4242CEC7418B51DFC081BCD21299EF5B5A0DDEF3A139A1817503DDE',
  },
];

describe('ElGamal', () => {
  should('restarts parameter generation when a safe prime has no acceptable generator', () => {
    let calls = 0;
    const rand = (bytes: number) => {
      deepStrictEqual(bytes, 1);
      calls++;
      if (calls === 1) return Uint8Array.of(5);
      if (calls <= 257) return Uint8Array.of(3);
      if (calls === 258) return Uint8Array.of(11);
      return Uint8Array.of(7);
    };
    deepStrictEqual(elg.genElGamalParams(8, rand), { p: 11n, g: 7n });
    deepStrictEqual(calls, 259);
  });

  should('Example', () => {
    // NOTE: this is super slow! 512: 1s, 1024: 20s, 2048: 1046s
    const params = elg.genElGamalParams(512);
    const elgamal = elg.ElGamal(params);

    const alicePriv = elgamal.randomPrivateKey();
    const alicePub = elgamal.getPublicKey(alicePriv);
    // Encryption
    const plaintext = new TextEncoder().encode('message');
    const cipherText = elgamal.encrypt(alicePub, plaintext); // Somebody encrypts message using Alice public key
    deepStrictEqual(elgamal.decrypt(alicePriv, cipherText), plaintext); // Alice can decrypt message using private key
    // Sign
    const message = new TextEncoder().encode('message');
    const sig = elgamal.sign(alicePriv, message); // Alice signs message using private key
    deepStrictEqual(elgamal.verify(alicePub, message, sig), true); // Other parties can verify it using Alice public key
  });
  should('Encryption', () => {
    for (const t of ENCRYPTION) {
      const p = BigInt(`0x${t.p}`);
      const g = BigInt(`0x${t.g}`);
      const x = BigInt(`0x${t.x}`);
      const y = BigInt(`0x${t.y}`);
      const k = BigInt(`0x${t.k}`);
      const ct1 = BigInt(`0x${t.ct1}`);
      const ct2 = BigInt(`0x${t.ct2}`);
      const pt = BigInt(`0x${t.pt}`);
      const elgamal = elg.ElGamal({ p, g }, { unsafeAllowRawEncryption: true });
      deepStrictEqual(elgamal.getPublicKey(x), y);
      deepStrictEqual(elgamal.decrypt(x, { ct1, ct2 }), pt);
      deepStrictEqual(elgamal.encrypt(y, pt, k), { ct1, ct2 });
    }
  });
  should('Signature', () => {
    for (const t of SIGNATURE) {
      const p = BigInt(`0x${t.p}`);
      const g = BigInt(`0x${t.g}`);
      const x = BigInt(`0x${t.x}`);
      const y = BigInt(`0x${t.y}`);
      const k = BigInt(`0x${t.k}`);
      const h = BigInt(`0x${t.h}`);
      const r = BigInt(`0x${t.sig1}`);
      const s = BigInt(`0x${t.sig2}`);
      const sig = { r, s };
      const elgamal = elg.ElGamal(
        { p, g },
        { unsafeDisablePrehash: true, unsafeAllowRawEncryption: true }
      );
      deepStrictEqual(elgamal.getPublicKey(x), y);
      deepStrictEqual(elgamal.sign(x, h, k), sig);
      deepStrictEqual(elgamal.verify(y, h, sig), true);
    }
  });
  should('handles odd-byte modulus widths in generated secrets', () => {
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: {
        getRandomValues(arr: Uint8Array) {
          arr.set(Uint8Array.of(0, 5));
          return arr;
        },
      },
    });
    try {
      const elgamal = elg.ElGamal({ p: 263n, g: 5n });
      const privateKey = elgamal.randomPrivateKey();
      deepStrictEqual(privateKey, 5n);
      const publicKey = elgamal.getPublicKey(7n);
      const plaintext = Uint8Array.of(9);
      deepStrictEqual(elgamal.decrypt(7n, elgamal.encrypt(publicKey, plaintext)), plaintext);
      const message = Uint8Array.of(9);
      deepStrictEqual(elgamal.verify(publicKey, message, elgamal.sign(7n, message)), true);
    } finally {
      if (saved) Object.defineProperty(globalThis, 'crypto', saved);
    }
  });
});

describe('ElGamal regressions', () => {
  should('prehash signatures by default and reject the raw existential forgery', () => {
    const p = 23n;
    const g = 5n;
    const y = 8n;
    const B = 2n;
    const C = 3n;
    const r = mod(pow(g, B, p) * pow(y, C, p), p);
    const s = mod(-r * invert(C, p - 1n), p - 1n);
    const forgedMessage = mod(B * s, p - 1n);
    const forgedSignature = { r, s };

    const legacy = elg.ElGamal({ p, g }, { unsafeDisablePrehash: true });
    deepStrictEqual(legacy.verify(y, forgedMessage, forgedSignature), true);

    const message = new TextEncoder().encode('message');
    const safe = elg.ElGamal({ p, g });
    deepStrictEqual(safe.verify(y, message, forgedSignature), false);
    const signature = safe.sign(6n, message, 3n);
    deepStrictEqual(safe.verify(y, message, signature), true);
    deepStrictEqual(elg.ElGamal({ p, g }, { prehash: sha256 }).sign(6n, message, 3n), signature);
    const sha512ElGamal = elg.ElGamal({ p, g }, { prehash: sha512 });
    const sha512Signature = sha512ElGamal.sign(6n, message, 3n);
    deepStrictEqual(sha512ElGamal.verify(y, message, sha512Signature), true);
    notDeepStrictEqual(sha512Signature, signature);
    throws(() => safe.sign(6n, forgedMessage as never, 3n), { name: 'TypeError' });
    throws(
      () =>
        elg.ElGamal({ p, g }, {
          prehash: sha256,
          unsafeDisablePrehash: true,
        } as elg.ElGamalOptions),
      /cannot be used together/
    );
  });
  should('verify rejects out-of-range r/s (RFC 2440 12.5)', () => {
    const t = SIGNATURE[0];
    const p = BigInt(`0x${t.p}`);
    const g = BigInt(`0x${t.g}`);
    const y = BigInt(`0x${t.y}`);
    const h = BigInt(`0x${t.h}`);
    const r = BigInt(`0x${t.sig1}`);
    const s = BigInt(`0x${t.sig2}`);
    const elgamal = elg.ElGamal(
      { p, g },
      { unsafeDisablePrehash: true, unsafeAllowRawEncryption: true }
    );
    deepStrictEqual(elgamal.verify(y, h, { r, s }), true);
    // s + (p-1) passed verification before the bounds check, since
    // r^(p-1) === 1 mod p (Fermat): unbounded s makes signatures malleable.
    deepStrictEqual(elgamal.verify(y, h, { r, s: s + p - 1n }), false);
    deepStrictEqual(elgamal.verify(y, h, { r: r + p, s }), false);
    deepStrictEqual(elgamal.verify(y, h, { r: 0n, s }), false);
    deepStrictEqual(elgamal.verify(y, h, { r, s: 0n }), false);
    deepStrictEqual(elgamal.verify(y, h, { r, s: -s }), false);
    deepStrictEqual(elgamal.verify(y, h, { r, s: p - 1n }), false); // s must be < p-1
  });
  should('sign rejects s = 0 instead of emitting an unverifiable signature', () => {
    const elgamal = elg.ElGamal(
      { p: 23n, g: 5n },
      { unsafeDisablePrehash: true, unsafeAllowRawEncryption: true }
    );
    // k = 3: r = 5^3 mod 23 = 10; x = 1, m = 10 => m - x*r = 0 => s = 0
    throws(() => elgamal.sign(1n, 10n, 3n));
    // with a self-generated nonce the same message still signs and verifies
    const sig = elgamal.sign(1n, 10n);
    deepStrictEqual(elgamal.verify(elgamal.getPublicKey(1n), 10n, sig), true);
  });
  should('encrypt/decrypt validate field-element ranges', () => {
    const elgamal = elg.ElGamal({ p: 23n, g: 5n }, { unsafeAllowRawEncryption: true });
    const pub = elgamal.getPublicKey(6n);
    // out-of-range plaintext previously round-tripped to m mod p (or garbage)
    throws(() => elgamal.encrypt(pub, 23n));
    throws(() => elgamal.encrypt(pub, -1n));
    throws(() => elgamal.decrypt(6n, { ct1: -1n, ct2: 5n }));
    throws(() => elgamal.decrypt(6n, { ct1: 5n, ct2: 23n }));
    deepStrictEqual(elgamal.decrypt(6n, elgamal.encrypt(pub, 22n)), 22n);
  });
  should('hides plaintext predicates with an authenticated order-q KEM', () => {
    const p = 23n;
    const g = 5n;
    const q = (p - 1n) / 2n;
    const privateKey = 6n;
    const safe = elg.ElGamal({ p, g });
    const publicKey = safe.getPublicKey(privateKey);
    const message = Uint8Array.of(0, 5, 9);
    const encrypted = safe.encrypt(publicKey, message);

    deepStrictEqual(safe.decrypt(privateKey, encrypted), message);
    deepStrictEqual(encrypted.version, 1);
    deepStrictEqual(encrypted.ephemeral.length, 1);
    deepStrictEqual(pow(OS2IP(encrypted.ephemeral), q, p), 1n);
    deepStrictEqual(encrypted.nonce.length, 24);
    deepStrictEqual(encrypted.ciphertext.length, message.length + 16);
    notDeepStrictEqual(encrypted.ciphertext.subarray(0, message.length), message);

    // With the legacy scheme and a subgroup public key, the Legendre symbol of
    // ct2 directly reveals the Legendre symbol of every non-zero plaintext.
    const raw = elg.ElGamal({ p, g }, { unsafeAllowRawEncryption: true });
    for (const plaintext of [4n, 5n]) {
      const { ct2 } = raw.encrypt(publicKey, plaintext, 3n);
      deepStrictEqual(pow(ct2, q, p), pow(plaintext, q, p));
    }
    deepStrictEqual(raw.encrypt(publicKey, 0n, 3n).ct2, 0n);
  });
  should('rejects malformed, tampered, and wrong-key authenticated ciphertexts uniformly', () => {
    const p = 23n;
    const g = 5n;
    const safe = elg.ElGamal({ p, g });
    const privateKey = 6n;
    const encrypted = safe.encrypt(safe.getPublicKey(privateKey), Uint8Array.of(1, 2, 3));
    const invalid = /invalid ciphertext/;
    const tamperedData = Uint8Array.from(encrypted.ciphertext);
    tamperedData[0] ^= 1;
    const tamperedEphemeral = Uint8Array.from(encrypted.ephemeral);
    tamperedEphemeral[0] = 1;
    const nonSubgroupEphemeral = Uint8Array.of(5);

    throws(() => safe.decrypt(privateKey, { ...encrypted, ciphertext: tamperedData }), invalid);
    throws(() => safe.decrypt(privateKey, { ...encrypted, ephemeral: tamperedEphemeral }), invalid);
    throws(
      () => safe.decrypt(privateKey, { ...encrypted, ephemeral: nonSubgroupEphemeral }),
      invalid
    );
    throws(() => safe.decrypt(privateKey, { ...encrypted, version: 2 as 1 }), invalid);
    throws(() => safe.decrypt(privateKey, { ct1: 1n, ct2: 2n } as never), invalid);
    throws(() => safe.decrypt(7n, encrypted), invalid);
    throws(() => safe.encrypt(1n, Uint8Array.of(1)), /invalid public key/);
    throws(() => safe.encrypt(p - 1n, Uint8Array.of(1)), /invalid public key/);
    // @ts-expect-error Safe encryption intentionally has no caller-selected nonce API.
    throws(() => safe.encrypt(safe.getPublicKey(privateKey), Uint8Array.of(1), 3n), /unsafe/);
  });
  should('requires explicit unsafe raw-encryption compatibility mode', () => {
    const params = { p: 23n, g: 5n };
    const safe = elg.ElGamal(params);
    const raw = elg.ElGamal(params, { unsafeAllowRawEncryption: true });
    const fullyLegacy = elg.ElGamal(params, {
      unsafeAllowRawEncryption: true,
      unsafeDisablePrehash: true,
    });
    const publicKey = raw.getPublicKey(6n);

    deepStrictEqual(raw.encrypt(publicKey, 9n, 7n), fullyLegacy.encrypt(publicKey, 9n, 7n));
    throws(() => safe.encrypt(publicKey, 9n as never), { name: 'TypeError' });
    throws(
      () => elg.ElGamal(params, { unsafeAllowRawEncryption: 'yes' } as never),
      /should be boolean/
    );
    throws(() => elg.ElGamal({ p: 257n, g: 3n }), /safe-prime modulus/);
    // Unsafe mode preserves construction and raw operation for legacy groups.
    deepStrictEqual(
      elg.ElGamal({ p: 257n, g: 3n }, { unsafeAllowRawEncryption: true }).decrypt(7n, {
        ct1: 1n,
        ct2: 9n,
      }),
      9n
    );
  });
  should('validates safe parameters and keys while preserving explicit legacy inputs', () => {
    const params = { p: 23n, g: 5n };
    const safe = elg.ElGamal(params);
    const message = Uint8Array.of(1);
    const signature = safe.sign(6n, message, 3n);

    throws(() => elg.ElGamal({ p: 21n, g: 5n }), /safe-prime modulus/);
    throws(() => elg.ElGamal({ p: 23n, g: 2n }), /invalid ElGamal generator/);
    throws(() => elg.ElGamal({ p: 23n, g: 11n }), /invalid ElGamal generator/);
    throws(() => elg.ElGamal({ p: 23n, g: 22n }), /invalid ElGamal generator/);
    throws(() => elg.ElGamal({ p: 1n << 16384n, g: 3n }), /must not exceed/);

    for (const privateKey of [-1n, 0n, 1n, 11n, 22n]) {
      throws(() => safe.getPublicKey(privateKey), /invalid private key/);
      throws(() => safe.sign(privateKey, message, 3n), /invalid private key/);
      throws(() => safe.decrypt(privateKey, safe.encrypt(8n, message)), /invalid private key/);
    }
    for (const publicKey of [-1n, 0n, 1n, 22n, 23n]) {
      throws(() => safe.encrypt(publicKey, message), /invalid public key/);
      throws(() => safe.verify(publicKey, message, signature), /invalid public key/);
    }

    const legacy = elg.ElGamal(
      { p: 23n, g: 22n },
      { unsafeAllowRawEncryption: true, unsafeDisablePrehash: true }
    );
    deepStrictEqual(legacy.getPublicKey(0n), 1n);
    deepStrictEqual(legacy.encrypt(1n, 8n, 7n).ct2, 8n);
    deepStrictEqual(legacy.verify(22n, 3n, { r: 1n, s: 1n }), true);
  });
});

should.runWhen(import.meta.url);
