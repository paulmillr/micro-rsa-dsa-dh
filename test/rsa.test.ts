import { sha256 } from '@noble/hashes/sha2.js';
import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, throws } from 'node:assert';
import * as fs from 'node:fs';
import { join as pathjoin } from 'node:path';
import * as rsa from '../src/rsa.ts';
import { gcd, I2OSP, invert, OS2IP } from '../src/utils.ts';
import { __dirname, bytesToHex, HASHES, hexToBytes, jsonGZ } from './utils.ts';

function parseRSADPComponent(filePath) {
  const data = fs.readFileSync(pathjoin(__dirname, filePath), 'utf-8');
  const lines = data.split('\n').map((line) => line.trim());
  const tests = [];
  let curTest;
  for (const l of lines) {
    if (l.startsWith('[') && l.includes('mod')) {
      const modSize = l.match(/\d+/)[0];
      if (curTest) tests.push(curTest);
      curTest = { mod: modSize, tests: [] };
    } else if (l.startsWith('COUNT =')) {
      if (curTest) curTest.tests.push({ COUNT: l.split('COUNT =')[1].trim() });
    } else if (l.includes(' = ')) {
      const [k, v] = l.split(' = ').map((s) => s.trim());
      if (curTest && curTest.tests.length > 0) curTest.tests[curTest.tests.length - 1][k] = v;
    }
  }
  if (curTest) tests.push(curTest);
  return tests;
}

const OAEP = [
  'rsa_oaep_2048_sha1_mgf1sha1_test.json.gz',
  'rsa_oaep_2048_sha224_mgf1sha1_test.json.gz',
  'rsa_oaep_2048_sha224_mgf1sha224_test.json.gz',
  'rsa_oaep_2048_sha256_mgf1sha1_test.json.gz',
  'rsa_oaep_2048_sha256_mgf1sha256_test.json.gz',
  'rsa_oaep_2048_sha384_mgf1sha1_test.json.gz',
  'rsa_oaep_2048_sha384_mgf1sha384_test.json.gz',
  'rsa_oaep_2048_sha512_224_mgf1sha1_test.json.gz',
  'rsa_oaep_2048_sha512_224_mgf1sha512_224_test.json.gz',
  'rsa_oaep_2048_sha512_mgf1sha1_test.json.gz',
  'rsa_oaep_2048_sha512_mgf1sha512_test.json.gz',
  'rsa_oaep_3072_sha256_mgf1sha1_test.json.gz',
  'rsa_oaep_3072_sha256_mgf1sha256_test.json.gz',
  'rsa_oaep_3072_sha512_256_mgf1sha1_test.json.gz',
  'rsa_oaep_3072_sha512_256_mgf1sha512_256_test.json.gz',
  'rsa_oaep_3072_sha512_mgf1sha1_test.json.gz',
  'rsa_oaep_3072_sha512_mgf1sha512_test.json.gz',
  'rsa_oaep_4096_sha256_mgf1sha1_test.json.gz',
  'rsa_oaep_4096_sha256_mgf1sha256_test.json.gz',
  'rsa_oaep_4096_sha512_mgf1sha1_test.json.gz',
  'rsa_oaep_4096_sha512_mgf1sha512_test.json.gz',

  'rsa_three_primes_oaep_2048_sha1_mgf1sha1_test.json.gz',
  'rsa_three_primes_oaep_3072_sha224_mgf1sha224_test.json.gz',
  'rsa_three_primes_oaep_4096_sha256_mgf1sha256_test.json.gz',
].map((i) => jsonGZ(`vectors/wycheproof/${i}`));

const PSS = [
  'rsa_pss_2048_sha1_mgf1_20_params_test.json.gz',
  'rsa_pss_2048_sha1_mgf1_20_test.json.gz',
  'rsa_pss_2048_sha256_mgf1_0_params_test.json.gz',
  'rsa_pss_2048_sha256_mgf1_0_test.json.gz',
  'rsa_pss_2048_sha256_mgf1_32_params_test.json.gz',
  'rsa_pss_2048_sha256_mgf1_32_test.json.gz',
  'rsa_pss_2048_sha256_mgf1sha1_20_test.json.gz',
  'rsa_pss_2048_sha384_mgf1_48_test.json.gz',
  'rsa_pss_2048_sha512_224_mgf1_28_test.json.gz',
  'rsa_pss_2048_sha512_256_mgf1_32_test.json.gz',
  'rsa_pss_2048_sha512_mgf1sha256_32_params_test.json.gz',
  'rsa_pss_2048_shake128_params_test.json.gz',
  'rsa_pss_2048_shake128_test.json.gz',
  'rsa_pss_2048_shake256_test.json.gz',
  'rsa_pss_3072_sha256_mgf1_32_params_test.json.gz',
  'rsa_pss_3072_sha256_mgf1_32_test.json.gz',
  'rsa_pss_3072_shake128_params_test.json.gz',
  'rsa_pss_3072_shake128_test.json.gz',
  'rsa_pss_3072_shake256_params_test.json.gz',
  'rsa_pss_3072_shake256_test.json.gz',
  'rsa_pss_4096_sha256_mgf1_32_test.json.gz',
  'rsa_pss_4096_sha384_mgf1_48_test.json.gz',
  'rsa_pss_4096_sha512_mgf1_32_params_test.json.gz',
  'rsa_pss_4096_sha512_mgf1_32_test.json.gz',
  'rsa_pss_4096_sha512_mgf1_64_params_test.json.gz',
  'rsa_pss_4096_sha512_mgf1_64_test.json.gz',
  'rsa_pss_4096_shake256_params_test.json.gz',
  'rsa_pss_4096_shake256_test.json.gz',
  'rsa_pss_misc_params_test.json.gz',
  'rsa_pss_misc_test.json.gz',
].map((i) => jsonGZ(`vectors/wycheproof/${i}`));

const PKCS1 = [
  'rsa_signature_2048_sha224_test.json.gz',
  'rsa_signature_2048_sha256_test.json.gz',
  'rsa_signature_2048_sha384_test.json.gz',
  'rsa_signature_2048_sha3_224_test.json.gz',
  'rsa_signature_2048_sha3_256_test.json.gz',
  'rsa_signature_2048_sha3_384_test.json.gz',
  'rsa_signature_2048_sha3_512_test.json.gz',
  'rsa_signature_2048_sha512_224_test.json.gz',
  'rsa_signature_2048_sha512_256_test.json.gz',
  'rsa_signature_2048_sha512_test.json.gz',
  'rsa_signature_3072_sha256_test.json.gz',
  'rsa_signature_3072_sha384_test.json.gz',
  'rsa_signature_3072_sha3_256_test.json.gz',
  'rsa_signature_3072_sha3_384_test.json.gz',
  'rsa_signature_3072_sha3_512_test.json.gz',
  'rsa_signature_3072_sha512_256_test.json.gz',
  'rsa_signature_3072_sha512_test.json.gz',
  'rsa_signature_4096_sha256_test.json.gz',
  'rsa_signature_4096_sha384_test.json.gz',
  'rsa_signature_4096_sha512_256_test.json.gz',
  'rsa_signature_4096_sha512_test.json.gz',
  'rsa_signature_8192_sha256_test.json.gz',
  'rsa_signature_8192_sha384_test.json.gz',
  'rsa_signature_8192_sha512_test.json.gz',
].map((i) => jsonGZ(`vectors/wycheproof/${i}`));

const PKCS1_ENCR = [
  'rsa_pkcs1_2048_test.json.gz',
  'rsa_pkcs1_3072_test.json.gz',
  'rsa_pkcs1_4096_test.json.gz',
].map((i) => jsonGZ(`vectors/wycheproof/${i}`));

const privKeys = {};
for (const t of OAEP) {
  for (const tg of t.testGroups) {
    privKeys[`${tg.privateKey.modulus}/${tg.privateKey.publicExponent}`] = {
      n: BigInt(`0x${tg.privateKey.modulus}`),
      d: BigInt(`0x${tg.privateKey.privateExponent}`),
    };
  }
}

const getOpts = (tg) => {
  if (tg.mgf === 'MGF1') return { hash: HASHES[tg.sha], mgfHash: rsa.mgf1(HASHES[tg.mgfSha]) };
  return { hash: HASHES[tg.sha], mgfHash: HASHES[tg.mgf] };
};

const emsaPkcs1Sha256 = (msg, emLen) => {
  const prefix = hexToBytes('3031300d060960864801650304020105000420');
  const h = sha256(msg);
  const psLen = emLen - prefix.length - h.length - 3;
  const out = new Uint8Array(emLen);
  out[1] = 0x01;
  out.fill(0xff, 2, 2 + psLen);
  out[2 + psLen] = 0x00;
  out.set(prefix, 3 + psLen);
  out.set(h, 3 + psLen + prefix.length);
  return out;
};

const xorshift = (seed) => {
  let x = seed >>> 0;
  const next = () => {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x >>>= 0;
    x ^= x << 5;
    x >>>= 0;
    return x & 0xff;
  };
  return (len) => {
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = next();
    return out;
  };
};

const tinyHash = Object.assign((_msg) => Uint8Array.of(0xaa), {
  outputLen: 1,
  blockLen: 1,
  create() {
    return {
      update() {
        return this;
      },
      digestInto(out) {
        out.fill(0xaa);
        return out;
      },
    };
  },
});

const oddBitsPss = {
  publicKey: { n: 16791641n, e: 65537n },
  privateKey: { n: 16791641n, d: 5824481n },
};

describe('RSA', () => {
  const { RSAEP, RSADP, RSASP1 } = rsa._TEST;

  describe('Examples', () => {
    it('OAEP', () => {
      const alice = rsa.keygen(2048);
      const oaep = rsa.OAEP(sha256, rsa.mgf1(sha256));
      const msg = new Uint8Array([1, 2, 3]);
      const encrypted = oaep.encrypt(alice.publicKey, msg);
      deepStrictEqual(oaep.decrypt(alice.privateKey, encrypted), msg);
    });
    it('PSS', () => {
      const alice = rsa.keygen(2048);
      const pss = rsa.PSS(sha256, rsa.mgf1(sha256));
      const msg = new Uint8Array([1, 2, 3]);
      const sig = pss.sign(alice.privateKey, msg);
      deepStrictEqual(pss.verify(alice.publicKey, msg, sig), true);
    });
    it('PCKS1', () => {
      const alice = rsa.keygen(2048);
      const pkcs = rsa.PKCS1_SHA256;
      const msg = new Uint8Array([1, 2, 3]);
      const sig = pkcs.sign(alice.privateKey, msg);
      deepStrictEqual(pkcs.verify(alice.publicKey, msg, sig), true);
    });
    it('PCKS1 KEM', () => {
      const alice = rsa.keygen(2048);
      const pkcs = rsa.PKCS1_KEM;
      const msg = new Uint8Array([1, 2, 3]);
      const encrypted = pkcs.encrypt(alice.publicKey, msg);
      deepStrictEqual(pkcs.decrypt(alice.privateKey, encrypted), msg);
    });
  });

  it('Basic', () => {
    const { publicKey, privateKey } = rsa.keygen(2048);
    const message = BigInt('0x1234567890abcdef');
    const encryptedMessage = RSAEP(publicKey, message);
    const decryptedMessage = RSADP(privateKey, encryptedMessage);
    deepStrictEqual(decryptedMessage.toString(16), message.toString(16));
  });

  it('uses caller randomness for RSA prime search candidates', () => {
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    let globalCalls = 0;
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: {
        getRandomValues(arr) {
          globalCalls++;
          arr.fill(0xff);
          return arr;
        },
      },
    });
    const rand = () => {
      throw new Error('randFn used');
    };
    try {
      throws(() => rsa.IFCPrimes(2048, 65537n, undefined, undefined, rand), /randFn used/);
      throws(() => rsa.keygen(2048, 65537n, rand), /randFn used/);
      deepStrictEqual(globalCalls, 0);
    } finally {
      if (saved) Object.defineProperty(globalThis, 'crypto', saved);
    }
  });

  it('mgf1 validates mask lengths before generating output', () => {
    const mgf = rsa.mgf1(sha256);
    deepStrictEqual(mgf(Uint8Array.of(1), { dkLen: 0 }), Uint8Array.of());
    deepStrictEqual(bytesToHex(mgf(Uint8Array.of(1), { dkLen: 5 })), '957b88b127');
    throws(() => mgf(Uint8Array.of(1), { dkLen: -1 }), /mask|length|dkLen/i);
    throws(() => mgf(Uint8Array.of(1), { dkLen: 1.5 }), /mask|length|dkLen/i);
    throws(() => mgf(Uint8Array.of(1), { dkLen: Number.NaN }), /mask|length|dkLen/i);
  });

  it('rejects public keys outside the RFC exponent interval', () => {
    const msg = Uint8Array.of(1, 2, 3);
    const n = (1n << 1023n) + 1n;
    const sig = emsaPkcs1Sha256(msg, 128);
    const pss = rsa.PSS(sha256, rsa.mgf1(sha256));
    const oaep = rsa.OAEP(sha256, rsa.mgf1(sha256));
    const invalid = [
      { n, e: 1n },
      { n, e: 2n },
      { n, e: 4n },
      { n, e: n },
    ];
    for (const publicKey of invalid) {
      throws(() => rsa.PKCS1_SHA256.verify(publicKey, msg, sig), /public|key|exponent|invalid/i);
      throws(() => pss.verify(publicKey, msg, new Uint8Array(128)), /public|key|exponent|invalid/i);
      throws(() => oaep.encrypt(publicKey, msg), /public|key|exponent|invalid/i);
      throws(() => rsa.PKCS1_KEM.encrypt(publicKey, msg), /public|key|exponent|invalid/i);
    }
    deepStrictEqual(rsa.PKCS1_SHA256.verify({ n, e: 3n }, msg, sig), false);
  });

  it('rejects invalid private exponents across private-key operations', () => {
    const msg = Uint8Array.of(1, 2, 3);
    const n = (1n << 1023n) + 1n;
    const pss = rsa.PSS(sha256, rsa.mgf1(sha256));
    const oaep = rsa.OAEP(sha256, rsa.mgf1(sha256));
    const invalid = [
      { n, d: 1n },
      { n, d: 0n },
      { n, d: 2n },
      { n, d: n },
    ];
    for (const privateKey of invalid) {
      throws(() => rsa.PKCS1_SHA256.sign(privateKey, msg), /private|key|exponent|invalid/i);
      throws(() => pss.sign(privateKey, msg), /private|key|exponent|invalid/i);
      throws(() => oaep.decrypt(privateKey, new Uint8Array(128)), /private|key|exponent|invalid/i);
      throws(
        () => rsa.PKCS1_KEM.decrypt(privateKey, new Uint8Array(128)),
        /private|key|exponent|invalid/i
      );
    }
  });

  it('generates private exponents as lambda representatives', () => {
    const e = 65537n;
    const { p, q } = rsa.IFCPrimes(2048, e, undefined, undefined, xorshift(2));
    const pair = rsa.keygen(2048, e, xorshift(2));
    const n = p * q;
    const phi = (p - 1n) * (q - 1n);
    const lambda = phi / gcd(p - 1n, q - 1n);
    const expectedD = invert(e, lambda);
    deepStrictEqual(invert(e, phi) === expectedD, false);
    deepStrictEqual(pair, {
      publicKey: { e, n },
      privateKey: { d: expectedD, n },
    });
    deepStrictEqual(pair.privateKey.d > 2n ** 1024n && pair.privateKey.d < lambda, true);
    const msg = Uint8Array.of(1, 2, 3);
    deepStrictEqual(
      rsa.PKCS1_SHA256.verify(pair.publicKey, msg, rsa.PKCS1_SHA256.sign(pair.privateKey, msg)),
      true
    );
  });

  it('uses generic OAEP decryption errors for public failure paths', () => {
    const oaep = rsa.OAEP(sha256, rsa.mgf1(sha256));
    const minKey = { n: (1n << 527n) + 1n, d: 3n };
    const invalid = [
      [minKey, new Uint8Array(66).fill(0xff)],
      [minKey, new Uint8Array(65)],
      [{ n: (1n << 519n) + 1n, d: 3n }, new Uint8Array(65)],
    ];
    for (const [privateKey, ciphertext] of invalid)
      throws(() => oaep.decrypt(privateKey, ciphertext), /decryption error/i);
  });

  it('uses generic PKCS1 KEM decryption errors for public failure paths', () => {
    const minKey = { n: (1n << 87n) + 1n, d: 3n };
    const invalid = [
      [minKey, new Uint8Array(11).fill(0xff)],
      [minKey, new Uint8Array(10)],
      [{ n: (1n << 79n) + 1n, d: 3n }, new Uint8Array(10)],
    ];
    for (const [privateKey, ciphertext] of invalid)
      throws(() => rsa.PKCS1_KEM.decrypt(privateKey, ciphertext), /decryption error/i);
  });

  it('rejects PSS salt lengths above hash output length', () => {
    const p = 1000003n;
    const q = 1000081n;
    const n = p * q;
    const e = 65537n;
    const p1 = p - 1n;
    const q1 = q - 1n;
    const lambda = (p1 * q1) / gcd(p1, q1);
    const privateKey = { n, d: invert(e, lambda) };
    const publicKey = { n, e };
    const msg = Uint8Array.of(9);
    const pss = rsa.PSS(tinyHash, rsa.mgf1(tinyHash), 2);

    const emBits = n.toString(2).length - 1;
    const emLen = Math.ceil(emBits / 8);
    const mHash = tinyHash(msg);
    const salt = new Uint8Array(2).fill(0x5a);
    const mPrime = new Uint8Array(8 + mHash.length + salt.length);
    mPrime.set(mHash, 8);
    mPrime.set(salt, 8 + mHash.length);
    const H = tinyHash(mPrime);
    const DB = new Uint8Array(emLen - tinyHash.outputLen - 1);
    DB[0] = 0x01;
    DB.set(salt, 1);
    const dbMask = rsa.mgf1(tinyHash)(H, { dkLen: DB.length });
    const maskedDB = DB.map((byte, idx) => byte ^ dbMask[idx]);
    maskedDB[0] &= 0xff >> (8 * emLen - emBits);
    const EM = new Uint8Array(emLen);
    EM.set(maskedDB);
    EM.set(H, maskedDB.length);
    EM[EM.length - 1] = 0xbc;
    const sig = I2OSP(RSASP1(privateKey, OS2IP(EM)), emLen);

    deepStrictEqual(pss.verify(publicKey, msg, sig), false);
    throws(() => pss.sign(privateKey, msg), /salt|sLen|encoding/i);
  });

  it('serializes PSS signatures to the RSA modulus length', () => {
    const pss = rsa.PSS(tinyHash, rsa.mgf1(tinyHash), 0);
    const msg = Uint8Array.of(1);
    const sig = pss.sign(oddBitsPss.privateKey, msg);
    deepStrictEqual(
      {
        k: Math.ceil(oddBitsPss.publicKey.n.toString(16).length / 2),
        sigLen: sig.length,
        verify: pss.verify(oddBitsPss.publicKey, msg, sig),
      },
      { k: 4, sigLen: 4, verify: true }
    );
  });

  it('maps PSS encoded-message overflow to invalid signature', () => {
    const pss = rsa.PSS(tinyHash, rsa.mgf1(tinyHash), 0);
    const sig = I2OSP(oddBitsPss.publicKey.n - 1n, 4);
    deepStrictEqual(pss.verify(oddBitsPss.publicKey, Uint8Array.of(1), sig), false);
  });

  describe('RSADP Tests', () => {
    const parsed = parseRSADPComponent('vectors/RSADPtestvectors/RSADPComponent800_56B.txt');
    for (const m of parsed) {
      for (const t of m.tests) {
        it(`${m.mod}/${t.COUNT}`, () => {
          const n = BigInt(`0x${t.n}`);
          const e = BigInt(`0x${t.e}`);
          const d = BigInt(`0x${t.d}`);
          const c = BigInt(`0x${t.c}`);
          const publicKey = { n, e };
          const privateKey = { n, d };
          if (t.Result === 'Pass') {
            const expectedK = BigInt(`0x${t.k}`);
            // RSAEP test
            const encryptedMessage = RSAEP(publicKey, expectedK);
            deepStrictEqual(encryptedMessage, c, 'RSAEP failed');
            // RSADP test
            const decryptedMessage = RSADP(privateKey, c);
            deepStrictEqual(decryptedMessage, expectedK, 'RSADP failed');
          } else if (t.Result === 'Fail') {
            throws(() => RSADP(privateKey, c));
          }
        });
      }
    }
  });
  describe('RSA2SP1', () => {
    const parsed = parseRSADPComponent('vectors/RSA2SP1testvectors/RSASP1.fax');
    for (const m of parsed) {
      for (const t of m.tests) {
        it(`${m.mod}/${t.COUNT}`, () => {
          const n = BigInt(`0x${t.n}`);
          const p = BigInt(`0x${t.p}`);
          const q = BigInt(`0x${t.q}`);
          const e = BigInt(`0x${t.e}`);
          const d = BigInt(`0x${t.d}`);
          const EM = BigInt(`0x${t.EM}`);
          const S = t.S.startsWith('FAIL') ? t.S : BigInt(`0x${t.S}`);
          const privateKey = { n, p, q, d };
          if (typeof S === 'bigint') {
            const signature = RSASP1(privateKey, EM);
            deepStrictEqual(signature, S, 'RSASP1 failed');
          } else {
            throws(() => RSASP1(privateKey, EM));
          }
        });
      }
    }
  });
  describe('Wycheproof', () => {
    describe('OAEP', () => {
      for (const t of OAEP) {
        for (const tg of t.testGroups) {
          const n = BigInt(`0x${tg.privateKey.modulus}`);
          const e = BigInt(`0x${tg.privateKey.publicExponent}`);
          const d = BigInt(`0x${tg.privateKey.privateExponent}`);
          const publicKey = { n, e };
          const privateKey = { n, d };
          it(`${tg.keySize}-${tg.sha}-${tg.mgf}-${tg.mgfSha}`, () => {
            const opts = getOpts(tg);
            for (const t of tg.tests) {
              const C = hexToBytes(t.ct);
              const L = hexToBytes(t.label);
              const expectedMsg = t.msg;
              const result = t.result;
              const oaep = rsa.OAEP(opts.hash, opts.mgfHash, L);
              if (result === 'valid') {
                const M = oaep.decrypt(privateKey, C);
                deepStrictEqual(bytesToHex(M), expectedMsg);
                // Re-encryption and decryption test
                const reEncryptedC = oaep.encrypt(publicKey, M);
                const decryptedM = oaep.decrypt(privateKey, reEncryptedC);
                deepStrictEqual(bytesToHex(decryptedM), expectedMsg);
              } else if (result === 'invalid') {
                throws(() => oaep.decrypt(privateKey, C));
              }
            }
          });
        }
      }
    });
    describe('PSS', () => {
      for (const t of PSS) {
        for (const tg of t.testGroups) {
          const n = BigInt(`0x${tg.publicKey.modulus}`);
          const e = BigInt(`0x${tg.publicKey.publicExponent}`);
          const privateKey = privKeys[`${tg.publicKey.modulus}/${tg.publicKey.publicExponent}`];
          const sLen = tg.sLen;
          const publicKey = { n, e };
          it(`${tg.keySize}-${tg.sha}-${tg.mgf}-${tg.mgfSha}`, () => {
            const opts = { ...getOpts(tg), sLen };
            const pss = rsa.PSS(opts.hash, opts.mgfHash, opts.sLen);
            const hLen =
              tg.sha === 'SHAKE128' ? 32 : tg.sha === 'SHAKE256' ? 64 : opts.hash.outputLen;
            for (const t of tg.tests) {
              const msg = hexToBytes(t.msg);
              const sig = hexToBytes(t.sig);
              // Wycheproof tracks RFC 8017 validity; FIPS 186-5 §5.4(g) additionally rejects sLen > hLen.
              deepStrictEqual(
                pss.verify(publicKey, msg, sig),
                t.result === 'valid' && sLen <= hLen
              );
              // NOTE: only if sLen=0 signature is determenistic
              if (privateKey && sLen === 0 && t.result === 'valid') {
                const sig2 = pss.sign(privateKey, msg);
                deepStrictEqual(sig, sig2);
              }
            }
          });
        }
      }
    });
    describe('PKCS1 Encryption', () => {
      for (const t of PKCS1_ENCR) {
        for (const tg of t.testGroups) {
          const n = BigInt(`0x${tg.privateKey.modulus}`);
          const e = BigInt(`0x${tg.privateKey.publicExponent}`);
          const d = BigInt(`0x${tg.privateKey.privateExponent}`);
          const publicKey = { n, e };
          const privateKey = { n, d };
          it(`${tg.keySize}`, () => {
            for (const t of tg.tests) {
              const C = hexToBytes(t.ct);
              const expectedMsg = t.msg;
              const result = t.result;
              if (result === 'valid') {
                const M = rsa.PKCS1_KEM.decrypt(privateKey, C);
                deepStrictEqual(bytesToHex(M), expectedMsg);
                // Re-encryption and decryption test
                const reEncryptedC = rsa.PKCS1_KEM.encrypt(publicKey, M);
                const decryptedM = rsa.PKCS1_KEM.decrypt(privateKey, reEncryptedC);
                deepStrictEqual(bytesToHex(decryptedM), expectedMsg);
              } else if (result === 'invalid') {
                throws(() => rsa.PKCS1_KEM.decrypt(privateKey, C));
              }
            }
          });
        }
      }
    });
    describe('PKCS1', () => {
      for (const t of PKCS1) {
        for (const tg of t.testGroups) {
          const n = BigInt(`0x${tg.publicKey.modulus}`);
          const e = BigInt(`0x${tg.publicKey.publicExponent}`);
          const publicKey = { n, e };
          const privateKey = privKeys[`${tg.publicKey.modulus}/${tg.publicKey.publicExponent}`];
          it(`${tg.keySize}`, () => {
            const pkcs = {
              'SHA-1': rsa.PKCS1_SHA1,
              'SHA-224': rsa.PKCS1_SHA224,
              'SHA-256': rsa.PKCS1_SHA256,
              'SHA-384': rsa.PKCS1_SHA384,
              'SHA-512': rsa.PKCS1_SHA512,
              'SHA-512/224': rsa.PKCS1_SHA512_224,
              'SHA-512/256': rsa.PKCS1_SHA512_256,
              // https://github.com/usnistgov/ACVP-Server/issues/257#issuecomment-1502669140
              'SHA3-224': rsa.PKCS1_SHA3_224,
              'SHA3-256': rsa.PKCS1_SHA3_256,
              'SHA3-384': rsa.PKCS1_SHA3_384,
              'SHA3-512': rsa.PKCS1_SHA3_512,
            }[tg.sha];
            for (const t of tg.tests) {
              const msg = hexToBytes(t.msg);
              const sig = hexToBytes(t.sig);
              deepStrictEqual(pkcs.verify(publicKey, msg, sig), t.result === 'valid');
              if (privateKey && t.result === 'valid')
                deepStrictEqual(pkcs.sign(privateKey, msg), sig);
            }
          });
        }
      }
    });
  });
});

it.runWhen(import.meta.url);
