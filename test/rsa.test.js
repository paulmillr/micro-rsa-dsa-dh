import { sha256 } from '@noble/hashes/sha256';
import { deepStrictEqual, throws } from 'node:assert';
import { describe, should } from 'micro-should';
import * as fs from 'node:fs';
import * as rsa from '../esm/rsa.js';
import { bytesToHex, HASHES, hexToBytes, jsonGZ } from './utils.js';

function parseRSADPComponent(filePath) {
  const data = fs.readFileSync(filePath, 'utf-8');
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
].map((i) => jsonGZ(`wycheproof/${i}`));

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
].map((i) => jsonGZ(`wycheproof/${i}`));

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
].map((i) => jsonGZ(`wycheproof/${i}`));

const PKCS1_ENCR = [
  'rsa_pkcs1_2048_test.json.gz',
  'rsa_pkcs1_3072_test.json.gz',
  'rsa_pkcs1_4096_test.json.gz',
].map((i) => jsonGZ(`wycheproof/${i}`));

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

describe('RSA', () => {
  const { RSAEP, RSADP, RSASP1 } = rsa._TEST;

  describe('Examples', () => {
    should('OAEP', () => {
      const alice = rsa.keygen(2048);
      const oaep = rsa.OAEP(sha256, rsa.mgf1(sha256));
      const msg = new Uint8Array([1, 2, 3]);
      const encrypted = oaep.encrypt(alice.publicKey, msg);
      deepStrictEqual(oaep.decrypt(alice.privateKey, encrypted), msg);
    });
    should('PSS', () => {
      const alice = rsa.keygen(2048);
      const pss = rsa.PSS(sha256, rsa.mgf1(sha256));
      const msg = new Uint8Array([1, 2, 3]);
      const sig = pss.sign(alice.privateKey, msg);
      deepStrictEqual(pss.verify(alice.publicKey, msg, sig), true);
    });
    should('PCKS1', () => {
      const alice = rsa.keygen(2048);
      const pkcs = rsa.PKCS1_SHA256;
      const msg = new Uint8Array([1, 2, 3]);
      const sig = pkcs.sign(alice.privateKey, msg);
      deepStrictEqual(pkcs.verify(alice.publicKey, msg, sig), true);
    });
    should('PCKS1 KEM', () => {
      const alice = rsa.keygen(2048);
      const pkcs = rsa.PKCS1_KEM;
      const msg = new Uint8Array([1, 2, 3]);
      const encrypted = pkcs.encrypt(alice.publicKey, msg);
      deepStrictEqual(pkcs.decrypt(alice.privateKey, encrypted), msg);
    });
  });

  should('Basic', () => {
    const { publicKey, privateKey } = rsa.keygen(2048);
    const message = BigInt('0x1234567890abcdef');
    const encryptedMessage = RSAEP(publicKey, message);
    const decryptedMessage = RSADP(privateKey, encryptedMessage);
    deepStrictEqual(decryptedMessage.toString(16), message.toString(16));
  });

  describe('RSADP Tests', () => {
    const parsed = parseRSADPComponent('./test/RSADPtestvectors/RSADPComponent800_56B.txt');
    for (const m of parsed) {
      for (const t of m.tests) {
        should(`${m.mod}/${t.COUNT}`, () => {
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
    const parsed = parseRSADPComponent('./test/RSA2SP1testvectors/RSASP1.fax');
    for (const m of parsed) {
      for (const t of m.tests) {
        should(`${m.mod}/${t.COUNT}`, () => {
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
          should(`${tg.keySize}-${tg.sha}-${tg.mgf}-${tg.mgfSha}`, () => {
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
          should(`${tg.keySize}-${tg.sha}-${tg.mgf}-${tg.mgfSha}`, () => {
            const opts = { ...getOpts(tg), sLen };
            const pss = rsa.PSS(opts.hash, opts.mgfHash, opts.sLen);
            for (const t of tg.tests) {
              const msg = hexToBytes(t.msg);
              const sig = hexToBytes(t.sig);
              deepStrictEqual(pss.verify(publicKey, msg, sig), t.result === 'valid');
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
          should(`${tg.keySize}`, () => {
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
          should(`${tg.keySize}`, () => {
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

should.runWhen(import.meta.url);
