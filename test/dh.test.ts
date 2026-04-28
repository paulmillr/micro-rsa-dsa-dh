import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, throws } from 'node:assert';
import * as crypto from 'node:crypto';
import { DH, DHGroups } from '../src/dh.ts';

const toBytes = (n: bigint, len: number) => {
  const hex = n.toString(16).padStart(len * 2, '0');
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const toNumber = (bytes: Uint8Array) => bytes.reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
const leftPad = (bytes: Uint8Array, len: number) => {
  if (bytes.length > len) throw new Error('input is longer than target length');
  const out = new Uint8Array(len);
  out.set(bytes, len - bytes.length);
  return out;
};

describe('DH', () => {
  should('Example', () => {
    const nobleDH = DH('modp18');
    const alicePriv = nobleDH.randomPrivateKey();
    const alicePub = nobleDH.getPublicKey(alicePriv);
    const bobPriv = nobleDH.randomPrivateKey();
    const bobPub = nobleDH.getPublicKey(bobPriv);
    deepStrictEqual(
      nobleDH.getSharedSecret(alicePriv, bobPub),
      nobleDH.getSharedSecret(bobPriv, alicePub)
    );
  });

  should('pads public keys to fixed group length', () => {
    const nobleDH = DH('modp18');
    const privateKey = new Uint8Array(1024);
    privateKey[1023] = 2;
    const publicKey = nobleDH.getPublicKey(privateKey);
    deepStrictEqual(publicKey.length, 1024);
    deepStrictEqual(nobleDH.getSharedSecret(privateKey, publicKey).length, 1024);
  });

  should('rejects caller-supplied private exponents outside the finite-field interval', () => {
    const nobleDH = DH('modp14');
    const p = DHGroups.modp14.p;
    const len = p.toString(16).length / 2;
    const publicKey = nobleDH.getPublicKey(toBytes(2n, len));
    for (const privateKey of [0n, 1n, p - 1n, p])
      for (const op of [
        () => nobleDH.getPublicKey(toBytes(privateKey, len)),
        () => nobleDH.getSharedSecret(toBytes(privateKey, len), publicKey),
      ])
        throws(op, { name: 'Error' });
  });

  should('rejects peer public keys outside the finite-field interval', () => {
    const nobleDH = DH('modp14');
    const p = DHGroups.modp14.p;
    const len = p.toString(16).length / 2;
    const privateKey = toBytes(2n, len);
    for (const publicKey of [0n, 1n, p - 1n, p])
      throws(() => nobleDH.getSharedSecret(privateKey, toBytes(publicKey, len)), { name: 'Error' });
  });

  should('generates private exponents inside the finite-field interval', () => {
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: {
        getRandomValues(arr: Uint8Array) {
          arr.fill(0);
          return arr;
        },
      },
    });
    try {
      const nobleDH = DH('modp14');
      const p = DHGroups.modp14.p;
      const key = nobleDH.randomPrivateKey();
      deepStrictEqual(toNumber(key) >= 2n && toNumber(key) <= p - 2n, true);
      deepStrictEqual(nobleDH.getPublicKey(key).length, p.toString(16).length / 2);
    } finally {
      if (saved) Object.defineProperty(globalThis, 'crypto', saved);
    }
  });

  should('Basic', () => {
    if (process.versions.deno || process.versions.bun) return;
    const getNodeDH = (privateKey, group, bytesLen) => {
      const dhg = crypto.createDiffieHellmanGroup(group);
      const dh = crypto.createDiffieHellman(dhg.getPrime(), dhg.getGenerator());
      dh.setPrivateKey(privateKey);
      // Node encodes DH public keys as minimal positive integers; this package returns
      // fixed-width field elements so leading-zero keys still round-trip into shared-secret derivation.
      const pub = leftPad(Uint8Array.from(dh.generateKeys()), bytesLen);
      const priv = dh.getPrivateKey();
      return { dh, pub, priv };
    };

    for (const group of [
      'modp1',
      'modp2',
      'modp5',
      'modp14',
      'modp15',
      'modp16',
      'modp17',
      'modp18',
    ]) {
      // Deno DH is broken:
      // Different groups, if we provide correct group prime/generator it will break anyway
      // node
      // GROUP modp14 {
      //   p: 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff',
      //   g: '02'
      // }
      // deno
      // GROUP modp14 {
      //   p: "ffffa2348bd10874a62279ddb31b6d376d4576c6e96bb6edfba511e6513db805369aa85f239656bb076d4e04087c463b2c03a28ff0c9f6187ce518105a68ffff",
      //   g: "00000002"
      // }

      // {
      //   const dhg = crypto.createDiffieHellmanGroup(group);
      //   console.log('GROUP', group, {
      //     p: dhg.getPrime().toString('hex'),
      //     g: dhg.getGenerator().toString('hex'),
      //   });
      // }

      const nobleDH = DH(group);
      const aliceNoble = nobleDH.randomPrivateKey();
      const bobNoble = nobleDH.randomPrivateKey();
      const bytesLen = DHGroups[group].p.toString(16).length / 2;
      // Example usage
      const aliceDH = getNodeDH(aliceNoble, group, bytesLen);
      console.log('DH', aliceDH);
      const bobDH = getNodeDH(bobNoble, group, bytesLen);
      deepStrictEqual(nobleDH.getPublicKey(aliceNoble), aliceDH.pub);
      deepStrictEqual(nobleDH.getPublicKey(bobNoble), bobDH.pub);

      // Node encodes DH secrets as minimal positive integers; this package returns
      // fixed-width field elements so leading-zero secrets still round-trip as keys.
      const aliceSecret = leftPad(
        Uint8Array.from(aliceDH.dh.computeSecret(Buffer.from(bobDH.pub, 'hex'))),
        bytesLen
      );
      const bobSecret = leftPad(
        Uint8Array.from(bobDH.dh.computeSecret(Buffer.from(aliceDH.pub, 'hex'))),
        bytesLen
      );
      deepStrictEqual(aliceSecret, bobSecret);

      deepStrictEqual(
        nobleDH.getSharedSecret(aliceNoble, nobleDH.getPublicKey(bobNoble)),
        aliceSecret
      );
      deepStrictEqual(
        nobleDH.getSharedSecret(bobNoble, nobleDH.getPublicKey(aliceNoble)),
        aliceSecret
      );
    }
  });
});

should.runWhen(import.meta.url);
