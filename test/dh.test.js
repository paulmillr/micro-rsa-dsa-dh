import { deepStrictEqual } from 'node:assert';
import { should, describe } from 'micro-should';
import { DH } from '../esm/dh.js';
import * as crypto from 'node:crypto';

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

  should('Basic', () => {
    const getNodeDH = (privateKey, group) => {
      const dhg = crypto.createDiffieHellmanGroup(group);
      const dh = crypto.createDiffieHellman(dhg.getPrime(), dhg.getGenerator());
      dh.setPrivateKey(privateKey);
      const pub = Uint8Array.from(dh.generateKeys());
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
      // Example usage
      const aliceDH = getNodeDH(aliceNoble, group);
      const bobDH = getNodeDH(bobNoble, group);
      deepStrictEqual(nobleDH.getPublicKey(aliceNoble), aliceDH.pub);
      deepStrictEqual(nobleDH.getPublicKey(bobNoble), bobDH.pub);

      const aliceSecret = Uint8Array.from(aliceDH.dh.computeSecret(Buffer.from(bobDH.pub, 'hex')));
      const bobSecret = Uint8Array.from(bobDH.dh.computeSecret(Buffer.from(aliceDH.pub, 'hex')));
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
