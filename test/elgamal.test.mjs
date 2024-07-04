import { deepStrictEqual } from 'assert';
import { should, describe } from 'micro-should';
import * as elg from '../esm/elgamal.js';

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
  should('Example', () => {
    // NOTE: this is super slow! 512: 1s, 1024: 20s, 2048: 1046s
    const params = elg.genElGamalParams(512);
    const elgamal = elg.ElGamal(params);

    const alicePriv = elgamal.randomPrivateKey();
    const alicePub = elgamal.getPublicKey(alicePriv);
    // Encryption
    const msg = 12345n; // bigint, because there is not rfc for padding and stuff
    const cipherText = elgamal.encrypt(alicePub, msg); // Somebody encrypts message using Alice public key
    deepStrictEqual(elgamal.decrypt(alicePriv, cipherText), msg); // Alice can decrypt message using private key
    // Sign
    const sig = elgamal.sign(alicePriv, msg); // Alice sings message using private key
    deepStrictEqual(elgamal.verify(alicePub, msg, sig), true); // Other parties can verify it using Alice public key
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
      const elgamal = elg.ElGamal({ p, g });
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
      const elgamal = elg.ElGamal({ p, g });
      deepStrictEqual(elgamal.getPublicKey(x), y);
      deepStrictEqual(elgamal.sign(x, h, k), sig);
      deepStrictEqual(elgamal.verify(y, h, sig), true);
    }
  });
});

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
