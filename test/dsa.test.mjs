import { deepStrictEqual } from 'assert';
import { should, describe } from 'micro-should';
import * as dsa from '../esm/dsa.js';
import { jsonGZ, hexToBytes, bytesToHex, HASHES, parseTestFile } from './utils.mjs';
import { sha256 } from '@noble/hashes/sha256';

const DSA_VECTORS = [
  'dsa_2048_224_sha224_p1363_test.json',
  'dsa_2048_224_sha224_test.json',
  'dsa_2048_224_sha256_p1363_test.json',
  'dsa_2048_224_sha256_test.json',
  'dsa_2048_256_sha256_p1363_test.json',
  'dsa_2048_256_sha256_test.json',
  'dsa_3072_256_sha256_p1363_test.json',
  'dsa_3072_256_sha256_test.json',
].map((i) => jsonGZ(`wycheproof/${i}`));

describe('DSA', () => {
  should('Example', () => {
    // 1. Params
    // Carol generates random params (because there is public params to use :()
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
  });
  describe('getParams', () => {
    const { genDSAPrimes, genDSAGenerator } = dsa._TEST;
    should('FIPS186-4: genPQ', () => {
      for (const tg of parseTestFile('test/186-3dsatestvectors/PQGGen.rsp')) {
        if ('A.1.2.1 Construction of the Primes p and q Using the Shawe-Taylor Algorithm' in tg)
          break;
        const [ns, ls, h] = tg.mod.split(',').map((i) => i.trim());
        const n = +ns.substr(2);
        const l = +ls.substr(2);
        const hash = HASHES[h];
        for (const t of tg.tests) {
          const res = genDSAPrimes(n, l, hash, hexToBytes(t.domain_parameter_seed));
          deepStrictEqual(res.counter, +t.counter);
          deepStrictEqual(res.q, BigInt(`0x${t.Q}`));
          deepStrictEqual(res.p, BigInt(`0x${t.P}`));
          deepStrictEqual(res.domainParameterSeed, hexToBytes(t.domain_parameter_seed));
        }
      }
    });
    should('FIPS186-4: genG', () => {
      let found = false;
      for (const tg of parseTestFile('test/186-3dsatestvectors/PQGGen.rsp')) {
        // I hope one day they will make it machine readable.
        if ('A.2.3   Verifiable Canonical Generation of the Generator g' in tg) found = true;
        if (!found) continue;
        const [ns, ls, h] = tg.mod.split(',').map((i) => i.trim());
        const n = +ns.substr(2);
        const l = +ls.substr(2);
        const hash = HASHES[h];
        for (const t of tg.tests) {
          if (!('domain_parameter_seed' in t)) continue;
          const index = Number(`0x${t.index}`);
          const P = BigInt(`0x${t.P}`);
          const Q = BigInt(`0x${t.Q}`);
          const G = BigInt(`0x${t.G}`);
          const domainParameterSeed = hexToBytes(t.domain_parameter_seed);
          const resG = genDSAGenerator({ p: P, q: Q, domainParameterSeed, hash }, index);
          deepStrictEqual(resG, G);

          const full = dsa.genDSAParams(n, l, hash, index, domainParameterSeed);
          deepStrictEqual(full.p, P);
          deepStrictEqual(full.q, Q);
          deepStrictEqual(full.g, G);
        }
      }
    });
  });

  //https://datatracker.ietf.org/doc/html/rfc6979#appendix-A.2.1
  describe('RFC6979', () => {
    should('DSA-1024', () => {
      const p = BigInt(
        '0x86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447' +
        'E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88' +
        '73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C' +
        '881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779'
      );
      const q = BigInt('0x996F967F6C8E388D9E28D01E205FBA957A5698B1');
      const g = BigInt(
        '0x07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D' +
        '89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD' +
        '87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4' +
        '17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD'
      );
      const privKey = BigInt('0x411602CB19A6CCC34494D79D98EF1E7ED5AF25F7');
      const pubKey = BigInt(
        '0x5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F653' +
        '92195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D' +
        '4CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E6' +
        '82F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B'
      );
      const VECTORS = [
        {
          hash: 'SHA-1',
          message: 'sample',
          k: '7BDB6B0FF756E1BB5D53583EF979082F9AD5BD5B',
          r: '2E1A0C2562B2912CAAF89186FB0F42001585DA55',
          s: '29EFB6B0AFF2D7A68EB70CA313022253B9A88DF5',
        },
        {
          hash: 'SHA-224',
          message: 'sample',
          k: '562097C06782D60C3037BA7BE104774344687649',
          r: '4BC3B686AEA70145856814A6F1BB53346F02101E',
          s: '410697B92295D994D21EDD2F4ADA85566F6F94C1',
        },
        {
          hash: 'SHA-256',
          message: 'sample',
          k: '519BA0546D0C39202A7D34D7DFA5E760B318BCFB',
          r: '81F2F5850BE5BC123C43F71A3033E9384611C545',
          s: '4CDD914B65EB6C66A8AAAD27299BEE6B035F5E89',
        },
        {
          hash: 'SHA-384',
          message: 'sample',
          k: '95897CD7BBB944AA932DBC579C1C09EB6FCFC595',
          r: '07F2108557EE0E3921BC1774F1CA9B410B4CE65A',
          s: '54DF70456C86FAC10FAB47C1949AB83F2C6F7595',
        },
        {
          hash: 'SHA-512',
          message: 'sample',
          k: '09ECE7CA27D0F5A4DD4E556C9DF1D21D28104F8B',
          r: '16C3491F9B8C3FBBDD5E7A7B667057F0D8EE8E1B',
          s: '02C36A127A7B89EDBB72E4FFBC71DABC7D4FC69C',
        },
        {
          hash: 'SHA-1',
          message: 'test',
          k: '5C842DF4F9E344EE09F056838B42C7A17F4A6433',
          r: '42AB2052FD43E123F0607F115052A67DCD9C5C77',
          s: '183916B0230D45B9931491D4C6B0BD2FB4AAF088',
        },
        {
          hash: 'SHA-224',
          message: 'test',
          k: '4598B8EFC1A53BC8AECD58D1ABBB0C0C71E67297',
          r: '6868E9964E36C1689F6037F91F28D5F2C30610F2',
          s: '49CEC3ACDC83018C5BD2674ECAAD35B8CD22940F',
        },
        {
          hash: 'SHA-256',
          message: 'test',
          k: '5A67592E8128E03A417B0484410FB72C0B630E1A',
          r: '22518C127299B0F6FDC9872B282B9E70D0790812',
          s: '6837EC18F150D55DE95B5E29BE7AF5D01E4FE160',
        },
        {
          hash: 'SHA-384',
          message: 'test',
          k: '220156B761F6CA5E6C9F1B9CF9C24BE25F98CD89',
          r: '854CF929B58D73C3CBFDC421E8D5430CD6DB5E66',
          s: '91D0E0F53E22F898D158380676A871A157CDA622',
        },
        {
          hash: 'SHA-512',
          message: 'test',
          k: '65D2C2EEB175E370F28C75BFCDC028D22C7DBE9C',
          r: '8EA47E475BA8AC6F2D821DA3BD212D11A3DEB9A0',
          s: '7C670C7AD72B6C050C109E1790008097125433E8',
        },
      ];
      for (const t of VECTORS) {
        const dsa1 = dsa.DSA({ p, q, g, hash: HASHES[t.hash] });
        deepStrictEqual(dsa1.getPublicKey(privKey), pubKey);
        const msg = new TextEncoder().encode(t.message);
        deepStrictEqual(bytesToHex(dsa1.sign(privKey, msg)), (t.r + t.s).toLowerCase());
      }
    });
    should('DSA-2048', () => {
      const p = BigInt(
        '0x9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48' +
        'C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44F' +
        'FE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5' +
        'B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE2' +
        '35567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41' +
        'F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE' +
        '92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA15' +
        '3E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B'
      );
      const q = BigInt('0xF2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1F');
      const g = BigInt(
        '0x5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613' +
        'D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C4' +
        '6A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472' +
        '085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5' +
        'AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA' +
        '3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71' +
        'BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0' +
        'DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7'
      );
      const privKey = BigInt('0x69C7548C21D0DFEA6B9A51C9EAD4E27C33D3B3F180316E5BCAB92C933F0E4DBC');
      const pubKey = BigInt(
        '0x667098C654426C78D7F8201EAC6C203EF030D43605032C2F1FA937E5237DBD94' +
        '9F34A0A2564FE126DC8B715C5141802CE0979C8246463C40E6B6BDAA2513FA61' +
        '1728716C2E4FD53BC95B89E69949D96512E873B9C8F8DFD499CC312882561ADE' +
        'CB31F658E934C0C197F2C4D96B05CBAD67381E7B768891E4DA3843D24D94CDFB' +
        '5126E9B8BF21E8358EE0E0A30EF13FD6A664C0DCE3731F7FB49A4845A4FD8254' +
        '687972A2D382599C9BAC4E0ED7998193078913032558134976410B89D2C171D1' +
        '23AC35FD977219597AA7D15C1A9A428E59194F75C721EBCBCFAE44696A499AFA' +
        '74E04299F132026601638CB87AB79190D4A0986315DA8EEC6561C938996BEADF'
      );

      const VECTORS = [
        {
          hash: 'SHA-1',
          message: 'sample',
          k: '888FA6F7738A41BDC9846466ABDB8174C0338250AE50CE955CA16230F9CBD53E',
          r: '3A1B2DBD7489D6ED7E608FD036C83AF396E290DBD602408E8677DAABD6E7445A',
          s: 'D26FCBA19FA3E3058FFC02CA1596CDBB6E0D20CB37B06054F7E36DED0CDBBCCF',
        },
        {
          hash: 'SHA-224',
          message: 'sample',
          k: 'BC372967702082E1AA4FCE892209F71AE4AD25A6DFD869334E6F153BD0C4D806',
          r: 'DC9F4DEADA8D8FF588E98FED0AB690FFCE858DC8C79376450EB6B76C24537E2C',
          s: 'A65A9C3BC7BABE286B195D5DA68616DA8D47FA0097F36DD19F517327DC848CEC',
        },
        {
          hash: 'SHA-256',
          message: 'sample',
          k: '8926A27C40484216F052F4427CFD5647338B7B3939BC6573AF4333569D597C52',
          r: 'EACE8BDBBE353C432A795D9EC556C6D021F7A03F42C36E9BC87E4AC7932CC809',
          s: '7081E175455F9247B812B74583E9E94F9EA79BD640DC962533B0680793A38D53',
        },
        {
          hash: 'SHA-384',
          message: 'sample',
          k: 'C345D5AB3DA0A5BCB7EC8F8FB7A7E96069E03B206371EF7D83E39068EC564920',
          r: 'B2DA945E91858834FD9BF616EBAC151EDBC4B45D27D0DD4A7F6A22739F45C00B',
          s: '19048B63D9FD6BCA1D9BAE3664E1BCB97F7276C306130969F63F38FA8319021B',
        },
        {
          hash: 'SHA-512',
          message: 'sample',
          k: '5A12994431785485B3F5F067221517791B85A597B7A9436995C89ED0374668FC',
          r: '2016ED092DC5FB669B8EFB3D1F31A91EECB199879BE0CF78F02BA062CB4C942E',
          s: 'D0C76F84B5F091E141572A639A4FB8C230807EEA7D55C8A154A224400AFF2351',
        },
        {
          hash: 'SHA-1',
          message: 'test',
          k: '6EEA486F9D41A037B2C640BC5645694FF8FF4B98D066A25F76BE641CCB24BA4F',
          r: 'C18270A93CFC6063F57A4DFA86024F700D980E4CF4E2CB65A504397273D98EA0',
          s: '414F22E5F31A8B6D33295C7539C1C1BA3A6160D7D68D50AC0D3A5BEAC2884FAA',
        },
        {
          hash: 'SHA-224',
          message: 'test',
          k: '06BD4C05ED74719106223BE33F2D95DA6B3B541DAD7BFBD7AC508213B6DA6670',
          r: '272ABA31572F6CC55E30BF616B7A265312018DD325BE031BE0CC82AA17870EA3',
          s: 'E9CC286A52CCE201586722D36D1E917EB96A4EBDB47932F9576AC645B3A60806',
        },
        {
          hash: 'SHA-256',
          message: 'test',
          k: '1D6CE6DDA1C5D37307839CD03AB0A5CBB18E60D800937D67DFB4479AAC8DEAD7',
          r: '8190012A1969F9957D56FCCAAD223186F423398D58EF5B3CEFD5A4146A4476F0',
          s: '7452A53F7075D417B4B013B278D1BB8BBD21863F5E7B1CEE679CF2188E1AB19E',
        },
        {
          hash: 'SHA-384',
          message: 'test',
          k: '206E61F73DBE1B2DC8BE736B22B079E9DACD974DB00EEBBC5B64CAD39CF9F91C',
          r: '239E66DDBE8F8C230A3D071D601B6FFBDFB5901F94D444C6AF56F732BEB954BE',
          s: '6BD737513D5E72FE85D1C750E0F73921FE299B945AAD1C802F15C26A43D34961',
        },
        {
          hash: 'SHA-512',
          message: 'test',
          k: 'AFF1651E4CD6036D57AA8B2A05CCF1A9D5A40166340ECBBDC55BE10B568AA0AA',
          r: '89EC4BB1400ECCFF8E7D9AA515CD1DE7803F2DAFF09693EE7FD1353E90A68307',
          s: 'C9F0BDABCC0D880BB137A994CC7F3980CE91CC10FAF529FC46565B15CEA854E1',
        },
      ];
      for (const t of VECTORS) {
        const dsa1 = dsa.DSA({ p, q, g, hash: HASHES[t.hash] });
        deepStrictEqual(dsa1.getPublicKey(privKey), pubKey);
        const msg = new TextEncoder().encode(t.message);
        deepStrictEqual(bytesToHex(dsa1.sign(privKey, msg)), (t.r + t.s).toLowerCase());
      }
    });
  });

  should('Wycheproof', () => {
    for (const v of DSA_VECTORS) {
      for (const tg of v.testGroups) {
        const hash = HASHES[tg.sha];
        const g = BigInt(`0x${tg.publicKey.g}`);
        const p = BigInt(`0x${tg.publicKey.p}`);
        const q = BigInt(`0x${tg.publicKey.q}`);
        const publicKey = BigInt(`0x${tg.publicKey.y}`);
        const dsa1 = dsa.DSA({ hash, p, q, g });
        for (const t of tg.tests) {
          const msg = hexToBytes(t.msg);
          const sig = hexToBytes(t.sig);
          deepStrictEqual(dsa1.verify(publicKey, msg, sig), t.result === 'valid');
          //  if (privateKey && t.result === 'valid') deepStrictEqual(pkcs.sign(privateKey, msg), sig);
        }
      }
    }
  });
});

// ESM is broken.
import url from 'node:url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}