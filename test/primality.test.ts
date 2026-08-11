import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, throws } from 'node:assert';
import * as primality from '../src/primality.ts';
import { IFCPrimes } from '../src/rsa.ts';
import {
  I2OSP,
  OS2IP,
  ensureBytes,
  gcd,
  getFieldBytesLength,
  getMinHashLength,
  hexToNumber,
  invert,
  mapHashToField,
  mod,
  numberToBytesBE,
  numberToVarBytesBE,
  pow,
  randomBits,
  sqrt,
} from '../src/utils.ts';
import { jsonGZ, parseTestFile } from './utils.ts';

describe('primality', () => {
  const { millerRabinBaseTest, jacobi } = primality;

  should('Example', () => {
    // Non-deterministic Miller-Rabin test over random bases (multiple iterations).
    // This test is probabilistic and may produce false positives (pseudoprimes).
    // Increasing the number of iterations (second parameter) decreases the probability of false positives.
    // Usage: Suitable for quick and practical primality testing where some risk of false positives is acceptable.
    // NOTE: There are known pseudoprimes (false positives) for it!
    deepStrictEqual(primality.millerRabin(7n, 10), true);
    // Deterministic Lucas test.
    // This test is deterministic and does not rely on random bases.
    // It is generally slower than the Miller-Rabin test but can be more reliable for certain numbers.
    // Usage: Useful when a deterministic result is preferred over a probabilistic one.
    // NOTE: There are known pseudoprimes (false positives) for it!
    deepStrictEqual(primality.lucas(7n), true);
    // Deterministic test which consists of Miller-Rabin with base 2 and Lucas test.
    // This combined approach leverages both tests to improve accuracy.
    // It is designed to avoid known pseudoprimes for both individual tests.
    // Usage: Suitable for critical applications where the highest reliability is required.
    // No pseudoprimes (false positives) known!
    deepStrictEqual(primality.bailliePSW(7n), true);
    // [Best] Non-deterministic test from FIPS186-5.
    // This is an enhanced version of the Baillie-PSW test, incorporating multiple rounds of the Miller-Rabin test with random bases.
    // It aims to provide a very high level of confidence in the primality result.
    // Usage: Recommended for most applications, balancing performance and reliability.
    // The combination of multiple tests significantly reduces the probability of false positives.
    deepStrictEqual(primality.isProbablePrime(7n, 10), true);
    // Non-deterministic safe prime test.
    // This function tests if a number is a probable safe prime.
    // A safe prime is a prime number of the form p = 2q + 1, where both p and q are prime.
    // This test first checks if p is a probable prime using multiple rounds of the Miller-Rabin test.
    // It then checks if q = (p - 1) / 2 is also a probable prime using the same method.
    // Usage: Suitable for generating safe primes used in cryptographic protocols, ensuring both p and q are probable primes.
    // Safe primes are essential in cryptographic applications such as key generation in RSA, Diffie-Hellman key exchange, and digital signatures.
    // They provide additional security against certain types of attacks, making cryptographic protocols more robust.
    deepStrictEqual(primality.isProbablySafePrime(7n, 10), true);
  });

  should('Safe primes', () => {
    //A005385		Safe primes p: (p-1)/2 is also prime.
    const A005385 = [
      5, 7, 11, 23, 47, 59, 83, 107, 167, 179, 227, 263, 347, 359, 383, 467, 479, 503, 563, 587,
      719, 839, 863, 887, 983, 1019, 1187, 1283, 1307, 1319, 1367, 1439, 1487, 1523, 1619, 1823,
      1907, 2027, 2039, 2063, 2099, 2207, 2447, 2459, 2579, 2819, 2879, 2903, 2963,
    ].map((i) => BigInt(i));
    for (const i of A005385) deepStrictEqual(primality.isProbablySafePrime(i, 10), true);
  });

  should('GCD', () => {
    deepStrictEqual(gcd(5777n, -1n), 1n);
    deepStrictEqual(gcd(5777n, 1n), 1n);
    deepStrictEqual(gcd(48n, 18n), 6n);
    deepStrictEqual(gcd(-48n, 18n), 6n);
    deepStrictEqual(gcd(48n, -18n), 6n);
    deepStrictEqual(gcd(-48n, -18n), 6n);
  });

  should('sqrt', () => {
    deepStrictEqual(sqrt(0n), 0n);
    deepStrictEqual(sqrt(1n), 1n);
    deepStrictEqual(sqrt(2n), 1n);
    deepStrictEqual(sqrt(3n), 1n);
    deepStrictEqual(sqrt(4n), 2n);
    deepStrictEqual(sqrt(5n), 2n);
    deepStrictEqual(sqrt(6n), 2n);
    deepStrictEqual(sqrt(7n), 2n);
    deepStrictEqual(sqrt(8n), 2n);
    deepStrictEqual(sqrt(9n), 3n);
    deepStrictEqual(sqrt(10n), 3n);
    deepStrictEqual(sqrt(11n), 3n);
    deepStrictEqual(sqrt(12n), 3n);
    deepStrictEqual(sqrt(13n), 3n);
    deepStrictEqual(sqrt(14n), 3n);
    deepStrictEqual(sqrt(15n), 3n);
    deepStrictEqual(sqrt(16n), 4n);
    deepStrictEqual(sqrt(2359296n), 1536n);
    deepStrictEqual(sqrt(54866395443885995655625n), 234235768925n);
    throws(() => sqrt(-1n), { name: 'RangeError' });
  });

  should('utils validation', () => {
    throws(() => ensureBytes('msg', 1 as any), { name: 'TypeError' });
    throws(() => ensureBytes('msg', 'zz'), { name: 'RangeError' });
    throws(() => ensureBytes('msg', Uint8Array.of(1), 2), { name: 'RangeError' });
    throws(() => I2OSP(-1n, 1), { name: 'RangeError' });
    throws(() => I2OSP(256n, 1), { name: 'RangeError' });
    throws(() => OS2IP(Int8Array.of(-1) as any), { name: 'TypeError' });
    throws(() => pow(-2n, 3n, 11n), { name: 'RangeError' });
    throws(() => pow(2n, -1n, 11n), { name: 'RangeError' });
    throws(() => mod(1n, -11n), { name: 'RangeError' });
    throws(() => invert(1n, 1n), { name: 'RangeError' });
    throws(() => hexToNumber(1 as any), { name: 'TypeError' });
    throws(() => getFieldBytesLength(1 as any), { name: 'TypeError' });
    throws(() => mapHashToField(new Uint8Array(1), 23n), { name: 'RangeError' });
  });

  should('randomBits validates bit lengths before randomness', () => {
    const calls: number[] = [];
    const rand = (bytes: number) => {
      calls.push(bytes);
      return Uint8Array.of(0);
    };
    for (const bits of [0, 1.5, -1, Number.NaN, Number.POSITIVE_INFINITY])
      throws(() => randomBits(bits, rand), { name: 'RangeError' });
    deepStrictEqual(calls, []);
    deepStrictEqual(randomBits(8, rand), 0n);
    deepStrictEqual(calls, [1]);
  });

  should('numberToBytesBE and numberToVarBytesBE split fixed and variable encodings', () => {
    deepStrictEqual(numberToBytesBE(255n, 1), Uint8Array.of(0xff));
    deepStrictEqual(numberToBytesBE(256n, 2), Uint8Array.of(0x01, 0x00));
    throws(() => numberToBytesBE(256n, 1), { name: 'RangeError' });
    throws(() => numberToBytesBE(0n, 0), { name: 'RangeError' });
    deepStrictEqual(numberToVarBytesBE(0n), Uint8Array.of(0));
    deepStrictEqual(numberToVarBytesBE(256n), Uint8Array.of(0x01, 0x00));
    throws(() => numberToVarBytesBE(-1n), { name: 'RangeError' });
  });

  should('mapHashToField respects explicit scalar lower bounds', () => {
    const key = new Uint8Array(Math.max(16, getMinHashLength(23n)));
    deepStrictEqual(mapHashToField(key, 23n), Uint8Array.of(1));
    deepStrictEqual(mapHashToField(key, 23n, 2n), Uint8Array.of(2));
    throws(() => mapHashToField(key, 3n, 2n), {
      name: 'RangeError',
    });
  });

  should('field-order helpers follow the noble-curves scalar-range width', () => {
    const orders = [255n, 256n, 257n, 65535n, 65536n].map((fieldOrder) => ({
      fieldOrder,
      bytes: getFieldBytesLength(fieldOrder),
      minHash: getMinHashLength(fieldOrder),
    }));
    deepStrictEqual(orders, [
      { fieldOrder: 255n, bytes: 1, minHash: 2 },
      { fieldOrder: 256n, bytes: 1, minHash: 2 },
      { fieldOrder: 257n, bytes: 2, minHash: 3 },
      { fieldOrder: 65535n, bytes: 2, minHash: 3 },
      { fieldOrder: 65536n, bytes: 2, minHash: 3 },
    ]);
    const key = new Uint8Array(16).fill(1);
    const mapped = [255n, 256n, 257n].map((fieldOrder) => ({
      fieldOrder,
      value: mapHashToField(key, fieldOrder),
    }));
    deepStrictEqual(mapped, [
      { fieldOrder: 255n, value: Uint8Array.of(0x04) },
      { fieldOrder: 256n, value: Uint8Array.of(0x11) },
      { fieldOrder: 257n, value: Uint8Array.of(0x00, 0x02) },
    ]);
    for (const fieldOrder of [1n, 0n, -1n]) {
      throws(() => getFieldBytesLength(fieldOrder), { name: 'RangeError' });
      throws(() => getMinHashLength(fieldOrder), { name: 'RangeError' });
      throws(() => mapHashToField(key, fieldOrder), { name: 'RangeError' });
    }
  });

  should('rejects zero Miller-Rabin iterations', () => {
    const rand = () => Uint8Array.of(0, 2);
    throws(() => primality.millerRabin(1009n, 0, rand), /iterations/i);
    throws(() => primality.isProbablePrime(1009n, 0, rand), /iterations/i);
    throws(() => primality.isProbablySafePrime(2027n, 0, rand), /iterations/i);
    deepStrictEqual(primality.millerRabin(1009n, 1, rand), true);
  });

  should('rejects Miller-Rabin candidates without valid random bases', () => {
    const rand = () => Uint8Array.of(0);
    throws(() => primality.millerRabin(2n, 1, rand), /base interval/i);
    throws(() => primality.millerRabin(3n, 1, rand), /base interval/i);
    deepStrictEqual(primality.isProbablePrime(3n, 1, rand), true);
  });

  should('rejects fixed Miller-Rabin bases outside the FIPS interval', () => {
    throws(() => primality.millerRabinBaseTest(23n, 34n), /base/i);
    throws(() => primality.millerRabinBaseTest(23n, 1n), /base/i);
    throws(() => primality.millerRabinBaseTest(23n, 22n), /base/i);
    throws(() => primality.millerRabinBaseTest(23n, 23n), /base/i);
    deepStrictEqual(primality.millerRabinBaseTest(23n, 2n), true);
    deepStrictEqual(primality.millerRabinBaseTest(23n, 21n), true);
  });

  should('lucas handles small nonsquares without perfect-square oscillation', () => {
    deepStrictEqual(primality.lucas(3n), true);
    deepStrictEqual(primality.lucas(7n), true);
    deepStrictEqual(primality.lucas(9n), false);
  });

  should('Jacobi', () => {
    deepStrictEqual(jacobi(0n, 1n), 1);
    deepStrictEqual(jacobi(2n, 5n), -1);
    deepStrictEqual(jacobi(5n, 3439601197n), -1);
  });
  should('Primes', () => {
    const vectors = jsonGZ('./vectors/wycheproof/primality_test.json.gz');
    for (const tg of vectors.testGroups) {
      for (const t of tg.tests) {
        const val = BigInt(`0x${t.value}`);
        if (t.comment.includes('negative')) continue;
        deepStrictEqual(primality.isProbablePrime(val, 3), t.result === 'valid');
      }
    }
  });

  should('Pseudoprimes', () => {
    // Here we test Lucas and Miller-Rabin tests with pseudoprimes on which they should fail.
    // Usually this code tested to make sure they correctly detect some pseudoprimes,
    // but we also test that they fail on pseudoprimes they expected to fail. This
    // approach uncovered a lot of issues with implementations.
    // For example, if Lucas test detects Lucas pseudoprimes, there is likely bug in implementation,
    // even if it can be seen as 'good' thing (pseudoprime detected, yay!).

    // A001262 (Strong pseudoprimes to base 2)
    const A001262 = [
      2047, 3277, 4033, 4681, 8321, 15841, 29341, 42799, 49141, 52633, 65281, 74665, 80581, 85489,
      88357, 90751, 104653, 130561, 196093, 220729, 233017, 252601, 253241, 256999, 271951, 280601,
      314821, 357761, 390937, 458989, 476971, 486737,
    ].map(BigInt);
    for (const i of A001262) {
      deepStrictEqual(millerRabinBaseTest(i, 2n), true);
      deepStrictEqual(millerRabinBaseTest(i, 3n), false);
      deepStrictEqual(primality.lucas(i), false);
    }
    // A020229 (Strong pseudoprimes to base 3)
    const A020229 = [
      121, 703, 1891, 3281, 8401, 8911, 10585, 12403, 16531, 18721, 19345, 23521, 31621, 44287,
      47197, 55969, 63139, 74593, 79003, 82513, 87913, 88573, 97567, 105163, 111361, 112141, 148417,
      152551, 182527, 188191, 211411, 218791, 221761, 226801,
    ].map(BigInt);
    for (const i of A020229) {
      deepStrictEqual(millerRabinBaseTest(i, 2n), false);
      deepStrictEqual(millerRabinBaseTest(i, 3n), true);
      deepStrictEqual(primality.lucas(i), false);
    }
    // A217255 (Strong Lucas pseudoprimes)
    const A217255 = [
      5459, 5777, 10877, 16109, 18971, 22499, 24569, 25199, 40309, 58519, 75077, 97439, 100127,
      113573, 115639, 130139, 155819, 158399, 161027, 162133, 176399, 176471, 189419, 192509,
      197801, 224369, 230691, 231703, 243629, 253259, 268349, 288919, 313499, 324899,
    ].map(BigInt);
    for (const i of A217255) {
      deepStrictEqual(millerRabinBaseTest(i, 2n), false);
      deepStrictEqual(primality.lucas(i), true);
    }
    // A006945 (Smallest odd composite number that requires n Miller-Rabin primality tests)
    const A006945 = [
      2047n,
      1373653n,
      25326001n,
      3215031751n,
      2152302898747n,
      3474749660383n,
      341550071728321n,
      341550071728321n,
      3825123056546413051n,
      3825123056546413051n,
      3825123056546413051n,
      318665857834031151167461n,
      3317044064679887385961981n,
    ];
    // A175530 (Pseudoprime Chebyshev numbers)
    const A175530 = [
      7056721n,
      79397009999n,
      443372888629441n,
      582920080863121n,
      2491924062668039n,
      14522256850701599n,
      39671149333495681n,
      242208715337316001n,
      729921147126771599n,
      842526563598720001n,
      1881405190466524799n,
      2380296518909971201n,
      3188618003602886401n,
      33711266676317630401n,
      54764632857801026161n,
      55470688965343048319n,
      72631455338727028799n,
      122762671289519184001n,
      361266866679292635601n,
      734097107648270852639n,
    ];

    // Very large Carmichael number: https://en.wikipedia.org/wiki/Carmichael_number
    const p =
      29674495668685510550154174642905332730771991799853043350995075531276838753171770199594238596428121188033664754218345562493168782883n;
    const n = p * (313n * (p - 1n) + 1n) * (353n * (p - 1n) + 1n);
    // Just test various pseudoprime numbers with PSW
    for (const i of [...A006945, ...A001262, ...A020229, ...A217255, ...A175530, n]) {
      deepStrictEqual(primality.bailliePSW(i), false);
    }
  });

  should('Probable primes (FIPS186-3)', () => {
    const parsed = parseTestFile(
      'vectors/186-3rsatestvectors/KeyGen_186-3_RandomProbablyPrime3_3_KAT.txt'
    );
    for (const tg of parsed) {
      for (const t of tg.tests) {
        const p = BigInt(`0x${t.prandom}`);
        const q = BigInt(`0x${t.qrandom}`);
        const res = primality.isProbablePrime(p, 3) && primality.isProbablePrime(q, 3);
        deepStrictEqual(t.Result.startsWith('P'), res);
      }
    }
  });

  should('IFCPrimes', () => {
    // super slow, 2048 - 1s, 4096 - 11s, 8192 - 122s
    // but there is very random and constantly change
    // AVG (20 iters):
    // 2048 - 244ms
    // 4096 - 3.5s
    // 8192 - 32s
    for (const len of [2048, 4096 /*8192*/]) {
      let total = 0;
      let n = 0;
      for (let i = 0; i < 1; i++) {
        const ts = Date.now();
        const { p, q } = IFCPrimes(len);
        deepStrictEqual(primality.isProbablePrime(p, 3), true);
        deepStrictEqual(primality.isProbablePrime(q, 3), true);
        const pq = p * q; // Should be 2^{bits-1} < p*q < 2^bits.
        deepStrictEqual(2n ** BigInt(len - 1) < pq && pq < 2n ** BigInt(len), true);
        deepStrictEqual(pq.toString(2).length, len);
        deepStrictEqual(p.toString(2).length, len / 2);
        deepStrictEqual(q.toString(2).length, len / 2);
        const t = Date.now() - ts;
        total += t;
        n++;
      }
      // console.log('AVG', len, total, n, total / n);
    }
  });
});

describe('utils regressions', () => {
  should('I2OSP/OS2IP edge cases', () => {
    deepStrictEqual(I2OSP(0n, 0), new Uint8Array(0));
    deepStrictEqual(I2OSP(0n, 3), new Uint8Array(3));
    deepStrictEqual(I2OSP(255n, 1), Uint8Array.from([255]));
    deepStrictEqual(I2OSP(258n, 2), Uint8Array.from([1, 2]));
    throws(() => I2OSP(256n, 1), { name: 'RangeError' });
    throws(() => I2OSP(-1n, 4), { name: 'RangeError' });
    deepStrictEqual(OS2IP(new Uint8Array(0)), 0n);
    deepStrictEqual(OS2IP(Uint8Array.from([1, 2])), 258n);
    const big = (1n << 2047n) + 987654321n;
    deepStrictEqual(OS2IP(I2OSP(big, 256)), big);
    deepStrictEqual(I2OSP(big, 257).length, 257); // wider-than-needed output pads left
  });
  should('invert returns the Bezout inverse and rejects non-invertible inputs', () => {
    deepStrictEqual(invert(3n, 11n), 4n);
    deepStrictEqual(mod(invert(-3n, 11n) * -3n, 11n), 1n); // negative inputs normalized
    throws(() => invert(6n, 9n)); // gcd != 1
    throws(() => invert(11n, 11n)); // number ≡ 0 mod modulo
    throws(() => invert(0n, 11n), { name: 'RangeError' });
    const m = (1n << 255n) - 19n;
    const a = 123456789123456789n;
    deepStrictEqual(mod(a * invert(a, m), m), 1n);
  });
  should('sqrt boundary values around powers of two', () => {
    for (const bits of [31, 32, 33, 63, 64, 127, 128, 1024]) {
      const s = 1n << BigInt(bits);
      deepStrictEqual(sqrt(s * s), s);
      deepStrictEqual(sqrt(s * s - 1n), s - 1n);
      deepStrictEqual(sqrt(s * s + 1n), s);
    }
  });
});

should.runWhen(import.meta.url);
