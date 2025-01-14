import { deepStrictEqual } from 'node:assert';
import { should, describe } from 'micro-should';
import * as primality from '../esm/primality.js';
import { sqrt, gcd } from '../esm/utils.js';
import { IFCPrimes } from '../esm/rsa.js';
import { jsonGZ, parseTestFile } from './utils.js';

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
  });

  should('Jacobi', () => {
    deepStrictEqual(jacobi(0n, 1n), 1);
    deepStrictEqual(jacobi(2n, 5n), -1);
    deepStrictEqual(jacobi(5n, 3439601197n), -1);
  });
  should('Primes', () => {
    const vectors = jsonGZ('./wycheproof/primality_test.json.gz');
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
      './test/186-3rsatestvectors/KeyGen_186-3_RandomProbablyPrime3_3_KAT.txt'
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

should.runWhen(import.meta.url);
