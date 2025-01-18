import { randomBytes } from '@noble/hashes/utils';
import { gcd, mod, numberToBytes, pow, type RandFn, randomBits } from './utils.js';

// Non-deterministic Miller-Rabin test over random bases (multiple iterations).
// This test is probabilistic and may produce false positives (pseudoprimes).
// Increasing the number of iterations (second parameter) decreases the probability of false positives.
// Usage: Suitable for quick and practical primality testing where some risk of false positives is acceptable.
// WARNING: There are known pseudoprimes (false positives) for it!

// Deterministic Lucas test. Does not rely on random bases. Generally slower than the Miller-Rabin test but can be more reliable for certain numbers.
// Usage: Useful when a deterministic result is preferred over a probabilistic one.
// WARNING: There are known pseudoprimes (false positives) for it!

// Deterministic test which consists of Miller-Rabin with base 2 and Lucas test.
// This combined approach leverages both tests to improve accuracy.
// It is designed to avoid known pseudoprimes for both individual tests.
// Usage: Suitable for critical applications where the highest reliability is required.
// No pseudoprimes (false positives) known!

// [Best] Non-deterministic test from FIPS186-5.
// This is an enhanced version of the Baillie-PSW test, incorporating multiple rounds of the Miller-Rabin test with random bases.
// It aims to provide a very high level of confidence in the primality result.
// Usage: Recommended for most applications, balancing performance and reliability.
// The combination of multiple tests significantly reduces the probability of false positives.

// Non-deterministic safe prime test.
// This function tests if a number is a probable safe prime. A safe prime is a prime number of the form p = 2q + 1, where both p and q are prime.
// NOTE: they are very rare and finding one takes a lot of time.

/**
 * Function to perform the Miller-Rabin primality test
 * @param w The odd integer to be tested for primality. This will be either p or q, or one of the auxiliary primes.
 * @param iterations The number of iterations of the test to be performed
 * @returns true for 'PROBABLY PRIME' and false for 'COMPOSITE'
 */
export function millerRabin(w: bigint, iterations: number, randFn: RandFn = randomBytes): boolean {
  if (typeof w !== 'bigint') throw new Error('number expected to be bigint');
  if (!Number.isSafeInteger(iterations))
    throw new Error('number of iterations should be safe interger');
  if (typeof randFn !== 'function') throw new Error('randFn should be function');
  if (w < 2n) return false;
  // Step 1: Find a such that 2^a * m = w - 1
  let a = 0;
  let m = w - 1n;
  while (m % 2n === 0n) {
    m >>= 1n;
    a += 1;
  }
  if (2n ** BigInt(a) * m !== w - 1n) throw new Error('millerRabin: wrong assertion');
  const wlen = w.toString(2).length; // 3. _wlen_ = **len** ( _w_ ).
  step4: for (let i = 1; i <= iterations; i++) {
    // Step 4.1 + 4.2
    let b: bigint = 0n;
    while (b <= 1n || b >= w - 1n) b = randomBits(wlen, randFn);
    let z = pow(b, m, w); // Step 4.3
    if (z === 1n || z === w - 1n) continue; // Step 4.4
    // Step 4.5
    for (let j = 1; j <= a - 1; j++) {
      z = (z * z) % w; // Step 4.5.1
      if (z === w - 1n) continue step4; // Step 4.5.2 + 4.7 (continue 4)
      if (z === 1n) return false; // 4.5.3 + 4.6
    }
    return false;
  }
  return true;
}

// Deterministic version of Miller-Rabin test with fixed base
export function millerRabinBaseTest(w: bigint, base: bigint): boolean {
  return millerRabin(w, 1, (len) => numberToBytes(base, len));
}

/**
 * Determines if positive integer C is a perfect square. From FIPS186-5 (B.4 CHECKING FOR A PERFECT SQUARE)
 * @param C positive integer
 * @returns true if integer is a perfect square
 */
function isPerfectSquare(C: bigint): boolean {
  const n = C.toString(2).length; // Step 1: Determine n such that 2^n > C >= 2^(n-1)
  const m = BigInt(Math.ceil(n / 2)); // Step 2: m = ⌈n / 2⌉
  // Step 4: Select X0 such that 2^m > X0 >= 2^(m-1)
  let X0 = 2n ** (m - 1n);
  if (X0 * X0 > C) X0 = X0 / 2n;
  if (!(2n ** m > X0 && X0 >= 2n ** (m - 1n))) throw new Error('isPerfectSquare: wrong assertion');
  let Xi = X0;
  // Step 5: Repeat until (Xi)^2 < 2^m + C
  for (let lastXi = 0n; Xi !== lastXi && Xi ** 2n < 2n ** m + C; ) {
    lastXi = Xi;
    Xi = (Xi ** 2n + C) / (2n * Xi);
  }
  return Xi * Xi === C; // Step 6: Check if C is a perfect square
}

/**
 * This routine computes the Jacobi symbol. From FIPS186-5 (B.5 JACOBI SYMBOL ALGORITHM)
 * @param a initial value is in the sequence {5, –7, 9, –11, 13, –15, 17, ...}
 * @param n initial value is the candidate being tested
 * @returns Jacobi symbol
 */
export function jacobi(a: bigint, n: bigint): number {
  a = mod(a, n); // Step 1
  if (a === 1n || n === 1n) return 1; // Step 2
  if (a === 0n) return 0; // Step 3
  // Step 4: Define e and a1 such that a = 2^e * a1, where a1 is odd
  let e = 0;
  while (a % 2n === 0n) {
    a >>= 1n;
    e++;
  }
  const a1 = a;
  // Step 5
  let s = 1;
  if (e % 2 !== 0) {
    const mod8 = mod(n, 8n);
    if (mod8 === 1n || mod8 === 7n) s = 1;
    else if (mod8 === 3n || mod8 === 5n) s = -1;
  }
  if (mod(n, 4n) === 3n && mod(a1, 4n) === 3n) s = -s; // Step 6
  const n1 = mod(n, a1); // Step 7
  return s * jacobi(n1, a1); // Step 8
}

/**
 * (General) Lucas Probabilistic Primality Test (From FIPS186-5)
 * @param C positive integer
 * @returns true if number is probably prime, false if composite
 */
export function lucas(C: bigint): boolean {
  if (typeof C !== 'bigint') throw new Error('number expected to be bigint');
  if (isPerfectSquare(C)) return false; // Step 1
  // Step 2: Find first D in sequence 5, -7, 9, -11, 13, -15, ...
  let D = 5n;
  for (; ; D = -(D + (D > 0n ? 2n : -2n))) {
    const js = jacobi(D, C);
    if (js === 0) return false; // if jacobi symbol = 0 for any D in the sequence, return (COMPOSITE)
    // GCD check added in FIPS186-5
    if (js === -1 && gcd(C, (1n - D) / 4n) === 1n) break;
  }
  const K = C + 1n; // Step 3
  const r = K.toString(2).length - 1; // Step 4
  // prettier-ignore
  let Ui = 1n, Vi = 1n; // Step 5
  // Computes (A * (C + 1) / 2) % C
  const div2 = (A: bigint, C: bigint) => mod(A * ((C + 1n) >> 1n), C);
  // Step 6
  for (let i = BigInt(r - 1); i >= 0n; i--) {
    const Utemp = mod(Ui * Vi, C); // Step 6.1
    const Vtemp = div2(Vi * Vi + Ui * Ui * D, C); // Step 6.2
    if ((K >> i) & 1n) {
      Ui = div2(Utemp + Vtemp, C); // Step 6.3.1
      Vi = div2(Vtemp + Utemp * D, C); // Step 6.3.2
    } else {
      Ui = Utemp; // Step 6.3.3
      Vi = Vtemp; // Step 6.3.4
    }
  }
  return Ui === 0n; // Step 7
}

// prettier-ignore
const sieveBase: Set<bigint> = new Set([
  // https://en.wikipedia.org/wiki/List_of_prime_numbers
  2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n, 53n, 59n, 61n, 67n, 71n, // 1–20
  73n, 79n, 83n, 89n, 97n, 101n, 103n, 107n, 109n, 113n, 127n, 131n, 137n, 139n, 149n, 151n, 157n, 163n, 167n, 173n, // 21–40
  179n, 181n, 191n, 193n, 197n, 199n, 211n, 223n, 227n, 229n, 233n, 239n, 241n, 251n, 257n, 263n, 269n, 271n, 277n, 281n, // 41–60
  283n, 293n, 307n, 311n, 313n, 317n, 331n, 337n, 347n, 349n, 353n, 359n, 367n, 373n, 379n, 383n, 389n, 397n, 401n, 409n, // 61–80
  419n, 421n, 431n, 433n, 439n, 443n, 449n, 457n, 461n, 463n, 467n, 479n, 487n, 491n, 499n, 503n, 509n, 521n, 523n, 541n, // 81–100
  547n, 557n, 563n, 569n, 571n, 577n, 587n, 593n, 599n, 601n, 607n, 613n, 617n, 619n, 631n, 641n, 643n, 647n, 653n, 659n, // 101–120
  661n, 673n, 677n, 683n, 691n, 701n, 709n, 719n, 727n, 733n, 739n, 743n, 751n, 757n, 761n, 769n, 773n, 787n, 797n, 809n, // 121–140
  811n, 821n, 823n, 827n, 829n, 839n, 853n, 857n, 859n, 863n, 877n, 881n, 883n, 887n, 907n, 911n, 919n, 929n, 937n, 941n, // 141–160
  947n, 953n, 967n, 971n, 977n, 983n, 991n, 997n, // 161–180
]);

function checkSieve(n: bigint) {
  if (typeof n !== 'bigint') throw new Error('expected bigint');
  if (n < 0n) throw new Error('negative numbers not supported');
  if (n === 1n) return false; // false
  if (n !== 2n && n % 2n === 0n) return false;
  // First, check trial division by the smallest primes
  if (sieveBase.has(n)) return true;
  for (const prime of sieveBase) if (n % prime === 0n) return false;
  return;
}

/**
 * Baillie–PSW primality test
 * @param n number to check if prime
 * @param iters iterations of Miler-Rabin tests
 * @param randFn
 * @returns true if probable prime
 */
export function bailliePSW(n: bigint): boolean {
  const sieveRes = checkSieve(n);
  if (sieveRes !== undefined) return sieveRes;
  // BPSW does single iteration of M-R with fixed base 2
  if (!millerRabinBaseTest(n, 2n)) return false;
  return lucas(n);
}

/**
 * Function to test if number is probable prime according to FIPS186-5.
 * Differences with bailliePSW:
 * - non-deterministic
 * - multiple rounds of Miller-Rabin tests (with different bases)
 * @param n - number to test
 * @param iters - iteration count (how much random bases to test)
 */
export function isProbablePrime(n: bigint, iters: number, randFn: RandFn = randomBytes): boolean {
  const sieveRes = checkSieve(n);
  if (sieveRes !== undefined) return sieveRes;
  if (!millerRabin(n, iters, randFn)) return false;
  return lucas(n);
}

export function isProbablePrimeRSA(n: bigint, randFn: RandFn = randomBytes): boolean {
  // - https://crypto.stackexchange.com/questions/104265/iteration-count-for-enhanced-miller-rabin
  // - https://github.com/openssl/openssl/blob/master/crypto/bn/bn_rsa_fips186_4.c
  const nLen = n.toString(2).length;
  // 1024 -> 5 (prob 2^-112)
  // 1536 -> 4 (prob 2^-128)
  // 2048 -> 4 (prob 2^-144)
  const iters = nLen > 1536 ? 4 : 5;
  return isProbablePrime(n, iters, randFn);
}

/**
 * Function to test if number is a probable safe prime.
 * A safe prime is of the form p = 2q + 1 where both p and q are prime.
 * @param p - number to test
 * @param iters - iteration count (how much random bases to test)
 * @param randFn - function to generate random bytes
 * @returns true if p is a probable safe prime, false otherwise
 */
export function isProbablySafePrime(
  p: bigint,
  iters: number,
  randFn: RandFn = randomBytes
): boolean {
  if (!isProbablePrime(p, iters, randFn)) return false;
  const q = (p - 1n) / 2n;
  return isProbablePrime(q, iters, randFn);
}
