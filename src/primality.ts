import { randomBytes } from '@noble/hashes/utils.js';
import { gcd, mod, numberToBytesBE, pow, type RandFn, randomBits, type TArg } from './utils.ts';

const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _2n = /* @__PURE__ */ BigInt(2);
const _3n = /* @__PURE__ */ BigInt(3);
const _4n = /* @__PURE__ */ BigInt(4);
const _5n = /* @__PURE__ */ BigInt(5);
const _7n = /* @__PURE__ */ BigInt(7);
const _8n = /* @__PURE__ */ BigInt(8);

// Non-deterministic Miller-Rabin test over random bases (multiple iterations).
// This test is probabilistic and may produce false positives (pseudoprimes).
// Increasing the iteration count decreases false-positive probability.
// Usage: quick practical primality testing where some false-positive risk is acceptable.
// WARNING: There are known pseudoprimes (false positives) for it!

// Deterministic Lucas test. Does not rely on random bases.
// Generally slower than Miller-Rabin, but can be more reliable for some numbers.
// Usage: Useful when a deterministic result is preferred over a probabilistic one.
// WARNING: There are known pseudoprimes (false positives) for it!

// Deterministic test which consists of Miller-Rabin with base 2 and Lucas test.
// This combined approach leverages both tests to improve accuracy.
// It is designed to avoid known pseudoprimes for both individual tests.
// Usage: Suitable for critical applications where the highest reliability is required.
// No pseudoprimes (false positives) known!

// [Best] Non-deterministic test from FIPS186-5.
// This enhanced Baillie-PSW-style test adds multiple random Miller-Rabin rounds.
// It aims to provide a very high level of confidence in the primality result.
// Usage: Recommended for most applications, balancing performance and reliability.
// The combination of multiple tests significantly reduces the probability of false positives.

// Non-deterministic safe prime test.
// Tests if a number is a probable safe prime, i.e. p = 2q + 1 with p and q prime.
// NOTE: they are very rare and finding one takes a lot of time.

function validateMillerRabinIterations(iterations: number) {
  // FIPS 186-5 Appendix B.3 uses minimum Miller-Rabin round counts from
  // Table B.1 / Appendix C.1, while B.3.1 step 4 only defines the loop for
  // `i = 1` through `iterations`. Positive low counts are caller policy;
  // zero would skip Miller-Rabin testing entirely.
  if (!Number.isSafeInteger(iterations) || iterations <= 0)
    throw new Error('number of iterations should be positive safe integer');
}

/**
 * Function to perform the Miller-Rabin primality test
 * @param w - Odd integer to test for probable primality.
 * @param iterations - Number of random-base rounds to execute.
 * @param randFn - Random-byte generator used to choose Miller-Rabin bases.
 * @returns `true` when the candidate passes every round, `false` for a composite witness.
 * @throws If the candidate, iteration count, or random-byte generator is invalid. {@link Error}
 * @example
 * 23 is prime, so Miller-Rabin accepts it for any random base.
 * ```ts
 * import { millerRabin } from 'micro-rsa-dsa-dh/primality.js';
 * millerRabin(23n, 3);
 * ```
 */
export function millerRabin(
  w: bigint,
  iterations: number,
  randFn: TArg<RandFn> = randomBytes
): boolean {
  if (typeof w !== 'bigint') throw new Error('number expected to be bigint');
  validateMillerRabinIterations(iterations);
  if (typeof randFn !== 'function') throw new Error('randFn should be function');
  if (w < _2n) return false;
  const w1 = w - _1n;
  // FIPS 186-5 Appendix B.3.1 step 4.2 requires 1 < b < w - 1.
  // The smallest integer base is 1 + 1, so it must still be below w - 1.
  if (_2n >= w1) throw new Error('millerRabin: invalid candidate, no valid random base interval');
  // Step 1: Find a such that 2^a * m = w - 1
  let a = 0;
  let m = w1;
  while ((m & _1n) === _0n) {
    m >>= _1n;
    a += 1;
  }
  if (m << BigInt(a) !== w1) throw new Error('millerRabin: wrong assertion');
  const wlen = w.toString(2).length; // 3. _wlen_ = **len** ( _w_ ).
  step4: for (let i = 1; i <= iterations; i++) {
    // Step 4.1 + 4.2
    let b: bigint = _0n;
    while (b <= _1n || b >= w1) b = randomBits(wlen, randFn);
    let z = pow(b, m, w); // Step 4.3
    if (z === _1n || z === w1) continue; // Step 4.4
    // Step 4.5
    for (let j = 1; j <= a - 1; j++) {
      z = (z * z) % w; // Step 4.5.1
      if (z === w1) continue step4; // Step 4.5.2 + 4.7 (continue 4)
      if (z === _1n) return false; // 4.5.3 + 4.6
    }
    return false;
  }
  return true;
}

/**
 * Deterministic Miller-Rabin check for a single fixed base.
 * @param w - Odd integer to test for probable primality.
 * @param base - Miller-Rabin base to evaluate against `w`.
 * @returns `true` when `w` passes the selected base test.
 * @throws If the candidate is invalid or an internal Miller-Rabin invariant fails. {@link Error}
 * @example
 * Run a single deterministic Miller-Rabin round with base 2.
 * ```ts
 * import { millerRabinBaseTest } from 'micro-rsa-dsa-dh/primality.js';
 * millerRabinBaseTest(23n, 2n);
 * ```
 */
export function millerRabinBaseTest(w: bigint, base: bigint): boolean {
  if (typeof w !== 'bigint') throw new Error('number expected to be bigint');
  if (typeof base !== 'bigint') throw new Error('base should be bigint');
  if (w < _2n) return false;
  // FIPS 186-5 Appendix B.3.1 step 4.2 says:
  // "If ((b <= 1) or (b >= w - 1)), then go to step 4.1."
  // Fixed bases cannot change on retry, and oversized encodings would be
  // masked by randomBits(), so reject values outside 1 < base < w - 1 here.
  if (base <= _1n || base >= w - _1n) throw new Error('millerRabinBaseTest: invalid base');
  return millerRabin(w, 1, (len) => numberToBytesBE(base, len));
}

/**
 * Determines if positive integer C is a perfect square.
 * From FIPS186-5 (B.4 CHECKING FOR A PERFECT SQUARE).
 * @param C positive integer
 * @returns true if integer is a perfect square
 */
function isPerfectSquare(C: bigint): boolean {
  const n = C.toString(2).length; // Step 1: Determine n such that 2^n > C >= 2^(n-1)
  const m = BigInt(Math.ceil(n / 2)); // Step 2: m = ⌈n / 2⌉
  // Step 4: Select X0 such that 2^m > X0 >= 2^(m-1)
  let X0 = _1n << (m - _1n);
  if (X0 * X0 > C) X0 >>= _1n;
  if (!(_1n << m > X0 && X0 >= _1n << (m - _1n)))
    throw new Error('isPerfectSquare: wrong assertion');
  // FIPS 186-5 Appendix B.4 step 5 says to repeat the Newton update
  // "Until (Xi)^2 < 2^m + C"; step 6 then compares C with floor(Xi)^2.
  // Do not use a repeated-value sentinel here: small nonsquares such as 3
  // can otherwise oscillate instead of reaching the FIPS stop condition.
  const limit = (_1n << m) + C;
  let Xi = X0;
  let sq = Xi * Xi;
  do {
    Xi = (sq + C) / (Xi << _1n);
    sq = Xi * Xi;
  } while (sq >= limit);
  return sq === C; // Step 6: Check if C is a perfect square
}

/**
 * This routine computes the Jacobi symbol. From FIPS186-5 (B.5 JACOBI SYMBOL ALGORITHM)
 * @param a - Value from the Lucas parameter search sequence.
 * @param n - Candidate integer being tested.
 * @returns Jacobi symbol for `(a / n)`.
 * @example
 * Jacobi symbols are used while selecting Lucas parameters.
 * ```ts
 * import { jacobi } from 'micro-rsa-dsa-dh/primality.js';
 * jacobi(5n, 11n);
 * ```
 */
export function jacobi(a: bigint, n: bigint): number {
  a = mod(a, n); // Step 1
  if (a === _1n || n === _1n) return 1; // Step 2
  if (a === _0n) return 0; // Step 3
  // Step 4: Define e and a1 such that a = 2^e * a1, where a1 is odd
  let e = 0;
  while ((a & _1n) === _0n) {
    a >>= _1n;
    e++;
  }
  const a1 = a;
  // Step 5
  let s = 1;
  if (e % 2 !== 0) {
    const mod8 = mod(n, _8n);
    if (mod8 === _1n || mod8 === _7n) s = 1;
    else if (mod8 === _3n || mod8 === _5n) s = -1;
  }
  if (mod(n, _4n) === _3n && mod(a1, _4n) === _3n) s = -s; // Step 6
  const n1 = mod(n, a1); // Step 7
  return s * jacobi(n1, a1); // Step 8
}

/**
 * (General) Lucas Probabilistic Primality Test (From FIPS186-5)
 * @param C - Positive integer candidate.
 * @returns `true` when the Lucas test accepts the candidate.
 * @throws If the candidate is not a bigint. {@link TypeError}
 * @throws If an internal Lucas invariant fails. {@link Error}
 * @example
 * Lucas complements Miller-Rabin in the Baillie-PSW test.
 * ```ts
 * import { lucas } from 'micro-rsa-dsa-dh/primality.js';
 * lucas(29n);
 * ```
 */
export function lucas(C: bigint): boolean {
  if (typeof C !== 'bigint') throw new TypeError('number expected to be bigint');
  if (C < _2n) return false;
  if (C === _2n) return true;
  if ((C & _1n) === _0n) return false;
  if (isPerfectSquare(C)) return false; // Step 1
  // Step 2: Find first D in sequence 5, -7, 9, -11, 13, -15, ...
  let D = _5n;
  for (; ; D = -(D + (D > _0n ? _2n : -_2n))) {
    const js = jacobi(D, C);
    // If Jacobi(D/C) is 0 for any D in the sequence, return COMPOSITE.
    if (js === 0) return false;
    // GCD check added in FIPS186-5
    if (js === -1 && gcd(C, (_1n - D) / _4n) === _1n) break;
  }
  const K = C + _1n; // Step 3
  const Kbin = K.toString(2);
  const r = Kbin.length - 1; // Step 4
  // prettier-ignore
  let Ui = _1n, Vi = _1n; // Step 5
  // Computes (A * (C + 1) / 2) % C
  const half = K >> _1n; // (C + 1) / 2
  const div2 = (A: bigint) => mod(A * half, C);
  // Step 6: bit i of K is Kbin[r - i]; iterate i = r-1 ... 0
  for (let j = 1; j <= r; j++) {
    const Utemp = mod(Ui * Vi, C); // Step 6.1
    const Vtemp = div2(Vi * Vi + Ui * Ui * D); // Step 6.2
    if (Kbin.charCodeAt(j) === 49 /* '1' */) {
      Ui = div2(Utemp + Vtemp); // Step 6.3.1
      Vi = div2(Vtemp + Utemp * D); // Step 6.3.2
    } else {
      Ui = Utemp; // Step 6.3.3
      Vi = Vtemp; // Step 6.3.4
    }
  }
  return Ui === _0n; // Step 7
}

// FIPS 186-5 Appendix B.3 / Appendix B.7 pick the minimal compliant
// trial-division limit L = 1000, i.e. every prime <= 997.
// prettier-ignore
const sieveBase: Set<bigint> = /* @__PURE__ */ new Set(/* @__PURE__ */ [
  // https://en.wikipedia.org/wiki/List_of_prime_numbers
  // 1-20
  2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
  // 21-40
  73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
  // 41-60
  179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
  // 61-80
  283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
  // 81-100
  419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
  // 101-120
  547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
  // 121-140
  661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
  // 141-160
  811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
  // 161-180
  947, 953, 967, 971, 977, 983, 991, 997,
].map((i) => BigInt(i)));

function checkSieve(n: bigint) {
  if (typeof n !== 'bigint') throw new Error('expected bigint');
  if (n < _0n) throw new Error('negative numbers not supported');
  if (n === _1n) return false; // false
  if (n !== _2n && n % _2n === _0n) return false;
  // First, check trial division by the smallest primes
  if (sieveBase.has(n)) return true;
  for (const prime of sieveBase) if (n % prime === _0n) return false;
  return;
}

/**
 * Baillie–PSW primality test
 * @param n - Number to test for primality.
 * @returns `true` when the candidate passes Miller-Rabin base 2 and Lucas checks.
 * @throws If the candidate is invalid or an internal primality-test invariant fails. {@link Error}
 * @example
 * Baillie-PSW combines Miller-Rabin base 2 with Lucas.
 * ```ts
 * import { bailliePSW } from 'micro-rsa-dsa-dh/primality.js';
 * bailliePSW(29n);
 * ```
 */
export function bailliePSW(n: bigint): boolean {
  const sieveRes = checkSieve(n);
  if (sieveRes !== undefined) return sieveRes;
  // BPSW does single iteration of M-R with fixed base 2
  if (!millerRabinBaseTest(n, _2n)) return false;
  return lucas(n);
}

/**
 * Function to test if number is probable prime according to FIPS186-5.
 * Differences with bailliePSW:
 * - non-deterministic
 * - multiple rounds of Miller-Rabin tests (with different bases)
 * @param n - number to test
 * @param iters - iteration count (how much random bases to test)
 * @param randFn - Random-byte generator used to choose Miller-Rabin bases.
 * @returns `true` when the candidate passes every selected primality check.
 * @throws If the candidate, iteration count, or random-byte generator is invalid. {@link Error}
 * @example
 * FIPS 186 prime checks add random Miller-Rabin rounds before Lucas.
 * ```ts
 * import { isProbablePrime } from 'micro-rsa-dsa-dh/primality.js';
 * isProbablePrime(29n, 3);
 * ```
 */
export function isProbablePrime(
  n: bigint,
  iters: number,
  randFn: TArg<RandFn> = randomBytes
): boolean {
  validateMillerRabinIterations(iters);
  const sieveRes = checkSieve(n);
  if (sieveRes !== undefined) return sieveRes;
  if (!millerRabin(n, iters, randFn)) return false;
  return lucas(n);
}

/**
 * RSA-tuned probable-prime check using FIPS 186 iteration counts.
 * @param n - Candidate integer to test.
 * @param randFn - Random-byte generator used by the Miller-Rabin rounds.
 * @returns `true` when the candidate passes the RSA-oriented probable-prime checks.
 * @throws If the candidate or random-byte generator is invalid. {@link Error}
 * @example
 * RSA key generation uses the iteration counts from FIPS 186.
 * ```ts
 * import { isProbablePrimeRSA } from 'micro-rsa-dsa-dh/primality.js';
 * isProbablePrimeRSA(65537n);
 * ```
 */
export function isProbablePrimeRSA(n: bigint, randFn: TArg<RandFn> = randomBytes): boolean {
  // - https://crypto.stackexchange.com/questions/104265/iteration-count-for-enhanced-miller-rabin
  // - https://github.com/openssl/openssl/blob/master/crypto/bn/bn_rsa_fips186_4.c
  const nLen = n.toString(2).length;
  // FIPS 186-5 Table B.1 uses 5 rounds for 1024-bit RSA factors and at
  // least 4 for 1536-/2048-bit factors; this helper keeps the stricter
  // 5-round setting through 1536 bits.
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
 * @returns `true` when both `p` and `(p - 1) / 2` pass the probable-prime checks.
 * @throws If the candidate, iteration count, or random-byte generator is invalid. {@link Error}
 * @example
 * Safe primes are needed by DH and ElGamal-style groups.
 * ```ts
 * import { isProbablySafePrime } from 'micro-rsa-dsa-dh/primality.js';
 * isProbablySafePrime(23n, 3);
 * ```
 */
export function isProbablySafePrime(
  p: bigint,
  iters: number,
  randFn: TArg<RandFn> = randomBytes
): boolean {
  if (!isProbablePrime(p, iters, randFn)) return false;
  const q = (p - _1n) / _2n;
  return isProbablePrime(q, iters, randFn);
}
