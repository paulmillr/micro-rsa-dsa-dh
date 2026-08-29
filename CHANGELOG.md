# Changelog for micro-rsa-dsa-dh

## 0.4.0 (2026-08-29)

- Hardened all algorithms: stricter parameter and type validation across RSA, DSA, DH, ElGamal and primality testing
- Made custom DH groups require validated `{ p, q, g }` parameters with a prime-order subgroup; moved obsolete modp1 / modp2 / modp5 groups to `LegacyDHGroups`, which need an explicit `allowUnsafeLegacy` opt-in
- Made ElGamal encryption operate on byte plaintexts via a hashed KEM (XChaCha20-Poly1305); textbook encryption and raw signatures now require explicit unsafe compatibility options
- Restricted DSA to approved FIPS size pairs; updated docs and examples from SHA-1 / 1024-bit to SHA-2 / 2048-bit parameters
- Added RSA modulus and exponent bounds checks, and verification of private-key operations against the public key to resist fault attacks
- Added a custom `randFn` parameter to `genElGamalParams()`

## 0.3.0 (2026-04-28)

- **April 2026 self-audit** (all files): no major issues found
  - Audited for spec compliance and security
  - Hardened all the minor bits
- Fix all Byte Array types, to ensure proper work in both TypeScript 5.6 & TypeScript 5.9+
  - TS 5.6 has `Uint8Array`, while TS 5.9+ made it generic `Uint8Array<ArrayBuffer>`
  - This creates incompatibility of code between versions
  - Previously, it was hard to use and constantly emitted errors similar to `TS2345`
  - See [typescript#62240](https://github.com/microsoft/TypeScript/issues/62240) for more context
- Fix compilation issues on TypeScript v6
- Add documentation comments everywhere

## 0.2.3 (2025-09-18)

- Add back export maps for text editor autocompletion

## 0.2.2 (2025-08-25)

- Upgrade to stable noble v2

## 0.2.1 (2025-08-20)

- Fixes failed JSR publish for 0.2.0: https://github.com/paulmillr/micro-rsa-dsa-dh/releases/tag/0.2.0

## 0.2.0 (2025-08-20)

- The package is now pure ESM and requires node.js v20.19+ (which supports loading ESM from CJS)
- Bump dependencies to noble v2-beta
- Publish to JSR.io

## 0.1.0 (2024-07-04)

Initial release
