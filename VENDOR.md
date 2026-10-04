# Vendored third-party code

The verifier ships exactly one locally built, pinned, reproducible bundle of third-party cryptography:
`assets/verifier.<hash>.js`, where `<hash>` is the first 12 hexadecimal digits of the file's SHA-256. The content-hashed
name means a page can never be paired with a different bundle from a stale cache: a new bundle is always a new file
name, and the three modules that import it (`assets/id.js`, `assets/verifier.js`, `assets/kdf-worker.js`) name it
exactly. No CDN, no package manager in this repository, no build step at runtime.
How to rebuild it and compare: `BUILD.md`.

## Shipped bundle

| File | Bytes | SHA-256 |
|---|---|---|
| `assets/verifier.804a6d17e2b5.js` | 160497 | `804a6d17e2b5a23be3a0190c41b512ca402a2a34cd9224676680baf15e014d40` |

The same value and the file name are in `assets/bundle.sha256`. SHA-512 (SRI form):
`sha512-Ntsn2frpLw8I5n092BiYptIoN8me+med9/Ltr4MRbh+wmPKphWP5XcPucjkTUaUeJF8eRaUYxX+6UevxlktCyQ==`.
Compressed size: about 54 KB (gzip -9). Changed 2026-10-03 for SPEC DRAFT 0.4 (signed build time, rollback rule, holder name in the sealed details); package versions unchanged. Renamed by content hash 2026-10-04 (bytes unchanged). Rebuilt 2026-10-04 from verification-only modules (`src/crypto/kdfCore.js`, `src/crypto/signingVerify.js`); verifier behaviour and package versions unchanged. Licence texts of everything inside it: `assets/verifier.bundle.LICENSES.txt`
(the noble packages also keep their inline `/*! ... */` banners).

The bundle's own sources are `src/site-entry.js` and `src/crypto/*.js` (checksums in `src/SHA256SUMS`).

## Packages inside the bundle (exact versions; integrity = the npm registry tarball's SRI value)

| Package | Version | Licence | Used for | Integrity |
|---|---|---|---|---|
| `hash-wasm` | 4.12.0 | MIT | Argon2id (WebAssembly, inlined as base64; no `.wasm` file) | `sha512-+/2B2rYLb48I/evdOIhP+K/DD2ca2fgBjp6O+GBEnCDk2e4rpeXIK8GvIyRPjTezgmWn9gmKwkQjjx6BtqDHVQ==` |
| `@noble/hashes` | 2.4.0 | MIT | SHA3-512; Argon2id in pure JavaScript (used when WebAssembly is unavailable) | `sha512-X5XaVWZIBCT7HHZGm5I7ZQXDwLG+bGXuSrMQAW+7Zvl87h1kmc1ZB1VSRJcpUfoUrGQp4Fkoxm5kZ+Ms+aW+eA==` |
| `@noble/ciphers` | 2.4.0 | MIT | XChaCha20-Poly1305 | `sha512-AnjFn0Jv92laAkvMrghlFZq4qQCIN/4DxFV/eooqtC2YTjB7kBeLMS2T9KJX4Dn+ZVXLOwK0lSgqDtx9gvxtiw==` |
| `@noble/curves` | 2.4.0 | MIT | Ed25519 (strict verification) | `sha512-P4/62zrgfH33CneE3Dn4WhJVA22YUU0eR51wKIan4NVRvwsA0YnPTwWGpNbpuacSujmSFLvyzpyuR30+fbq2Ew==` |
| `@noble/post-quantum` | 0.7.1 | MIT | ML-DSA-65 verification (FIPS 204). Pre-1.0 release; the hybrid design also requires Ed25519 to verify | `sha512-+P9981IiAnVh+rmcubozzVwrEy3XsN/tMhTnvsjV9VDaYpOnNCqWqKo2FLWxbu92YHfjGIlE5XnW175UK+ln+Q==` |

Build tool (build machine only, not shipped):

| Package | Version | Licence | Integrity |
|---|---|---|---|
| `esbuild` | 0.28.2 | MIT | `sha512-HKVLS8dvII+xoKW9kmqxbRKrnWEXfJJr/FZhhJmiqIB0e053QNYFqOBouTMO/k5sID4MvCiUCvv8b9M4h32wIA==` |
| `@esbuild/win32-x64` (platform binary used for the recorded build) | 0.28.2 | MIT | `sha512-5ebpxr3nWMzrL/rnUI755Jkuee0bHL/Gq0WTF9lvcpv73wAp5eu8MfBUgWK9bhWvZjj7yX8etf/8tI8Ney695g==` |

## Rules
1. Versions are pinned exactly (no ranges). A version change is a reviewed commit that updates this file, the bundle
   (new content-hashed file name; the old file is removed), the three importing modules, `assets/bundle.sha256`, `src/`
   and `assets/verifier.bundle.LICENSES.txt` together.
2. The shipped bundle is reproducible: `BUILD.md` gives the exact command; a reviewer rebuilds and compares the SHA-256.
3. No code is loaded from a third-party host at runtime (enforced by the page's content security policy). The only cross-origin request is for registry DATA from the single pinned origin `https://raw.githubusercontent.com` (SPEC.md 4), read as bytes and verified before use.
4. Licence notices travel with the code (inline banners + `assets/verifier.bundle.LICENSES.txt`).
