# Build and review notes

The site is static HTML, CSS and ES modules. The only built file is the cryptography bundle
`assets/verifier.<hash>.js` (`<hash>` = the first 12 hexadecimal digits of its SHA-256; the current name and full
digest are in `assets/bundle.sha256`; see `VENDOR.md`). Everything else is hand-written and served as is.

## Run the conformance vectors

```
node test/run-vectors.mjs              # test/vectors.json against the shipped bundle, in Node 22 or later
```
Serve the repository from any local static web server and open `/test/harness.html` to run the same vectors in a
browser against the same bundle. The vectors are part of the public interface (SPEC.md section 11); the key `test-k1`
and every secret in them are TEST-ONLY.

The registry is never served from this site's origin (SPEC.md 4). The pages' content security policy allows exactly one
other origin for data, `https://raw.githubusercontent.com`; the verifier pins the full registry base URL in
`assets/verifier.js` (`REGISTRY_BASES`).

## What the bundle is

- Entry `src/site-entry.js`; modules `src/crypto/*.js` (identifiers, normalisation, SHA3-512, Argon2id, sealing,
  manifest, signature verification) as comment-free, type-free ES2020. Checksums of these files are in `src/SHA256SUMS`. The issuer
  builds the bundle from its own sources and from this mirror and requires the two outputs to be byte-identical before
  publishing.
- One ES2020 module, whitespace- and syntax-minified. Identifiers are deliberately NOT renamed: readable names make
  review easier, and renaming would make the output depend on comment text. No source map is published.
- Status path (identifier, manifest signature, shard digest) needs no WebAssembly. Argon2id uses hash-wasm's inlined
  WebAssembly (needs `'wasm-unsafe-eval'` in the page policy) and falls back to the pure-JavaScript implementation.
- `assets/kdf-worker.js` (same-origin module worker) runs the reveal derivation off the page thread; `assets/verifier.js`
  holds the verification flow; `assets/id.js` is a thin adapter over the bundle for the page's live input feedback.

## Reproduce the bundle (reviewer)

Use Node 22 or later, in a throwaway directory outside this repository:

```
mkdir verifier-build && cd verifier-build
npm init -y
npm i --save-exact --no-audit --no-fund hash-wasm@4.12.0 @noble/hashes@2.4.0 @noble/ciphers@2.4.0 @noble/curves@2.4.0 @noble/post-quantum@0.7.1 esbuild@0.28.2
#   compare the "integrity" values in package-lock.json with VENDOR.md
cp -r <this repository>/src ./src
npx esbuild src/site-entry.js --bundle --format=esm --platform=browser --target=es2020 --minify-whitespace --minify-syntax --legal-comments=inline --charset=utf8 --outfile=verifier.js
sha256sum verifier.js                  # must equal the digest in assets/bundle.sha256 (PowerShell: Get-FileHash verifier.js)
cmp verifier.js <this repository>/assets/verifier.<hash>.js
```

Recorded result (2026-10-04, SPEC DRAFT 0.4): builds from the issuer's sources, a build from `src/`, and a clean
reviewer build with the command above all gave
`804a6d17e2b5a23be3a0190c41b512ca402a2a34cd9224676680baf15e014d40` (160497 bytes), shipped as
`assets/verifier.804a6d17e2b5.js`.

Then run `node test/run-vectors.mjs` against the rebuilt file (copy it over the shipped one, same name).

## Publishing checklist

1. Rebuild and compare the SHA-256 (above); update `VENDOR.md` if any pin changed.
2. Conformance vectors pass in Node and in a browser; every refusal case and the accessibility checks pass.
3. Copy only site files into the repository; never `node_modules`, a lock file or build scratch files.
