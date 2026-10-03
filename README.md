# unodc-cyber.github.io - certificate verifier (placeholder)

Public, static verification page for training certificates issued by the Cybercrime Programme of the United Nations Office on Drugs and Crime (UNODC).

**Status: not yet live.** This repository currently serves a placeholder at https://unodc-cyber.github.io/ . No certificate status can be checked here yet, and nothing on the site produces a verification result.

This README documents the **public interface** of the verifier, so that anyone can check a certificate independently or build a compatible verifier of their own. It does not describe how certificates are issued.

## Certificate identifier

- Alphabet: Crockford Base32 (`0-9 A-Z` without `I L O U`).
- Length: **27 symbols** = 26 random symbols (130 bits) + **1 check symbol**.
- Check symbol: Damm algorithm over the 32-symbol alphabet (detects every single-symbol error and every adjacent transposition; the check symbol is itself in the alphabet). The operation table will be published with the test vectors.
- Printed form: three groups of nine separated by hyphens, e.g. `XXXXXXXXX-XXXXXXXXX-XXXXXXXXX`. Canonical form: 27 upper-case symbols, no separators.
- Input normalisation before checking: remove spaces and hyphens, convert to upper case, map `I` and `L` to `1` and `O` to `0`. A failed check symbol is reported before any network request.

## Verify address

```
https://unodc-cyber.github.io/v/<ID>#k=<REVEAL-CODE>
```

- `<ID>` is the canonical 27-symbol identifier. GitHub Pages serves this repository's `404.html` for this path (and any other unknown path); at launch that file is the verifier.
- The optional fragment `#k=` carries the 10-symbol reveal code printed on the certificate. A URL fragment is never sent to any server.

## Registry

The registry will be served from the same origin as the verifier (`https://unodc-cyber.github.io`); its exact location will be published here before launch. It contains no personal data and no identifiers in clear. In the steps below, `<registry>` stands for that location.

| File | Content |
|---|---|
| `manifest.json` | `schema`, `seq` (snapshot number), `asOf` and `expires` (UTC timestamps), `generator` (string), `entries` (count), `kid` (signing key id), `files` (SHA3-512 of every other registry file) |
| `manifest.sig.json` | `kid`, `alg` = `ML-DSA-65+Ed25519`, `mldsa65` and `ed25519` signatures over the exact bytes of `manifest.json` (base64url) |
| `r/0.json` ... `r/f.json` | 16 shards; an entry is stored in the shard named by the first hexadecimal digit of `SHA3-512(ID)` |
| `meta.json` | schema version and the certificate-type code table |

### Record schema

Each shard is canonical JSON, entries sorted by key:

```json
{"v":2,"c":{"<registry key>":{
  "s":"V", "t":"CMP",
  "sv":2, "sp":"a2id-64m-3t-1p",
  "kdf":{"alg":"argon2id","v":19,"m":65536,"t":3,"p":1,"len":32},
  "salt":"...",
  "kcv_s":"...", "n_s":"...", "w_s":"...",
  "kcv_e":"...", "n_e":"...", "w_e":"...",
  "n_c":"...", "enc":"..."}}}
```

- **Registry key** (opaque): `SHA3-512(ID)` over the ASCII bytes of the canonical identifier, base64url-encoded. Identifiers themselves are never published, so a valid identifier cannot be harvested from the registry.
- **Public fields**: `s` status (`V` valid, `R` revoked) and `t` certificate-type code (looked up in `meta.json`, e.g. `CMP` = Completion, `ATT` = Attendance).
- **Sealed payload**: everything else. It holds the course title, dates and venue and can be opened only with the holder's own inputs (see Reveal flow).

## Cryptographic primitives and parameters

| Purpose | Primitive |
|---|---|
| Every hash (registry key, file hashes, key-check values, fingerprints) | **SHA3-512** |
| Key derivation | **Argon2id** (version 19), 32-byte output. Parameters are stored in every record (`kdf`, plus profile id `sp` and seal-format version `sv`), so they can be raised for new records without breaking old ones. Minimum: m = 19 MiB, t = 2, p = 1; current target profile `a2id-64m-3t-1p` (m = 64 MiB, t = 3, p = 1) |
| Sealing | **XChaCha20-Poly1305** (256-bit keys, 24-byte random nonces) |
| Key commitment | Explicit **key-check value**: `kcv = SHA3-512("UNODC-CERT/KCV/v1" ‖ K)` |
| Manifest signature | **Hybrid ML-DSA-65 (FIPS 204) + Ed25519** - both signatures must verify |

Domain-separation strings: `UNODC-CERT/KCV/v1`, `UNODC-CERT/WRAP/v1`, `UNODC-CERT/SEAL/v1`.

## Verification steps

1. Normalise the identifier and check its check symbol.
2. Fetch `<registry>/manifest.json` and `<registry>/manifest.sig.json`. Verify **both** signatures against the public keys pinned in this repository's `keys.json` (the key `kid` must be valid at `asOf`). Refuse if `now > expires`; warn if the snapshot is old.
3. Compute the registry key, fetch shard `<registry>/r/<first hex digit>.json`, check its SHA3-512 against `manifest.files`, and look up the key.
4. Show the public status, always with the registry date: exactly one of **Valid (Completion)**, **Valid (Attendance)**, **Revoked** or **Not found** (absence from the registry). Any signature, hash or expiry failure means the result must not be relied on.

## Reveal flow (course details)

Course details are shown only to someone holding the certificate.

1. The user supplies their surname **or** e-mail address, plus the reveal code (taken from `#k=` or typed).
2. Normalise the factor. Names: NFKC, case-fold, NFD, drop combining marks, keep letters and digits only, NFC. E-mail: trim, case-fold, NFKC.
3. `K = Argon2id(password = factor ‖ 0x1F ‖ revealCode, salt = salt ‖ first 32 bytes of SHA3-512(ID), params from the record)`.
4. Compute the key-check value and compare with `kcv_s` (surname) or `kcv_e` (e-mail). No match: stop ("could not unlock").
5. Unwrap the content key: `CK = XChaCha20-Poly1305-decrypt(K, n_s|n_e, w_s|w_e, aad = "UNODC-CERT/WRAP/v1" ‖ registryKey)`.
6. Decrypt `enc` with `CK`, nonce `n_c`, `aad = "UNODC-CERT/SEAL/v1" ‖ registryKey`, giving the course title, dates, venue and type.

All of this runs in the browser; the surname, e-mail and reveal code never leave the device.

## Signing keys (`keys.json`)

- No signing key exists yet. `keys.json` will be added at launch by pull request.
- Each key has a `kid` and a validity period. Key fingerprint = first 128 bits of `SHA3-512(ML-DSA public key ‖ Ed25519 public key)`, in Crockford Base32. The fingerprint will be published on the organization profile so that the pinned key can be cross-checked.

## Test vectors

Conformance test vectors (identifier and check symbol, normalisation, Argon2id, key-check values, sealing, manifest signatures) will be published in this repository before launch.

## Contributing and security

Issues are welcome for problems with the page itself. Never include a person's name, e-mail address, certificate identifier or reveal code in a public issue. Security problems: use **Security → Report a vulnerability** (private). See `SECURITY.md`.

## Licence

The verifier code in this repository is licensed under the **Apache License 2.0** (see `LICENSE` and `NOTICE`). The licence does **not** cover any name, emblem, logo or other branding - see `BRANDING.md` - and it does **not** cover certificate data - see `DATA-NOTICE.md`.

---

Verification service operated by UNODC Cybercrime Programme staff. Not hosted on a unodc.org domain.
