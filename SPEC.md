# Certificate verification - public interface specification

Status: DRAFT 0.4 (2026-10-03). Identifier, sealing, manifest and signature sections fixed; conformance vectors in
test/vectors.json. Changes since DRAFT 0.3 are listed in section 13. This document describes the public interface of the
certificate verification service published at this site: identifier format, link format, registry data format,
cryptographic primitives and parameters, and the checks the verifier page performs.
It describes a generic "issuing system". Nothing here is a statement about who operates that
system or how it works internally.

Terms: MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose and public states

A certificate carries a unique identifier, printed and encoded in a QR code. The verifier page
answers one question - "is a certificate with this identifier recorded as valid?" - using a signed,
public registry that contains only hash-derived keys, status codes and sealed (encrypted) details, never names in clear.

The page shows exactly one of four public states, always together with the line
"Registry last updated <date>":

| State | Shown when |
|---|---|
| Valid - Certificate of Completion | entry present, status `V`, type `CMP` |
| Valid - Certificate of Attendance | entry present, status `V`, type `ATT` |
| Revoked - not valid | entry present, status `R` |
| Not found | no entry for the identifier in the registry as last updated |

The two non-certifying types of `meta.json` are shown the same way: `V` + `APP` = "Valid - Certificate of
Appreciation", `V` + `TRN` = "Valid - Certificate of Contribution". A `V` entry with any other type is treated as an
integrity failure.

A valid state applies to the identifier, not to whoever presents it. Every valid state therefore carries the line
"This status applies to the certificate with this identifier. Unlock the course details below to confirm the holder's
name." The holder's name is shown only after the reveal step (section 6).

Not found does not mean forged: a certificate issued recently may not be published yet. The page
never reveals why an entry has its status and never shows a person's name before a successful reveal.

Additional non-certificate outcomes (no status is shown with any of them): "Could not verify the registry's integrity"
(any failure in section 7), "registry is older than a version already seen on this device or required by this site"
(section 7.5), "registry is out of date" (`now > expires`), "registry date is later than this device's date"
(`issued > now + 1 day`, usually a wrong device clock), "registry unreachable", and "verification service not yet live"
(`keys.json` is a production list with no keys, section 7.1; checked before any registry response is used). When the pinned key list is a test list
(`keys.json` `"production": false`) every state carries a "test registry" banner.

## 2. Identifier

### 2.1 Alphabet
32 symbols, Crockford base32: `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no `I`, `L`, `O`, `U`).
Symbol value = index in that string (0..31).

### 2.2 Structure
27 symbols = 26 random symbols (130 bits) + 1 check symbol. Printed in three groups of nine
separated by hyphens (`XXXXXXXXX-XXXXXXXXX-XXXXXXXXX`); the canonical form has no separators.

### 2.3 Check symbol (Damm over a 32-symbol quasigroup)
Operation on 5-bit values: `q(i, d) = mulx(i XOR d)` where `mulx(v)` is multiplication by `x` in
GF(2^5) modulo `x^5 + x^2 + 1`, i.e. `v <<= 1; if (v & 32) v ^= 0x25`.
Start `interim = 0`; for each of the 26 symbols `interim = q(interim, value)`. The check symbol is
the symbol whose value equals the final `interim`. An identifier is well formed when processing all 27
symbols ends with `interim == 0`. This detects every single-symbol substitution, every adjacent
transposition (including one involving the check symbol) and every twin error (`aa` -> `bb`):
for fixed `i`, `d -> x(i+d)` is a bijection; `q(q(i,a),b) + q(q(i,b),a) = x(x+1)(a+b) != 0` for `a != b`;
`q(q(i,a),a) = x^2 i + x(x+1)a` is injective in `a`. These properties are verified exhaustively over all
32 x 32 x 32 cases by the issuer's tests and by the conformance vectors (section 11).
Jump transpositions (`abc` -> `cba`) are not guaranteed to be detected.

### 2.3a Reveal key
10 random Crockford symbols (50 bits), printed in two groups of five (`XXXXX-XXXXX`). The reveal key has
**no check symbol**: it is never looked up, only fed to the key derivation (5.2), so a mistyped reveal key
produces the same "could not unlock" result as a wrong family name. Typed input is cleaned exactly as in 2.4.

### 2.4 Input normalisation (before any lookup)
NFKC, uppercase, remove spaces, hyphens and dash variants, map `I` and `L` to `1`, `O` to `0`.
Any remaining symbol outside the alphabet is invalid and is reported by position. The result MUST
be 27 symbols with a valid check symbol; otherwise no network request is made.

### 2.5 Registry key
`registryKey = base64url(SHA3-512(ASCII(canonical 27 symbols)))`, no padding. The registry lists keys,
never identifiers, so published data does not let anyone harvest a valid identifier.
The shard that holds an entry is the first hexadecimal digit of that SHA3-512 digest (0-f).

## 3. Links

`https://<site>/v/<27 symbols>` optionally followed by `#k=<10 symbols>` (reveal key, section 5.1).
The path part may be sent to the web server; the fragment never is. The static host answers
unknown paths with its `404.html`, which forwards `/v/<ID>[#k=<key>]` to `/?id=<ID>[#k=<key>]`,
keeping the fragment. `/v` and `/v/` forward to `/`. Both URL forms use the canonical (unhyphenated)
identifier; the lookup page also accepts the printed grouped form.

## 4. Registry data

The registry is published as plain files in a separate public data repository and is read by the verifier
**cross-origin** from exactly one pinned base URL:

    https://raw.githubusercontent.com/UNODC-Cyber/registry/main/

The registry is NOT served from this site's origin, and the data repository has no web site of its own: nothing
anyone commits to the data repository can run as script on, or share storage with, the verifier's origin.
A verifier MUST:
- take the base URL from a list pinned in its own reviewed code (`REGISTRY_BASES` in `assets/verifier.js`), never from
  the registry, a link or a query parameter;
- fetch with `mode: cors`, `credentials: omit`, `redirect: error` and no referrer;
- treat every response as untrusted bytes: ignore `Content-Type`, never render or execute them, only hash them and
  parse them as JSON after the checks of section 7;
- allow that origin (and no other) in its content security policy's `connect-src`.
The host answers with `Access-Control-Allow-Origin: *` and caches files for about five minutes, so a newly published
snapshot is visible within minutes.

```
<base>/
  manifest.json       signed index (4.1)
  manifest.sig.json   signature (7.2)
  meta.json           {"schema":2,"types":{"CMP":"completion","ATT":"attendance","APP":"appreciation","TRN":"contribution"}}
  r/0.json ... r/f.json   shards (4.2)
```
All JSON files are canonical: UTF-8, object keys sorted, no insignificant whitespace, entries ordered
by key, no timestamps inside shards.

A local test harness may serve the same files from a second loopback origin. The verifier honours such a loopback
base only when the page itself is served over `http` from a loopback host; a page on any real host can never use it.

### 4.1 manifest.json (schema 3)
```
{"asOf":"<ISO 8601 UTC>","entries":<int>,"expires":"<ISO 8601 UTC>",
 "files":{"meta.json":"<digest>","r/0.json":"<digest>", ... ,"r/f.json":"<digest>"},
 "generator":"<neutral version string>","issued":"<ISO 8601 UTC>","kid":"<key id>","schema":3,"seq":<int>}
```
`digest` = base64url (no padding) of SHA3-512 over the exact bytes of that file. `seq` increases by at least one
per published snapshot, including a snapshot that only renews `expires`; it never decreases. `asOf` is the time of the
last content change (not the last check): the page therefore says "Registry last updated", never "checked".
`issued` is the time the manifest was built and signed. Both are signed. Date rules (a manifest that breaks any of them
MUST be refused): `asOf <= issued < expires` and `expires - issued <= 60 days`. A renewal that only extends the
validity keeps `asOf`, and sets a new `issued`, a new `expires` and a new `seq`. Readers MUST ignore unknown fields.

### 4.2 Shard `r/<x>.json`
```
{"c":{"<registryKey>":{"s":"V","t":"CMP","sv":3,"sp":"<profile id>",
  "kdf":{"alg":"argon2id","v":19,"m":<KiB>,"t":<int>,"p":<int>,"len":32},"salt":"<b64url 16 B>",
  "kcv_s":"..","n_s":"..","w_s":"..",   "kcv_e":"..","n_e":"..","w_e":"..",   "n_c":"..","enc":".."}},
 "v":2}
```
`s`: `V` valid or `R` revoked (a downgrade is expressed by publishing the effective public type, `ATT`;
the registry never records that a type was downgraded). `t`: type code from `meta.json`; it is the only type a
verifier ever displays. `sv` seal-format version (5.3); `sp` named parameter profile (informational); `kdf` the explicit
parameters actually used for this entry - the verifier always uses the entry's own `kdf`, never a built-in table.

## 5. Cryptography

All hashing is SHA3-512. All key derivation is Argon2id. No weaker fallback exists.

### 5.1 Reveal key and factors
Each certificate has a reveal key `k` of 10 Crockford symbols (50 bits), printed under the QR code and
carried in the link fragment. The sealed details (course and holder name) can be opened only with
`k` plus one of two second factors: the holder's family name or e-mail address.

Factor normalisation (normalisation version 1; the conformance vectors contain the full table):
- family name: (1) NFKC; (2) lowercase (`String.prototype.toLowerCase`, locale-independent); (3) fold table:
  `đ ð -> d`, `ł -> l`, `ø -> o`, `ħ -> h`, `ŧ -> t`, `ı -> i`, `ß -> ss`, `ς -> σ`, `æ -> ae`, `œ -> oe`, `þ -> th`;
  (4) NFD and drop every combining mark of category Mn; (5) keep only letters and digits (`\p{L}\p{N}`), which also
  removes spaces, punctuation, spacing marks (Mc), zero-width joiners and bidirectional marks; (6) NFC.
  Lossy but deterministic: `Nguyễn Văn -> nguyenvan`, `de la Cruz -> delacruz`, `Đặng -> dang`.
- e-mail: NFKC, lowercase, then remove every whitespace, control (Cc) and format (Cf) character anywhere.
  Nothing else changes (plus-addressing, dots and the domain are kept).
A factor that normalises to the empty string never unlocks anything.

### 5.2 Key derivation
`K_f = Argon2id(password = UTF-8(normalise_f(factor)) || 0x1F || ASCII(k), salt = salt16 || SHA3-512(ASCII(ID))[0..32], m, t, p, outputLength = 32)`
with `m`, `t`, `p` (and version 0x13) from the entry's own `kdf`. `k` is the canonical 10-symbol reveal key.

Named profiles (a profile is only ever added, never changed; the entry's `kdf` is authoritative):

| Profile | m (KiB) | t | p | Use |
|---|---|---|---|---|
| `a2id-19m-2t-1p` | 19456 | 2 | 1 | floor (OWASP minimum) |
| `a2id-32m-3t-1p` | 32768 | 3 | 1 | tuning step |
| `a2id-47m-3t-1p` | 48128 | 3 | 1 | tuning step |
| `a2id-64m-3t-1p` | 65536 | 3 | 1 | target for new entries |

Issuers MUST NOT create entries below the floor (m >= 19456, t >= 2, p >= 1). Verifiers MUST still open an older
entry whose parameters are below a later, raised floor, but MUST NOT open an entry below this original floor.
Verifiers MUST refuse a `kdf` header with `alg != "argon2id"`, `v != 19`, `len != 32`, non-integer or non-positive
m/t/p, or m > 1048576, t > 16, p > 4 (resource-exhaustion guard).

### 5.3 Key check value, wrapping and the sealed details
Byte strings below are concatenated; `0x1F` is the ASCII unit separator; tags, `registryKey`, `sv` (decimal) and `sp`
are ASCII text.
- `kcv_s = SHA3-512("UNODC-CERT/KCV/v1/surname" || 0x00 || K_s)` and `kcv_e = SHA3-512("UNODC-CERT/KCV/v1/email" || 0x00 || K_e)`.
  The two tags differ, so a key check value computed for one factor never validates the other. A mismatch means a
  wrong factor or a wrong reveal key; the page shows one message for both.
- `CK = XChaCha20-Poly1305-open(key = K_f, nonce = n_f, ct = w_f, aad = "UNODC-CERT/WRAP/v1" || 0x1F || registryKey || 0x1F || sv || 0x1F || sp || 0x1F || f)`
  with `f` = `s` or `e`.
- `plain = XChaCha20-Poly1305-open(key = CK, nonce = n_c, ct = enc, aad = "UNODC-CERT/SEAL/v1" || 0x1F || registryKey || 0x1F || sv || 0x1F || sp)`
  is canonical JSON. For seal version `sv` 3:
  `{"c": course title, "d": dates, "f": holder family name (display form, as used for the unlock), "n": holder name exactly as printed on the certificate, "t": type code at sealing time, "v": venue, "z": padding}`.
  `n` and `f` MUST be non-empty strings; an `sv` 3 entry whose plaintext lacks either is corrupt. `t` is informational
  and MUST NOT be displayed (6.3). `z` is a run of ASCII spaces that pads the plaintext to a multiple of 256 bytes
  (at least 256), so ciphertext length does not group entries by course; readers ignore it.
- Seal version 2 (earlier entries): the same construction with plaintext `{"c","d","t","v"}` and no holder name.
  Verifiers MUST still open it and MUST then say that the name is not recorded. Issuers MUST NOT write new `sv` 2
  entries. Because `sv` is inside both associated data strings, relabelling an `sv` 3 entry as `sv` 2 breaks
  authentication (it does not turn into a "nameless" entry).
- The holder's name exists only inside this ciphertext. It never appears in any public field, file name, manifest or
  shard. A registry reader without the factor and the reveal key learns nothing about it.
- Field sizes: `salt` 16 B, `kcv_*` 64 B, `n_*` 24 B, `w_*` 48 B (32 B key + 16 B tag), `enc` >= 16 B; all base64url, no padding.
Every ciphertext is bound to its registry key, seal version and profile by the associated data, and every derived key
is bound to the identifier through the salt, so entries cannot be moved between identifiers. When the holder has no
e-mail on file the e-mail copy is a decoy made with a random key, so every entry has the same shape.
If the key check value matches but either decryption fails, the entry is corrupt (cannot happen for an entry covered
by a verified manifest).

### 5.4 Quantum-safety posture
Symmetric keys are 256 bits, hashes are SHA3-512, identifiers carry 130 bits. Registry authenticity uses a
hybrid signature (7.2): ML-DSA-65 (FIPS 204) and Ed25519; both MUST verify.

## 6. Reveal flow (holder only)
1. The status is shown first; it never depends on this step.
2. The holder enters the factor and, if the link had no `#k=`, the reveal key.
3. The page derives `K_f`, checks `kcv_f`, unwraps `CK`, decrypts, and displays, in this order:
   **"Issued to: <n>"**, prominently, followed by "Check that this name matches the name on the certificate and the
   person presenting it."; then course, dates, venue and certificate type. For a seal version 2 entry the first line
   reads "Name not recorded for this certificate".
4. The certificate type displayed is ALWAYS the public entry's `t` (the effective type), never the `t` inside the
   sealed details. A certificate whose public type was changed after sealing (for example a Completion downgraded to
   Attendance) reveals only as its current public type; nothing on the page indicates the change.
5. Errors: wrong factor ("check the family name exactly as printed"); entry unreadable; device cannot allocate
   the memory Argon2id needs ("the status shown above is still valid"). No oracle other than yes or no; a failed
   attempt shows no name.
6. Inputs are cleared on navigation. Nothing typed is stored, logged or transmitted.

The reveal key travels in the QR link's fragment. The page removes it from the address bar once read, but the first
navigation can remain in the browser's history and in the scanning app's history; this is equivalent to holding the
paper certificate.

## 7. Registry verification (before any status is shown)
### 7.1 Pinned keys
`keys.json` in this site lists accepted signing keys:
`{"production":true|false,"minSeq":<int, optional>,"keys":[{"kid","alg":"ML-DSA-65+Ed25519","mldsa65":"<b64url>","ed25519":"<b64url>","validFrom","validTo"|null,"fingerprint"}]}`.
`production` MUST be a boolean. When it is `true`, a verifier MUST ignore every key whose `kid` starts with `test-`
(case-insensitive) and MUST refuse a manifest whose `kid` starts with `test-` or that carries `"fixture": true`, even if
such a key was listed by mistake. When it is `false` the page MUST show that results are test data.
`minSeq`, when present, MUST be a positive safe integer; a manifest with a lower `seq` MUST be refused (7.5).
`keys.json` is part of this site and is changed only by a reviewed change to it, exactly like the verifier code, so
`minSeq` is as trustworthy as the keys themselves; a registry cannot change it. `keys.json` is always fetched from the
page's own origin.
Fingerprint = the first 130 bits of `SHA3-512("UNODC-CERT/KEY/v1" || 0x00 || mldsa65 public key (1952 B) || ed25519 public key (32 B))`,
written as 26 Crockford symbols (big-endian, 5 bits per symbol), displayed `XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX`; the short form
printed on certificates is the first 8 symbols (`XXXX-XXXX`). A verifier MUST recompute the fingerprint of a `keys.json`
entry and reject the entry if it differs from the stored one.
Keys are changed only by a reviewed change to this site; a registry cannot introduce its own key. `validTo` retires a
key for manifests signed after that time. A key that is suspected **compromised** is removed from `keys.json`
outright (not merely given a `validTo`): every manifest it ever signed is then refused, and the registry is re-signed
under the new key with the next snapshot.

### 7.2 Manifest signature
`manifest.sig.json` = `{"kid","alg":"ML-DSA-65+Ed25519","mldsa65":"<b64url 3309 B>","ed25519":"<b64url 64 B>"}`.
Both algorithms sign the same message
`M = ASCII("UNODC-CERT/MANIFEST/v1") || 0x00 || <exact bytes of manifest.json>`:
ML-DSA-65 (FIPS 204) in pure mode with an empty context string; Ed25519 (RFC 8032) pure mode, verified strictly
(canonical encodings only). `manifest.json` MUST be canonical (re-encoding it yields the same bytes) and schema 3 before
it is trusted, and MUST satisfy the date rules of 4.1. The `kid` in the signature MUST equal the manifest's `kid`, MUST
exist in `keys.json`, and the key MUST be valid at the signed build time: `validFrom <= issued <= validTo` (an
open-ended key has `validTo` null). The content date `asOf` is NOT used for key validity. Both signatures MUST verify;
there is no mode in which one suffices.

### 7.3 Freshness
`issued <= now + 1 day` (otherwise refuse with the "date later than this device" outcome); refuse when `now > expires`
("out of date"); show a warning when `now > asOf + 10 days`. Together with the 60-day cap of 4.1, a manifest signed
with a retired key (even with a back-dated `issued`) stops being accepted at most 60 days after that key's `validTo`.
`manifest.json`, `manifest.sig.json` and `keys.json` are fetched with `?v=<unix minutes>`.

### 7.4 Shard
`manifest.files` MUST list `meta.json` and all sixteen shards. Fetch `r/<nibble>.json?v=<seq>`; a missing shard (any HTTP
error) is an integrity failure; its SHA3-512 digest MUST equal `manifest.files["r/<nibble>.json"]`; the shard MUST be
canonical JSON with `"v":2`. Absence of the registry key => Not found.

### 7.5 Rollback and replay
An older snapshot is correctly signed and may still be unexpired; serving it again would hide a later revocation.
A verifier MUST therefore remember, per registry base URL and key-list mode, the highest `seq` it has accepted together
with `digest = base64url(SHA3-512(exact manifest.json bytes))` of that manifest, and MUST refuse:
- a manifest with `seq < minSeq` (`keys.json`, 7.1);
- a manifest with `seq` lower than the remembered one;
- a manifest with the same `seq` but a different digest.
Otherwise it accepts the manifest and remembers the higher of the two. The page stores this in the browser's local
storage (public registry data only: a sequence number and a digest; never an identifier, name or key), with an
in-memory copy so that the rule still holds for the session when storage is unavailable or blocked.
Residual risk: a device that has never seen a newer snapshot (first visit, cleared storage, private browsing) cannot
detect a replay by itself. `minSeq` closes that gap for every visitor once the site raises it (for example after a
revocation that must take effect immediately); between such raises, a first-time device is protected only by the
registry's `expires` (at most 60 days after `issued`).

Any failure => "Could not verify the registry's integrity - do not rely on this result" (or, for 7.5, the
"older than a version already seen" outcome). No status is shown.

## 8. Wording rules
Every state line carries the registry date, formatted with the browser locale and an ISO 8601 tooltip.
When the page is shown in a language other than English, the English status words are shown beside the translation.
Valid states carry the holder hint of section 1; a successful reveal leads with "Issued to" (section 6).

## 9. Page module interface
`assets/verifier.js` exports `verify(id)`, `reveal(id, input)` and the pinned `REGISTRY_BASES`; the page UI depends only
on that contract (documented at the top of the file). `reveal` returns `details = {name, course, dates, venue, type}`
where `name` is the sealed holder name (or null for a seal version 2 entry) and `type` is the public entry's type.
It implements sections 4-7 with the cryptography bundle `assets/verifier.<hash>.js`, whose file name carries the first 12
hexadecimal digits of its SHA-256 (exact name and digest in `assets/bundle.sha256`; `VENDOR.md`, `BUILD.md`).
When `keys.json` is a production list with no keys, `verify` returns the error `not-live` and the page says that the
verification service is not yet live; no status is shown. The reveal derivation runs in a
same-origin module worker (`assets/kdf-worker.js`) and falls back to the page thread; Argon2id falls back from
WebAssembly to pure JavaScript (same output, several times slower). The reveal key from `#k=` is kept in memory only and
removed from the address bar and history (`history.replaceState`) once read.

## 10. Hosting and page security
Static files only. Content security policy via `<meta>`: same-origin scripts, styles, fonts and images;
`connect-src 'self' https://raw.githubusercontent.com` (the pinned registry origin, section 4); `'wasm-unsafe-eval'` for
the memory-hard key derivation; `base-uri 'none'`, `form-action 'none'`, `object-src 'none'`. No analytics, no
third-party code, no external fonts, no inline scripts or handlers. The only stored data is the rollback state of 7.5
(public); no identifiers, names or keys are stored. Referrer suppression via `<meta name="referrer" content="no-referrer">`.
The worker is a same-origin file (allowed by `script-src 'self'`); no `blob:` or `data:` script source is needed.
A meta policy cannot set `frame-ancestors`, so the page checks at start-up whether it is inside a frame; if it is, it
removes the lookup form and shows only a link to open the page in its own tab.

## 11. Conformance vectors
`test/vectors.json` (version 1, generated deterministically by the issuer's test suite and copied here verbatim) contains:
identifier vectors (valid identifiers with registry key and shard, check symbols, parse cases incl. I/L/O mapping and
separators, every single-symbol error and every adjacent transposition of one identifier, reveal-key parsing); the
factor-normalisation table (Latin with diacritics incl. Vietnamese, Thai, Khmer, Lao, Myanmar, Mongolian Cyrillic,
Devanagari, Bengali, Sinhala, CJK, Hangul, Arabic, Greek, Turkish, zero-width and bidirectional marks, e-mail);
SHA3-512; Argon2id for every profile plus a reference vector; XChaCha20-Poly1305; key check values per tag; sealed entries
(seal version 3 with holder names in Latin/Vietnamese, Thai and Khmer script, plus one seal version 2 entry without a
name) under the floor and target profiles with every random input and intermediate value (salt, content key, nonces,
KDF password and salt, derived keys) and expected outcomes, including wrong factors, a wrong reveal key, a decoy e-mail
copy and a transplanted entry; canonical-JSON bytes; a four-entry mini registry (16 shards, `meta.json`, schema 3
manifest, hybrid signature) under the TEST key `test-k1` with lookups for all four states, one entry whose sealed type
differs from its public type (the displayed type is the public one), freshness cases, and a list of variants that MUST
fail (changed shard byte, changed manifest, each signature stripped, unknown key, relabelled `kid`, spliced foreign
signature, schema 2 manifest, expiry more than 60 days after `issued`, `asOf` after `issued`, back-dated manifests
signed with a retired key); and rollback cases (a correctly signed earlier snapshot, a fork with the same `seq`, `minSeq`).
`test-k1` and every secret in the file are TEST-ONLY; a test key MUST never appear in `keys.json`.

### 11.1 Canonical JSON
UTF-8; object keys sorted by UTF-16 code units; no insignificant whitespace; strings escaped as ECMAScript `JSON.stringify`
does; numbers are safe integers only (no fractions, exponents or `-0`); `true`, `false`, `null`, arrays and plain objects.
This is a strict subset of RFC 8785. Dates are strings `YYYY-MM-DDTHH:MM:SSZ`.

## 12. Versioning
This document and the data `schema` / `sv` fields are versioned independently of the site. A change to anything in
sections 2-7 requires a new `schema`/`sv` value so that existing certificates keep verifying or fail explicitly.

## 13. Changes in DRAFT 0.4
- Registry origin (4, 10): the registry is read cross-origin from one pinned base URL on `raw.githubusercontent.com`
  instead of a path on this site's origin; `connect-src` names that origin; responses are untrusted bytes.
- Manifest schema 3 (4.1, 7.2, 7.3): new signed field `issued`; key validity is checked at `issued` (not `asOf`);
  date rules `asOf <= issued < expires <= issued + 60 days`; the "future" outcome uses `issued`; every snapshot,
  including an expiry renewal, has a new `seq`.
- Rollback rule (7.5) and optional `keys.json` `minSeq` (7.1); new "older than a version already seen" outcome.
- Compromised keys are removed from `keys.json` (7.1).
- Seal version 3 (5.3, 6): the sealed details carry the holder name `n` and family name `f`; the reveal leads with
  "Issued to"; plaintext padding; seal version 2 entries still open and show "name not recorded".
- The displayed type is always the public entry's type (6.4).
- Valid states carry a holder hint (1, 8); the page refuses to run inside a frame (10); entries below the original
  key-derivation floor are not opened (5.2).
- "Verification service not yet live" outcome for a production `keys.json` with no keys (1, 9); the bundle file name
  carries its content hash (9).
