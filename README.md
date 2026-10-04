# unodc-cyber.github.io - certificate verifier

Public, static verification page for training certificates issued by the Cybercrime Programme of the United Nations
Office on Drugs and Crime (UNODC), served at https://unodc-cyber.github.io/ .

**Status: not yet live.** The verification page and its full checking logic are published here, but no production
signing key has been added to `keys.json` yet. Until it is, the page answers every check with "Verification service not
yet live" and shows no certificate status.

## How to verify a certificate

1. Open the link or scan the QR code printed on the certificate (`https://unodc-cyber.github.io/v/<identifier>`), or open
   https://unodc-cyber.github.io/ and type the 27-symbol identifier printed on the certificate. Spaces and hyphens are
   optional; a mistyped symbol is reported before anything is looked up.
2. The page checks the signed public registry and shows exactly one result, always with the date the registry was last
   updated: **Valid** (with the certificate type), **Revoked - not valid**, or **Not found**. A certificate issued
   recently may not be published yet.
3. A valid result applies to the identifier, not to the person presenting it. The certificate holder can unlock the
   course details and the name the certificate was issued to with their family name or e-mail address plus the reveal
   code printed under the QR code. This happens entirely in the browser; nothing typed is sent anywhere.

If the registry's signature, dates or file digests do not check out, the page says so and shows no status.

## Public interface

- `SPEC.md` - the full public specification: identifier format and check symbol, link format, registry files and record
  schema, cryptographic primitives and parameters, signature verification, reveal flow, the states shown to the public,
  and the conformance vectors. It is written so that anyone can check a certificate independently or build a compatible
  verifier of their own.
- `test/vectors.json` - conformance vectors (`node test/run-vectors.mjs`, or `test/harness.html` in a browser). Every key
  and secret in them is TEST-ONLY.
- `keys.json` - the pinned registry signing keys (empty until launch). Keys change only through a reviewed change to
  this repository.
- `VENDOR.md` and `BUILD.md` - the pinned third-party cryptography and how to rebuild the bundle byte for byte from
  `src/`.

The registry is published separately, as plain data files read from a fixed address (SPEC.md section 4). It contains no
personal data: no names, e-mail addresses or identifiers in clear, only hash-derived keys, status codes and sealed
(encrypted) course details.

## Privacy

No personal data is published in this repository or in the registry. The page uses no analytics, no cookies and no
third-party code; the only thing it stores in the browser is the number and digest of the newest registry version it
has seen (SPEC.md section 7.5).

## Contributing and security

Issues are welcome for problems with the page itself. Never include a person's name, e-mail address, certificate
identifier, reveal code or a photo of a certificate in a public issue. Security problems: use **Security -> Report a
vulnerability** (private). See `SECURITY.md`.

## Licence

The verifier code in this repository is licensed under the **Apache License 2.0** (see `LICENSE` and `NOTICE`). The
licence does **not** cover any name, emblem, logo or other branding - see `BRANDING.md` - and it does **not** cover
certificate data - see `DATA-NOTICE.md`. Third-party code inside the bundle keeps its own MIT licences
(`assets/verifier.bundle.LICENSES.txt`).

---

Verification service operated by UNODC Cybercrime Programme staff. Not hosted on a unodc.org domain.
