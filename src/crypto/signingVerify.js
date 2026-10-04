import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { ascii, b64urlDecode, concat } from "./bytes";
import { fingerprint } from "./fingerprint";
import { manifestDateProblem, parseManifest } from "./manifest";
const SIGNATURE_ALG = "ML-DSA-65+Ed25519";
const MANIFEST_SIGN_TAG = "UNODC-CERT/MANIFEST/v1";
const MLDSA65_SIGNATURE_BYTES = 3309;
function keyFingerprint(k) {
  return fingerprint(k.publicMldsa65, k.publicEd25519);
}
function signedMessage(manifestBytes) {
  return concat([ascii(MANIFEST_SIGN_TAG), new Uint8Array([0]), manifestBytes]);
}
function fail(reason) {
  return { ok: false, reason };
}
function verifyManifest(manifestBytes, sig, pinned) {
  let m;
  try {
    m = parseManifest(manifestBytes);
  } catch {
    return fail("manifest-unparseable");
  }
  if (manifestDateProblem(m)) return fail("manifest-dates");
  if (!sig || typeof sig !== "object" || typeof sig.mldsa65 !== "string" || typeof sig.ed25519 !== "string" || typeof sig.kid !== "string") {
    return fail("bad-signature-format");
  }
  if (sig.alg !== SIGNATURE_ALG) return fail("alg");
  if (sig.kid !== m.kid) return fail("kid-mismatch");
  let key;
  for (let i = 0; i < pinned.length; i++) if (pinned[i] && pinned[i].kid === sig.kid) key = pinned[i];
  if (!key) return fail("unknown-kid");
  if (key.alg !== SIGNATURE_ALG) return fail("alg");
  let pkPq;
  let pkEd;
  let sPq;
  let sEd;
  try {
    pkPq = b64urlDecode(key.mldsa65);
    pkEd = b64urlDecode(key.ed25519);
    if (fingerprint(pkPq, pkEd) !== key.fingerprint) return fail("fingerprint-mismatch");
  } catch {
    return fail("key-record-invalid");
  }
  const issued = Date.parse(m.issued);
  const from = Date.parse(key.validFrom);
  if (isNaN(from) || issued < from) return fail("key-not-valid-at-issued");
  if (key.validTo !== null && key.validTo !== void 0) {
    const to = Date.parse(key.validTo);
    if (isNaN(to) || issued > to) return fail("key-not-valid-at-issued");
  }
  try {
    sPq = b64urlDecode(sig.mldsa65);
    sEd = b64urlDecode(sig.ed25519);
  } catch {
    return fail("bad-signature-format");
  }
  if (sPq.length !== MLDSA65_SIGNATURE_BYTES || sEd.length !== 64) return fail("bad-signature-format");
  const msg = signedMessage(manifestBytes);
  let okPq = false;
  let okEd = false;
  try {
    okPq = ml_dsa65.verify(sPq, msg, pkPq);
  } catch {
    okPq = false;
  }
  if (!okPq) return fail("mldsa65-invalid");
  try {
    okEd = ed25519.verify(sEd, msg, pkEd, { zip215: false });
  } catch {
    okEd = false;
  }
  if (!okEd) return fail("ed25519-invalid");
  return { ok: true, manifest: m, key };
}
export {
  MANIFEST_SIGN_TAG,
  MLDSA65_SIGNATURE_BYTES,
  SIGNATURE_ALG,
  keyFingerprint,
  signedMessage,
  verifyManifest
};
