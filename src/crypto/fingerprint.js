import { bytesToSymbols, group } from "./crockford";
import { concat } from "./bytes";
import { taggedSha3 } from "./sha3";
const FINGERPRINT_TAG = "UNODC-CERT/KEY/v1";
const FINGERPRINT_SYMBOLS = 26;
const MLDSA65_PUBLIC_KEY_BYTES = 1952;
const ED25519_PUBLIC_KEY_BYTES = 32;
function fingerprint(pkMldsa65, pkEd25519) {
  if (pkMldsa65.length !== MLDSA65_PUBLIC_KEY_BYTES) throw new Error("ML-DSA-65 public key must be 1952 bytes");
  if (pkEd25519.length !== ED25519_PUBLIC_KEY_BYTES) throw new Error("Ed25519 public key must be 32 bytes");
  return bytesToSymbols(taggedSha3(FINGERPRINT_TAG, concat([pkMldsa65, pkEd25519])), FINGERPRINT_SYMBOLS);
}
function formatFingerprint(fp) {
  return group(fp, [5, 5, 5, 5, 6]);
}
function shortFingerprint(fp) {
  return group(fp.substring(0, 8), [4, 4]);
}
export {
  ED25519_PUBLIC_KEY_BYTES,
  FINGERPRINT_SYMBOLS,
  FINGERPRINT_TAG,
  MLDSA65_PUBLIC_KEY_BYTES,
  fingerprint,
  formatFingerprint,
  shortFingerprint
};
