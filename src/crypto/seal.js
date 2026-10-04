import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { systemRandom, ascii, b64url, b64urlDecode, concat, equalBytes, utf8, utf8Decode, wipe } from "./bytes";
import { canonicalJson } from "./canonical";
import { idDigest, isValidId, registryKeyOf, REVEAL_LENGTH } from "./ids";
import { argon2id, assertSealable, DEFAULT_SEAL_PROFILE, kdfHeaderProblem, meetsFloor, SEAL_PROFILES, sealProfile } from "./kdfCore";
import { normaliseFactor } from "./normalise";
import { taggedSha3 } from "./sha3";
import { cleanSymbols } from "./crockford";
const SEAL_VERSION = 3;
const SEAL_VERSIONS_READABLE = [2, 3];
const SEAL_VERSION_WITH_NAME = 3;
const KCV_TAG_SURNAME = "UNODC-CERT/KCV/v1/surname";
const KCV_TAG_EMAIL = "UNODC-CERT/KCV/v1/email";
const WRAP_TAG = "UNODC-CERT/WRAP/v1";
const SEAL_TAG = "UNODC-CERT/SEAL/v1";
const SEAL_PAD_BUCKET = 256;
const US = 31;
const MESSAGES = {
  "no-match": "could not unlock - check the family name or e-mail and the reveal code",
  corrupt: "this registry entry is corrupt",
  malformed: "this registry entry is malformed"
};
function sealError(code, detail) {
  const e = new Error(code === "no-match" || !detail ? MESSAGES[code] : MESSAGES[code] + ": " + detail);
  e.code = code;
  return e;
}
function isSealError(e) {
  return !!e && typeof e === "object" && typeof e.code === "string" && !!MESSAGES[e.code];
}
function kcvTag(kind) {
  return kind === "e" ? KCV_TAG_EMAIL : KCV_TAG_SURNAME;
}
function kcvOf(kind, key) {
  return taggedSha3(kcvTag(kind), key);
}
function checkProfileId(sp) {
  if (typeof sp !== "string" || !/^[a-z0-9-]{1,40}$/.test(sp)) throw sealError("malformed", "bad profile id");
}
function wrapAad(registryKey, sv, sp, kind) {
  return concat([
    ascii(WRAP_TAG),
    new Uint8Array([US]),
    ascii(registryKey),
    new Uint8Array([US]),
    ascii(String(sv)),
    new Uint8Array([US]),
    ascii(sp),
    new Uint8Array([US]),
    ascii(kind)
  ]);
}
function sealAad(registryKey, sv, sp) {
  return concat([
    ascii(SEAL_TAG),
    new Uint8Array([US]),
    ascii(registryKey),
    new Uint8Array([US]),
    ascii(String(sv)),
    new Uint8Array([US]),
    ascii(sp)
  ]);
}
function canonicalReveal(revealKey) {
  const c = cleanSymbols(revealKey);
  if (c.invalid.length || c.canonical.length !== REVEAL_LENGTH) throw sealError("no-match");
  return c.canonical;
}
function kdfPassword(kind, factor, revealKey) {
  return concat([utf8(normaliseFactor(kind, factor)), new Uint8Array([US]), ascii(canonicalReveal(revealKey))]);
}
function kdfSalt(salt16, canonicalId) {
  if (salt16.length !== 16) throw new Error("salt must be 16 bytes");
  return concat([salt16, idDigest(canonicalId).subarray(0, 32)]);
}
function deriveFactorKey(kind, factor, revealKey, canonicalId, salt16, kdf, engine) {
  return argon2id(kdfPassword(kind, factor, revealKey), kdfSalt(salt16, canonicalId), kdf, engine);
}
function checkPayload(p) {
  if (!p || typeof p.c !== "string" || typeof p.d !== "string" || typeof p.v !== "string" || typeof p.t !== "string") {
    throw new Error("payload must be {c, d, v, t} strings");
  }
}
const nonEmpty = (s) => typeof s === "string" && s.trim() !== "";
function sealablePayload(p, surname) {
  checkPayload(p);
  if (!nonEmpty(p.n)) throw new Error("payload.n (holder name as printed) is required from seal version 3");
  if (p.f !== void 0 && !nonEmpty(p.f)) throw new Error("payload.f must be a non-empty string when given");
  const f = p.f !== void 0 ? String(p.f).trim() : String(surname).trim();
  if (normaliseFactor("s", f) !== normaliseFactor("s", surname)) throw new Error("payload.f does not match the unlock family name");
  return { c: p.c, d: p.d, f, n: String(p.n).trim(), t: p.t, v: p.v };
}
function checkOpenedPayload(p, sv) {
  if (!p || typeof p !== "object" || typeof p.c !== "string" || typeof p.d !== "string" || typeof p.v !== "string" || p.t !== void 0 && typeof p.t !== "string") {
    throw new Error("payload must be {c, d, v[, t]} strings");
  }
  if (sv >= SEAL_VERSION_WITH_NAME && (!nonEmpty(p.n) || !nonEmpty(p.f))) throw new Error("payload lacks the holder name");
}
function paddedPlaintext(p) {
  const base = { c: p.c, d: p.d, t: p.t, v: p.v };
  if (p.f !== void 0) base.f = p.f;
  if (p.n !== void 0) base.n = p.n;
  const bare = utf8(canonicalJson(base)).length;
  const target = Math.max(SEAL_PAD_BUCKET, Math.ceil((bare + 7) / SEAL_PAD_BUCKET) * SEAL_PAD_BUCKET);
  const body = utf8(canonicalJson({ ...base, z: " ".repeat(target - bare - 7) }));
  if (body.length !== target) throw new Error("padding arithmetic failed");
  return body;
}
async function seal(input) {
  if (!isValidId(input.id)) throw new Error("not a canonical certificate identifier");
  const reveal = canonicalReveal(input.revealKey);
  if (!normaliseFactor("s", input.surname)) throw new Error("family name normalises to an empty string");
  const sealed = sealablePayload(input.payload, input.surname);
  const profile = sealProfile(input.profile || DEFAULT_SEAL_PROFILE);
  assertSealable(profile.kdf);
  const sp = profile.id;
  const kdf = { alg: "argon2id", v: profile.kdf.v, m: profile.kdf.m, t: profile.kdf.t, p: profile.kdf.p, len: profile.kdf.len };
  const rnd = input.random || systemRandom;
  if (!normaliseFactor("s", input.surname)) throw new Error("family name normalises to an empty string");
  const hasEmail = !!input.email && !!normaliseFactor("e", input.email);
  const registryKey = registryKeyOf(input.id);
  const salt = rnd(16);
  const ck = rnd(32);
  const nS = rnd(24);
  const nE = rnd(24);
  const nC = rnd(24);
  const kS = await deriveFactorKey("s", input.surname, reveal, input.id, salt, kdf, input.engine);
  const kE = hasEmail ? await deriveFactorKey("e", input.email, reveal, input.id, salt, kdf, input.engine) : rnd(32);
  const wS = xchacha20poly1305(kS, nS, wrapAad(registryKey, SEAL_VERSION, sp, "s")).encrypt(ck);
  const wE = xchacha20poly1305(kE, nE, wrapAad(registryKey, SEAL_VERSION, sp, "e")).encrypt(ck);
  const body = paddedPlaintext(sealed);
  const enc = xchacha20poly1305(ck, nC, sealAad(registryKey, SEAL_VERSION, sp)).encrypt(body);
  const rec = {
    sv: SEAL_VERSION,
    sp,
    kdf,
    salt: b64url(salt),
    kcv_s: b64url(kcvOf("s", kS)),
    n_s: b64url(nS),
    w_s: b64url(wS),
    kcv_e: b64url(kcvOf("e", kE)),
    n_e: b64url(nE),
    w_e: b64url(wE),
    n_c: b64url(nC),
    enc: b64url(enc)
  };
  wipe(kS);
  wipe(kE);
  wipe(ck);
  return rec;
}
function field(rec, name, len, minLen) {
  const v = rec[name];
  if (typeof v !== "string") throw sealError("malformed", "missing " + name);
  let b;
  try {
    b = b64urlDecode(v);
  } catch {
    throw sealError("malformed", "bad encoding in " + name);
  }
  if (len !== void 0 && b.length !== len) throw sealError("malformed", "bad length of " + name);
  if (minLen !== void 0 && b.length < minLen) throw sealError("malformed", "bad length of " + name);
  return b;
}
function decodeRecord(rec) {
  if (!rec || typeof rec !== "object") throw sealError("malformed", "not an object");
  if (SEAL_VERSIONS_READABLE.indexOf(rec.sv) < 0) throw sealError("malformed", "unsupported seal version");
  checkProfileId(rec.sp);
  const problem = kdfHeaderProblem(rec.kdf);
  if (problem) throw sealError("malformed", problem);
  return {
    salt: field(rec, "salt", 16),
    kcv: { s: field(rec, "kcv_s", 64), e: field(rec, "kcv_e", 64) },
    n: { s: field(rec, "n_s", 24), e: field(rec, "n_e", 24) },
    w: { s: field(rec, "w_s", 48), e: field(rec, "w_e", 48) },
    nC: field(rec, "n_c", 24),
    enc: field(rec, "enc", void 0, 16)
  };
}
function openWithFactorKey(rec, registryKey, kind, key) {
  const d = decodeRecord(rec);
  if (!equalBytes(kcvOf(kind, key), kind === "e" ? d.kcv.e : d.kcv.s)) throw sealError("no-match");
  let ck;
  let body;
  try {
    ck = xchacha20poly1305(key, kind === "e" ? d.n.e : d.n.s, wrapAad(registryKey, rec.sv, rec.sp, kind)).decrypt(kind === "e" ? d.w.e : d.w.s);
  } catch {
    throw sealError("corrupt", "wrap");
  }
  try {
    body = xchacha20poly1305(ck, d.nC, sealAad(registryKey, rec.sv, rec.sp)).decrypt(d.enc);
  } catch {
    throw sealError("corrupt", "seal");
  } finally {
    wipe(ck);
  }
  let p;
  try {
    p = JSON.parse(utf8Decode(body));
    checkOpenedPayload(p, rec.sv);
  } catch {
    throw sealError("corrupt", "payload");
  }
  const out = { c: p.c, d: p.d, v: p.v, t: typeof p.t === "string" ? p.t : "" };
  if (rec.sv >= SEAL_VERSION_WITH_NAME) {
    out.n = p.n;
    out.f = p.f;
  }
  return out;
}
async function unseal(rec, input) {
  const d = decodeRecord(rec);
  if (!isValidId(input.id)) throw sealError("no-match");
  if (!normaliseFactor(input.kind, input.factor)) throw sealError("no-match");
  const registryKey = registryKeyOf(input.id);
  const key = await deriveFactorKey(input.kind, input.factor, input.revealKey, input.id, d.salt, rec.kdf, input.engine);
  try {
    const payload = openWithFactorKey(rec, registryKey, input.kind, key);
    const known = Object.prototype.hasOwnProperty.call(SEAL_PROFILES, rec.sp) ? SEAL_PROFILES[rec.sp].kdf : void 0;
    return {
      payload,
      nameRecorded: rec.sv >= SEAL_VERSION_WITH_NAME,
      belowFloor: !meetsFloor(rec.kdf),
      profileMismatch: !!known && (known.m !== rec.kdf.m || known.t !== rec.kdf.t || known.p !== rec.kdf.p)
    };
  } finally {
    wipe(key);
  }
}
async function reseal(rec, input) {
  sealProfile(input.profile);
  const opened = await unseal(rec, { id: input.id, kind: "s", factor: input.surname, revealKey: input.revealKey, engine: input.engine });
  const payload = { ...opened.payload };
  if (input.printName !== void 0) payload.n = input.printName;
  if (!opened.nameRecorded) delete payload.f;
  const record = await seal({
    id: input.id,
    revealKey: input.revealKey,
    surname: input.surname,
    email: input.email,
    payload,
    profile: input.profile,
    random: input.random,
    engine: input.engine
  });
  const s = sealablePayload(payload, input.surname);
  return { record, payload: { c: s.c, d: s.d, v: s.v, t: s.t, n: s.n, f: s.f } };
}
export {
  KCV_TAG_EMAIL,
  KCV_TAG_SURNAME,
  SEAL_PAD_BUCKET,
  SEAL_TAG,
  SEAL_VERSION,
  SEAL_VERSIONS_READABLE,
  SEAL_VERSION_WITH_NAME,
  WRAP_TAG,
  decodeRecord,
  deriveFactorKey,
  isSealError,
  kcvOf,
  kdfPassword,
  kdfSalt,
  openWithFactorKey,
  paddedPlaintext,
  reseal,
  seal,
  sealAad,
  sealError,
  unseal,
  wrapAad
};
