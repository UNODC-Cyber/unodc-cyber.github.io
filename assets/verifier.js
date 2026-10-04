// verifier.js - registry verification and holder-only reveal (SPEC.md sections 2, 4, 5, 6, 7).
// The UI (app.js) depends ONLY on the contract below. All cryptography comes from the verifier bundle (assets/verifier.<hash>.js)
// (the issuer's crypto modules + pinned libraries, built reproducibly: BUILD.md, VENDOR.md).
//
// ---------------------------------------------------------------------------------------
// CONTRACT (VERIFIER_API = 3; API 1/2 callers keep working: same functions, more fields and error codes)
//
//   verify(id, opts?)  -> Promise<VerifyResult>
//     id    : canonical 27-symbol identifier (already normalised; check symbol already valid).
//     opts  : { signal?: AbortSignal, keysUrl?: string (default "keys.json", same origin as the page),
//               registryBase?: string (default REGISTRY_BASES[0]; must be in REGISTRY_BASES - see "Registry origin"),
//               now?: Date }
//     VerifyResult =
//       { ok: true,
//         state: "valid-completion" | "valid-attendance" | "valid-appreciation" | "valid-contribution"
//              | "revoked" | "not-found",
//         asOf: string, seq: number, stale: boolean, canReveal: boolean,
//         integrity: "verified",      // hybrid signature, pinned key, dates, rollback rule and shard digest all checked
//         production: boolean }       // false = the pinned key list is a TEST list (UI shows a banner)
//     | { ok: false,
//         error: "not-live"    // keys.json is a production list with no signing key yet: the service is not live
//              | "integrity"   // any failure of SPEC.md section 7: no status may be shown
//              | "rollback"   // registry older than one this device has already accepted, or than keys.json minSeq
//              | "expired"     // registry is out of date (now > manifest.expires)
//              | "future"      // registry signing time is more than one day ahead of this device's clock
//              | "network"     // registry unreachable
//              | "bad-id"      // defensive: id malformed
//              | "unsupported",// a required browser API is missing
//         detail?: string }    // developer-facing only, never shown to users, never contains inputs
//
//   reveal(id, input, opts?) -> Promise<RevealResult>
//     input : { factor: string, factorKind: "surname" | "email", revealCode: string }
//             factor is the RAW typed string (normalised inside, SPEC.md 5.1); revealCode = 10 symbols.
//     opts  : { signal?: AbortSignal, onProgress?: (phase) => void, worker?: boolean (default true) }
//     RevealResult =
//       { ok: true, details: { name: string | null, course, dates, venue, type }, ms: number, engine: "wasm" | "js" }
//         name : holder name exactly as printed (sealed); null = an older entry that does not record it
//         type : ALWAYS the type code of the PUBLIC registry entry (never the sealed copy: a downgrade is not revealed)
//     | { ok: false, error: "wrong-factor"  // ONE generic "could not unlock" for wrong name/e-mail/reveal code
//                         | "corrupt"       // key check matched but authenticated decryption failed
//                         | "no-wasm"       // the device could not run the memory-hard derivation
//                         | "not-found" | "not-live" | "integrity" | "rollback" | "expired" | "future" | "network" | "bad-id" }
//     Never returns, stores, logs or transmits the factor or the reveal code.
//
//   Registry origin (SPEC.md 4): the registry is fetched cross-origin, read-only, as bytes, from exactly one of
//   REGISTRY_BASES (pinned here, reviewed like the rest of this file). Response Content-Type is ignored; bytes are
//   only ever hashed and parsed as JSON, never rendered or executed. keys.json comes from this page's own origin.
//   Development override: ONLY when this page itself is served over http from a loopback host (or there is no page,
//   e.g. a Node test runner) may a loopback http registry base be used, from opts.registryBase or a
//   <meta name="dev-registry-base"> injected by the local harness. A page on any real host can never enable it, and
//   the production content security policy would block the connection anyway.
//
//   Rollback state (SPEC.md 7.5): the highest accepted manifest seq and its digest are kept in localStorage (public
//   data only; per registry base and key-list mode), with an in-memory copy for when storage is unavailable.
//
//   Both functions never throw (an AbortError is re-thrown so a superseded request can be dropped by the caller).
// ---------------------------------------------------------------------------------------

import * as C from './verifier.804a6d17e2b5.js';

export const VERIFIER_API = 3;
export const REGISTRY_BASES = Object.freeze(['https://raw.githubusercontent.com/UNODC-Cyber/registry/main/']);
const TYPES = { CMP: 'valid-completion', ATT: 'valid-attendance', APP: 'valid-appreciation', TRN: 'valid-contribution' };
const LIMITS = { keys: 256 * 1024, manifest: 64 * 1024, sig: 16 * 1024, shard: 16 * 1024 * 1024 };
const TEST_KID = /^test-/i;
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);
// The original key-derivation floor (SPEC.md 5.2). Fixed here on purpose: a later, raised floor in the shared
// modules must not stop older entries from opening, but nothing below THIS floor is ever opened.
const ABSOLUTE_FLOOR = Object.freeze({ m: 19456, t: 2, p: 1 });
const HWM_PREFIX = 'unodc-cert/seen-manifest/v1 ';

let lastVerified = null; // { id, seq, entry } - public registry data only, kept in memory for reveal()
const memorySeen = new Map(); // fallback when localStorage is unavailable

class Refusal extends Error { constructor(code, detail) { super(detail || code); this.code = code; } }

function pageBase() {
  const b = (typeof document !== 'undefined' && document.baseURI) || (typeof location !== 'undefined' && location.href);
  if (!b) throw new Refusal('unsupported', 'no page address');
  return b;
}
function devContext() {
  if (typeof location === 'undefined') return true; // no page at all (Node test runner)
  return location.protocol === 'http:' && LOOPBACK.has(location.hostname);
}
function devMetaBase() {
  if (!devContext() || typeof document === 'undefined' || typeof document.querySelector !== 'function') return undefined;
  const m = document.querySelector('meta[name="dev-registry-base"]');
  return (m && m.getAttribute('content')) || undefined;
}
function sameOriginAsPage(url) {
  if (typeof location === 'undefined' || !/^https?:$/.test(location.protocol)) return true;
  return url.origin === location.origin;
}

/** The registry base for this check: an allowlisted origin, or (development only) a loopback one. */
export function resolveRegistryBase(requested) {
  const raw = requested !== undefined && requested !== null ? requested : devMetaBase() || REGISTRY_BASES[0];
  let u;
  try { u = new URL(String(raw)); } catch { throw new Refusal('integrity', 'registry base unparseable'); }
  if (u.search || u.hash || u.username || u.password || !u.pathname.endsWith('/')) throw new Refusal('integrity', 'registry base shape');
  if (REGISTRY_BASES.includes(u.href)) return u.href;
  if (devContext() && u.protocol === 'http:' && LOOPBACK.has(u.hostname)) return u.href;
  throw new Refusal('integrity', 'registry base not allowlisted');
}

async function fetchBytes(url, signal, limit, httpFailure, what) {
  let res;
  try {
    res = await fetch(url, { signal, mode: 'cors', credentials: 'omit', cache: 'no-cache', referrerPolicy: 'no-referrer', redirect: 'error' });
  } catch (e) {
    if (e && e.name === 'AbortError') throw e;
    throw new Refusal('network', 'fetch failed ' + what);
  }
  if (!res.ok) throw new Refusal(httpFailure, `HTTP ${res.status} ${what}`);
  // Content-Type is deliberately ignored (untrusted): the bytes are hashed and parsed as JSON, nothing else.
  const buf = new Uint8Array(await res.arrayBuffer());
  if (buf.length > limit) throw new Refusal('integrity', 'oversized ' + what);
  return buf;
}

function getKeys(path, query, signal) {
  const url = new URL(path, pageBase());
  if (query) url.search = query;
  if (!sameOriginAsPage(url)) throw new Refusal('integrity', 'keys.json must be same-origin');
  return fetchBytes(url, signal, LIMITS.keys, 'integrity', 'keys.json');
}

function getRegistry(base, path, query, signal, limit, httpFailure) {
  const url = new URL(path, base);
  if (!url.href.startsWith(base) || url.origin !== new URL(base).origin) throw new Refusal('integrity', 'registry path escapes its base');
  if (query) url.search = query;
  return fetchBytes(url, signal, limit, httpFailure, path);
}

function parseJson(bytes, what) {
  try { return JSON.parse(C.utf8Decode(bytes)); } catch { throw new Refusal('integrity', 'unparseable ' + what); }
}

function pinnedKeys(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc) || typeof doc.production !== 'boolean' || !Array.isArray(doc.keys)) {
    throw new Refusal('integrity', 'keys.json shape');
  }
  if (doc.minSeq !== undefined && !(Number.isSafeInteger(doc.minSeq) && doc.minSeq >= 1)) throw new Refusal('integrity', 'keys.json minSeq');
  // A production list never accepts a test key, even if one was added to it by mistake (SPEC.md 7.1).
  const keys = doc.keys.filter((k) => k && typeof k === 'object' && typeof k.kid === 'string' && !(doc.production && TEST_KID.test(k.kid)));
  return { production: doc.production, keys, minSeq: doc.minSeq, listed: doc.keys.length };
}

// ---- rollback state (public data only; SPEC.md 7.5) ------------------------------------------
function seenKey(base, production) { return HWM_PREFIX + base + (production ? '' : ' #test'); }
function readSeen(key) {
  let best = memorySeen.get(key);
  try {
    const raw = typeof localStorage !== 'undefined' ? localStorage.getItem(key) : null;
    if (raw) {
      const v = JSON.parse(raw);
      if (v && Number.isSafeInteger(v.seq) && typeof v.digest === 'string' && (!best || v.seq > best.seq)) best = { seq: v.seq, digest: v.digest };
    }
  } catch { /* storage unavailable or unreadable: the in-memory copy still protects this session */ }
  return best;
}
function writeSeen(key, seen) {
  memorySeen.set(key, seen);
  try { if (typeof localStorage !== 'undefined') localStorage.setItem(key, JSON.stringify(seen)); } catch { /* ignore */ }
}

async function verifyChain(id, opts) {
  if (typeof id !== 'string' || !C.isValidId(id)) throw new Refusal('bad-id');
  if (typeof fetch !== 'function' || typeof TextDecoder === 'undefined') throw new Refusal('unsupported');
  const base = resolveRegistryBase(opts.registryBase);
  const now = opts.now || new Date();
  const minute = `v=${Math.floor(now.getTime() / 60000)}`;
  const keysP = getKeys(opts.keysUrl || 'keys.json', minute, opts.signal);
  const regP = Promise.all([
    getRegistry(base, 'manifest.json', minute, opts.signal, LIMITS.manifest, 'network'),
    getRegistry(base, 'manifest.sig.json', minute, opts.signal, LIMITS.sig, 'network'),
  ]);
  regP.catch(() => {}); // settled below; never an unhandled rejection if keys.json decides first
  const pinned = pinnedKeys(parseJson(await keysP, 'keys.json'));
  // A production key list with no key means the service is not live yet (no registry can be trusted). Say so
  // plainly, whatever the registry host answers (missing repository, empty snapshot, or anything else).
  // (A production list that lists only test keys is a misconfiguration, not "not live": it stays an integrity failure.)
  if (pinned.production && pinned.listed === 0) throw new Refusal('not-live', 'no production signing key pinned');
  const [mBytes, sigBytes] = await regP;
  const sig = parseJson(sigBytes, 'manifest.sig.json');
  // Hybrid signature over the exact manifest bytes: canonical form, date rules, kid binding, pinned key, fingerprint,
  // key validity at the signed build time "issued", then ML-DSA-65 AND Ed25519 (SPEC.md 7.1-7.2).
  const vr = C.verifyManifest(mBytes, sig, pinned.keys);
  if (!vr.ok) throw new Refusal('integrity', 'manifest ' + vr.reason);
  const m = vr.manifest;
  if (pinned.production && (TEST_KID.test(m.kid) || m.fixture === true)) throw new Refusal('integrity', 'test snapshot under production keys');
  const fresh = C.freshness(m, now);
  if (fresh === 'future') throw new Refusal('future', 'issued ahead of the device clock');
  if (fresh === 'expired') throw new Refusal('expired', 'manifest expired');
  // Rollback / replay (SPEC.md 7.5): never accept an older snapshot than one already accepted here, or than minSeq.
  const key = seenKey(base, pinned.production);
  const digest = C.manifestDigest(mBytes);
  const seen = readSeen(key);
  const verdict = C.rollbackVerdict(m.seq, digest, seen, pinned.minSeq);
  if (verdict !== 'ok') throw new Refusal('rollback', verdict);
  if (!seen || m.seq > seen.seq) writeSeen(key, { seq: m.seq, digest });
  for (const s of C.SHARD_NAMES) if (typeof m.files['r/' + s + '.json'] !== 'string') throw new Refusal('integrity', 'manifest lacks shard ' + s);
  if (typeof m.files['meta.json'] !== 'string') throw new Refusal('integrity', 'manifest lacks meta.json');

  const shardName = C.shardOf(id);
  const path = `r/${shardName}.json`;
  const shardBytes = await getRegistry(base, path, `v=${m.seq}`, opts.signal, LIMITS.shard, 'integrity');
  if (!C.fileMatches(m, path, shardBytes)) throw new Refusal('integrity', 'shard digest mismatch ' + path);
  let shard;
  try { shard = C.parseCanonical(shardBytes); } catch { throw new Refusal('integrity', 'shard not canonical'); }
  if (!shard || shard.v !== 2 || !shard.c || typeof shard.c !== 'object' || Array.isArray(shard.c)) throw new Refusal('integrity', 'shard shape');
  const rkey = C.registryKeyOf(id);
  const entry = Object.prototype.hasOwnProperty.call(shard.c, rkey) ? shard.c[rkey] : null;
  const common = { ok: true, asOf: m.asOf, seq: m.seq, stale: fresh === 'stale', integrity: 'verified', production: pinned.production };
  if (!entry) return { result: { ...common, state: 'not-found', canReveal: false }, entry: null, seq: m.seq };
  if (entry.s === 'R') return { result: { ...common, state: 'revoked', canReveal: false }, entry, seq: m.seq };
  if (entry.s === 'V' && Object.prototype.hasOwnProperty.call(TYPES, entry.t)) {
    return { result: { ...common, state: TYPES[entry.t], canReveal: true }, entry, seq: m.seq };
  }
  throw new Refusal('integrity', 'unknown status or type in entry');
}

export async function verify(id, opts = {}) {
  try {
    const r = await verifyChain(id, opts);
    lastVerified = { id, seq: r.seq, entry: r.entry };
    return r.result;
  } catch (e) {
    if (e && e.name === 'AbortError') throw e;
    lastVerified = null;
    if (e instanceof Refusal) return { ok: false, error: e.code, detail: e.message };
    return { ok: false, error: 'integrity', detail: 'unexpected ' + (e && e.name) };
  }
}

// ---- reveal --------------------------------------------------------------------------------

function unsealHere(entry, msg) {
  const t0 = performance.now();
  return C.unseal(entry, msg).then(
    (r) => ({ ok: true, payload: r.payload, ms: performance.now() - t0, engine: C.wasmFellBack() ? 'js' : 'wasm' }),
    (e) => ({ ok: false, code: C.isSealError(e) ? e.code : 'device', ms: performance.now() - t0, engine: C.wasmFellBack() ? 'js' : 'wasm' }),
  );
}

// The memory-hard derivation takes 0.1-4 s; run it in a same-origin module worker so the page stays
// responsive. Falls back to the page thread if workers are unavailable.
function unsealInWorker(entry, msg, signal) {
  return new Promise((resolve, reject) => {
    let w;
    try { w = new Worker(new URL('./kdf-worker.js', import.meta.url), { type: 'module', name: 'kdf' }); } catch { resolve(null); return; }
    let done = false;
    const finish = (v) => { if (done) return; done = true; w.terminate(); if (signal) signal.removeEventListener('abort', onAbort); resolve(v); };
    const onAbort = () => { if (done) return; done = true; w.terminate(); reject(new DOMException('aborted', 'AbortError')); };
    if (signal) signal.addEventListener('abort', onAbort);
    let started = false;
    w.onmessage = (ev) => {
      if (ev.data && ev.data.ready) { started = true; w.postMessage(msg); return; }
      finish(ev.data);
    };
    w.onerror = (ev) => { ev.preventDefault(); finish(started ? { ok: false, code: 'device' } : null); };
  });
}

function belowAbsoluteFloor(kdf) {
  return !kdf || typeof kdf !== 'object' || C.kdfHeaderProblem(kdf) !== undefined
    || kdf.m < ABSOLUTE_FLOOR.m || kdf.t < ABSOLUTE_FLOOR.t || kdf.p < ABSOLUTE_FLOOR.p;
}

export async function reveal(id, input, opts = {}) {
  try {
    if (!lastVerified || lastVerified.id !== id) {
      const v = await verify(id, opts);
      if (!v.ok) return { ok: false, error: v.error };
    }
    const entry = lastVerified && lastVerified.id === id ? lastVerified.entry : null;
    if (!entry || entry.s !== 'V') return { ok: false, error: 'not-found' };
    // An entry below the original floor was never issued by a conforming issuer: refuse to open it.
    if (belowAbsoluteFloor(entry.kdf)) return { ok: false, error: 'corrupt' };
    const kind = input && input.factorKind === 'email' ? 'e' : 's';
    const msg = { id, kind, factor: String((input && input.factor) || ''), revealKey: String((input && input.revealCode) || '') };
    if (opts.onProgress) opts.onProgress('deriving');
    let r = opts.worker === false || typeof Worker === 'undefined' ? null : await unsealInWorker(entry, { rec: entry, ...msg }, opts.signal);
    if (!r) r = await unsealHere(entry, msg);
    msg.factor = ''; msg.revealKey = '';
    if (r.ok) {
      const p = r.payload;
      // The type shown is the PUBLIC entry's (effective) type, never the sealed copy's (SPEC.md 6): a downgraded
      // certificate reveals as what it is now, with no trace of what it was.
      const name = typeof p.n === 'string' && p.n.trim() !== '' ? p.n : null;
      return { ok: true, details: { name, course: p.c, dates: p.d, venue: p.v, type: entry.t }, ms: Math.round(r.ms || 0), engine: r.engine };
    }
    if (r.code === 'no-match') return { ok: false, error: 'wrong-factor' };
    if (r.code === 'corrupt' || r.code === 'malformed') return { ok: false, error: 'corrupt' };
    return { ok: false, error: 'no-wasm' };
  } catch (e) {
    if (e && e.name === 'AbortError') throw e;
    return { ok: false, error: 'no-wasm' };
  }
}
