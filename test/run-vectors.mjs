// run-vectors.mjs - conformance vectors (test/vectors.json) against the shipped bundle.
// Shared by Node (node test/run-vectors.mjs) and the browser (test/harness.html), so both run
// exactly the same checks against exactly the same bundle (the file named in assets/bundle.sha256).
//
//   runVectors(lib, vectors, { log, jsArgon2MaxKiB }) -> Promise<{ pass, fail, failures: string[], timings }>
//   lib = the module namespace of that bundle

const enc = (s) => new TextEncoder().encode(s);
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const now = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());

export async function runVectors(lib, v, opts = {}) {
  const log = opts.log || (() => {});
  const jsMax = opts.jsArgon2MaxKiB ?? 65536;
  let pass = 0; let fail = 0; const failures = []; const timings = {};
  const ok = (name, cond, extra = '') => { if (cond) pass++; else { fail++; failures.push(name + (extra ? ' ' + extra : '')); log('FAIL ' + name + ' ' + extra); } };
  const H = lib.hex; const HD = lib.hexDecode;

  // ---- identifiers
  const id = v.identifier;
  ok('alphabet', lib.ALPHABET === id.alphabet);
  for (const c of id.checkSymbols) ok(`check symbol of ${c.payload}`, lib.dammCheckSymbol(c.payload) === c.check);
  for (const x of id.valid) {
    const p = lib.parseId(x.printed);
    ok(`valid ${x.id}`, p.ok && p.canonical === x.id && lib.formatId(x.id) === x.printed);
    ok(`registry key ${x.id}`, lib.registryKeyOf(x.id) === x.registryKey && lib.shardOf(x.id) === x.shard && H(lib.idDigest(x.id)) === x.sha3_512);
  }
  for (const x of id.parse) {
    const p = lib.parseId(x.raw);
    ok(`parse ${JSON.stringify(x.raw)}`, p.ok === x.ok && p.canonical === x.canonical && (x.ok || p.problem === x.problem) && (x.invalidPos === undefined || (p.invalid && p.invalid.pos === x.invalidPos)), JSON.stringify(p));
  }
  ok(`${id.singleSymbolErrors.count} single-symbol errors rejected`, id.singleSymbolErrors.allInvalid.length === id.singleSymbolErrors.count && id.singleSymbolErrors.allInvalid.every((s) => !lib.parseId(s).ok));
  ok(`${id.adjacentTranspositions.count} adjacent transpositions rejected`, id.adjacentTranspositions.allInvalid.every((s) => !lib.parseId(s).ok));
  for (const r of id.revealKey.parse) ok(`reveal key ${JSON.stringify(r.raw)}`, (lib.parseRevealKey(r.raw) ?? null) === r.canonical);

  // ---- normalisation
  for (const [raw, want] of v.normalise.surname) ok(`surname ${JSON.stringify(raw)}`, lib.normaliseSurname(raw) === want, JSON.stringify(lib.normaliseSurname(raw)));
  for (const [raw, want] of v.normalise.email) ok(`email ${JSON.stringify(raw)}`, lib.normaliseEmail(raw) === want, JSON.stringify(lib.normaliseEmail(raw)));

  // ---- primitives
  for (const x of v.sha3_512) ok(`sha3-512 (${x.inputHex.length / 2} B)`, H(lib.sha3_512(HD(x.inputHex))) === x.digestHex);
  for (const x of v.xchacha20poly1305) {
    const c = lib.xchacha20poly1305(HD(x.keyHex), HD(x.nonceHex), HD(x.aadHex));
    ok(`xchacha20poly1305 seal (${x.plaintextHex.length / 2} B)`, H(c.encrypt(HD(x.plaintextHex))) === x.ciphertextAndTagHex);
    ok('xchacha20poly1305 open', H(lib.xchacha20poly1305(HD(x.keyHex), HD(x.nonceHex), HD(x.aadHex)).decrypt(HD(x.ciphertextAndTagHex))) === x.plaintextHex);
  }
  for (const x of v.kcv) ok(`kcv ${x.tag}`, lib.b64url(lib.taggedSha3(x.tag, HD(x.keyHex))) === x.kcv);
  for (const x of v.canonicalJson) ok(`canonical JSON ${x.bytes.slice(0, 24)}`, lib.canonicalJson(x.value) === x.bytes && H(lib.utf8(x.bytes)) === x.utf8Hex);
  for (const x of v.argon2id.vectors) {
    for (const engine of ['wasm', 'js']) {
      if (engine === 'js' && x.kdf.m > jsMax) continue;
      if (engine === 'wasm' && opts.noWasm) continue;
      const t0 = now();
      let out = '';
      try { out = H(await lib.argon2id(HD(x.passwordHex), HD(x.saltHex), x.kdf, engine)); } catch (e) { out = 'error ' + e.message; }
      timings[`argon2id ${x.profile} ${engine}`] = Math.round(now() - t0);
      ok(`argon2id ${x.profile} (${engine})`, out === x.outHex, out);
    }
  }

  // ---- key fingerprints
  for (const k of Object.keys(v.keys)) {
    const r = v.keys[k].keyRecord;
    ok(`fingerprint ${k}`, lib.fingerprint(lib.b64urlDecode(r.mldsa65), lib.b64urlDecode(r.ed25519)) === r.fingerprint);
  }

  // ---- sealed entries
  const unseal = async (rec, inp) => { try { const u = await lib.unseal(rec, inp); return { result: 'ok', payload: u.payload, nameRecorded: u.nameRecorded }; } catch (e) { return { result: lib.isSealError(e) ? e.code : 'throw ' + e.message }; } };
  for (const s of v.sealed) {
    ok(`sealed ${s.name}: registry key + KDF inputs`, lib.registryKeyOf(s.id) === s.derived.registryKey && H(lib.kdfSalt(HD(s.randomness.saltHex), s.id)) === s.derived.kdfSaltHex && H(lib.kdfPassword('s', s.surname, s.revealKey)) === s.derived.kdfPasswordSurnameHex);
    for (const e of s.expect) {
      const t0 = now();
      const r = await unseal(s.record, { id: s.id, kind: e.kind, factor: e.factor, revealKey: e.revealKey });
      timings[`unseal ${s.name} ${e.kind} ${e.result}`] = Math.round(now() - t0);
      ok(`sealed ${s.name}: ${e.kind} ${JSON.stringify(e.factor)} -> ${e.result}`, r.result === e.result && (e.result !== 'ok' || eq(r.payload, e.payload)), JSON.stringify(r));
      if (e.result === 'ok' && e.nameRecorded !== undefined) ok(`sealed ${s.name}: holder name ${e.nameRecorded ? 'recorded' : 'not recorded (older seal version)'}`, r.nameRecorded === e.nameRecorded);
    }
  }
  {
    const t = v.transplanted;
    const r = await unseal(t.record, { id: t.lookup.id, kind: t.lookup.kind, factor: t.lookup.factor, revealKey: t.lookup.revealKey });
    ok('transplanted record: lookup under the other identifier -> no-match', r.result === t.lookup.result, JSON.stringify(r));
    let code = 'ok';
    try { lib.openWithFactorKey(t.record, t.aadOnly.registryKey, 's', HD(t.aadOnly.K_sHex)); } catch (e) { code = e.code; }
    ok('transplanted record: right key, wrong associated data -> corrupt', code === t.aadOnly.result);
  }

  // ---- mini registry under test-k1
  const R = v.registry;
  const mBytes = lib.utf8(R.manifest);
  ok('signed message bytes', H(lib.signedMessage(mBytes)) === R.signedMessageHex);
  const vr = lib.verifyManifest(mBytes, R.signature, R.pinnedKeys);
  ok('registry: hybrid signature verifies with pinned test-k1', vr.ok === true, JSON.stringify(vr.reason));
  ok('registry: fresh at verifyAt', lib.freshness(vr.manifest, new Date(R.verifyAt)) === 'ok');
  for (const f of R.freshness || []) ok(`registry: freshness at ${f.at} -> ${f.expect}`, lib.freshness(vr.manifest, new Date(f.at)) === f.expect);
  for (const [path, text] of Object.entries(R.files)) ok(`registry: digest of ${path}`, lib.fileMatches(vr.manifest, path, lib.utf8(text)));
  for (const L of R.lookups) {
    const key = lib.registryKeyOf(L.id); const shard = JSON.parse(R.files[`r/${lib.shardOf(L.id)}.json`]);
    const e = Object.prototype.hasOwnProperty.call(shard.c, key) ? shard.c[key] : null;
    const state = !e ? 'not-found' : e.s === 'R' ? 'revoked' : e.t === 'ATT' ? 'valid-attendance' : 'valid-completion';
    ok(`registry lookup ${L.id} -> ${L.expectState}`, state === L.expectState, state);
    if (e && L.surname) {
      const r = await unseal(e, { id: L.id, kind: 's', factor: L.surname, revealKey: L.revealKey });
      ok(`registry reveal ${L.id}`, r.result === 'ok' && eq(r.payload, L.payload), JSON.stringify(r));
      // The type a verifier displays is the PUBLIC entry's, even where the sealed copy says otherwise (downgrade).
      if (L.displayType) ok(`registry reveal ${L.id}: displayed type = public t ${L.displayType}${L.payload.t !== L.displayType ? ' (sealed copy says ' + L.payload.t + ')' : ''}`, e.t === L.displayType);
    }
  }
  for (const f of R.mustFail) {
    let reason = 'ok';
    const manifest = f.manifest ? lib.utf8(f.manifest) : mBytes;
    const res = lib.verifyManifest(manifest, f.signature || R.signature, f.pinnedKeys || R.pinnedKeys);
    if (!res.ok) reason = res.reason;
    else if (f.replaceFile && !lib.fileMatches(res.manifest, f.replaceFile.path, lib.utf8(f.replaceFile.text))) reason = 'shard-digest-mismatch';
    else if (lib.freshness(res.manifest, new Date(R.verifyAt)) === 'expired') reason = 'expired';
    ok(`must fail: ${f.name} -> ${f.expect}`, reason === f.expect, reason);
  }

  // ---- rollback rule
  const RB = v.rollback;
  if (RB) {
    const prev = lib.verifyManifest(lib.utf8(RB.previous.manifest), RB.previous.signature, R.pinnedKeys);
    ok('rollback: the previous snapshot carries a valid signature (only the rollback rule stops its replay)', prev.ok === true && lib.freshness(prev.manifest, new Date(RB.previous.verifyAt)) === 'ok');
    ok('rollback: digest = SHA3-512 of the manifest bytes', lib.manifestDigest(lib.utf8(RB.previous.manifest)) === RB.previous.digest && lib.manifestDigest(mBytes) === RB.cases[0].digest);
    for (const c of RB.cases) ok(`rollback: ${c.name} -> ${c.expect}`, lib.rollbackVerdict(c.seq, c.digest, c.seen || undefined, c.minSeq === null ? undefined : c.minSeq) === c.expect);
  }
  return { pass, fail, failures, timings };
}

// Node entry: node test/run-vectors.mjs
if (typeof process !== 'undefined' && process.argv && process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop())) {
  const { readFileSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const bundle = readFileSync(fileURLToPath(new URL('../assets/bundle.sha256', import.meta.url)), 'utf8').trim().split(/\s+/)[1];
  if (!/^verifier\.[0-9a-f]{12}\.js$/.test(bundle || '')) throw new Error('assets/bundle.sha256 does not name a bundle');
  const lib = await import('../assets/' + bundle);
  const v = JSON.parse(readFileSync(fileURLToPath(new URL('./vectors.json', import.meta.url)), 'utf8'));
  const r = await runVectors(lib, v, { log: console.log, jsArgon2MaxKiB: Number(process.env.JS_ARGON2_MAX_KIB || 65536) });
  console.log(JSON.stringify(r.timings));
  console.log(`vectors (Node ${process.version}): ${r.pass} passed, ${r.fail} failed`);
  process.exitCode = r.fail ? 1 : 0;
}
