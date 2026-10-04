// harness.js - runs the conformance vectors in the browser against the shipped bundle.
// The bundle's file name carries its content hash; the current name is recorded in assets/bundle.sha256.
const BUNDLE = (await (await fetch('../assets/bundle.sha256', { cache: 'no-cache' })).text()).trim().split(/\s+/)[1];
if (!/^verifier\.[0-9a-f]{12}\.js$/.test(BUNDLE || '')) throw new Error('assets/bundle.sha256 does not name a bundle');
const lib = await import('../assets/' + BUNDLE);
import { runVectors } from './run-vectors.mjs';

const out = document.getElementById('out');
const status = document.getElementById('status');
const lines = [];
const log = (s) => { lines.push(s); out.textContent = lines.join('\n'); };
try {
  const v = await (await fetch('vectors.json', { cache: 'no-cache' })).json();
  const q = new URLSearchParams(location.search);
  const jsMax = Number(q.get('jsmax') || 65536);
  const r = await runVectors(lib, v, { log, jsArgon2MaxKiB: jsMax, noWasm: typeof WebAssembly === 'undefined' || q.has('nowasm') });
  log(JSON.stringify(r.timings, null, 1));
  status.textContent = `${r.pass} passed, ${r.fail} failed`;
  window.__vectors = r;
} catch (e) {
  status.textContent = 'harness error: ' + (e && e.message);
  window.__vectors = { pass: 0, fail: 1, failures: [String(e && e.message)] };
}
