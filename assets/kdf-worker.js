// kdf-worker.js - same-origin module worker for the holder-only reveal (SPEC.md 5.2-5.3, 6).
// Runs the Argon2id derivation + key check + authenticated decryption off the page thread.
// Receives one message, answers once, and is terminated by the page. Nothing is stored or logged.
import { unseal, isSealError, wasmFellBack } from './verifier.804a6d17e2b5.js';

self.onmessage = async (ev) => {
  const { rec, id, kind, factor, revealKey } = ev.data || {};
  const t0 = performance.now();
  let out;
  try {
    const r = await unseal(rec, { id, kind, factor, revealKey });
    out = { ok: true, payload: r.payload };
  } catch (e) {
    out = { ok: false, code: isSealError(e) ? e.code : 'device' };
  }
  out.ms = performance.now() - t0;
  out.engine = wasmFellBack() ? 'js' : 'wasm';
  self.postMessage(out);
};
self.postMessage({ ready: true });
