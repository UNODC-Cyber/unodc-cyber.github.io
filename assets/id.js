// id.js - identifier and factor helpers used by the page UI (pure functions, no I/O, no DOM).
// Thin adapter: every rule comes from the verifier bundle (the issuer's own modules), so the page and the
// issuing system cannot drift apart. See SPEC.md section 2 (identifier) and 5.1 (factor normalisation).
import * as C from './verifier.804a6d17e2b5.js';

export const ALPHABET = C.ALPHABET; // Crockford base32, no I L O U
export const ID_LENGTH = C.ID_LENGTH;
export const REVEAL_LENGTH = C.REVEAL_LENGTH;

/** Check symbol for a string of valid symbols. Throws RangeError on a symbol outside the alphabet. */
export const dammSymbol = (symbols) => C.dammCheckSymbol(symbols);

/** True if all 27 symbols are valid and the Damm check passes. */
export const dammValid = (id) => typeof id === 'string' && id.length === ID_LENGTH && C.dammValid(id);

/** Canonicalise typed input -> { canonical, invalid: [{ pos, ch }] } (SPEC.md 2.4). */
export const normaliseId = (raw) => C.cleanSymbols(raw);

/**
 * Classify typed input for live feedback. Never touches the network.
 * kind: 'empty' | 'invalid-symbol' | 'too-short' | 'too-long' | 'bad-check' | 'ok'
 */
export function checkId(raw) {
  const p = C.parseId(String(raw ?? ''));
  const r = { kind: p.ok ? 'ok' : p.problem, canonical: p.canonical, length: p.canonical.length };
  if (p.problem === 'invalid-symbol') { r.pos = p.invalid.pos; r.ch = p.invalid.ch; }
  return r;
}

/** Canonical symbols -> "XXXXXXXXX-XXXXXXXXX-XXXXXXXXX" (partial input is grouped as far as it goes). */
export const formatId = (canonical) => C.formatId(canonical);

/** Typed reveal code (10 symbols, hyphen/space tolerated) -> canonical or null. */
export const normaliseReveal = (raw) => C.parseRevealKey(String(raw ?? '')) ?? null;

/** Factor normalisation, version 1 (SPEC.md 5.1). kind: 'surname' | 'email'. */
export const normaliseFactor = (raw, kind) => C.normaliseFactor(kind === 'email' ? 'e' : 's', String(raw ?? ''));
