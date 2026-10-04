import { systemRandom, ascii, b64url } from "./bytes";
import { cleanSymbols, dammCheckSymbol, dammValid, group, randomSymbols } from "./crockford";
import { sha3_512 } from "./sha3";
const ID_RANDOM_SYMBOLS = 26;
const ID_LENGTH = 27;
const REVEAL_LENGTH = 10;
function generateId(random) {
  const rnd = (random || systemRandom)(ID_RANDOM_SYMBOLS);
  const payload = randomSymbols(rnd);
  return payload + dammCheckSymbol(payload);
}
function generateRevealKey(random) {
  return randomSymbols((random || systemRandom)(REVEAL_LENGTH));
}
function formatId(canonical) {
  return group(canonical, [9, 9, 9]);
}
function formatRevealKey(canonical) {
  return group(canonical, [5, 5]);
}
function parseId(raw) {
  const c = cleanSymbols(raw);
  const s = c.canonical;
  if (!s) return { ok: false, canonical: s, problem: "empty" };
  if (c.invalid.length) return { ok: false, canonical: s, problem: "invalid-symbol", invalid: c.invalid[0] };
  if (s.length < ID_LENGTH) return { ok: false, canonical: s, problem: "too-short" };
  if (s.length > ID_LENGTH) return { ok: false, canonical: s, problem: "too-long" };
  if (!dammValid(s)) return { ok: false, canonical: s, problem: "bad-check" };
  return { ok: true, canonical: s };
}
function isValidId(canonical) {
  return canonical.length === ID_LENGTH && cleanSymbols(canonical).canonical === canonical && dammValid(canonical);
}
function parseRevealKey(raw) {
  const c = cleanSymbols(raw);
  return c.invalid.length || c.canonical.length !== REVEAL_LENGTH ? void 0 : c.canonical;
}
function idDigest(canonicalId) {
  if (!isValidId(canonicalId)) throw new Error("not a canonical certificate identifier");
  return sha3_512(ascii(canonicalId));
}
function registryKeyOf(canonicalId) {
  return b64url(idDigest(canonicalId));
}
function shardOf(canonicalId) {
  return (idDigest(canonicalId)[0] >> 4).toString(16);
}
async function createWithUniqueKey(isTaken, options) {
  const max = options && options.maxAttempts ? options.maxAttempts : 5;
  for (let attempt = 0; attempt < max; attempt++) {
    const id = generateId(options ? options.random : void 0);
    if (!await isTaken(id)) return id;
  }
  throw new Error("could not draw an unused certificate identifier after " + max + " attempts");
}
export {
  ID_LENGTH,
  ID_RANDOM_SYMBOLS,
  REVEAL_LENGTH,
  createWithUniqueKey,
  formatId,
  formatRevealKey,
  generateId,
  generateRevealKey,
  idDigest,
  isValidId,
  parseId,
  parseRevealKey,
  registryKeyOf,
  shardOf
};
