const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const REDUCE = 37;
function mulx(v) {
  let r = (v & 31) << 1;
  if (r & 32) r ^= REDUCE;
  return r & 31;
}
function dammStep(interim, value) {
  return mulx((interim ^ value) & 31);
}
function symbolValue(ch) {
  return ALPHABET.indexOf(ch);
}
function dammInterim(symbols) {
  let interim = 0;
  for (let i = 0; i < symbols.length; i++) {
    const d = ALPHABET.indexOf(symbols.charAt(i));
    if (d < 0) return -1;
    interim = dammStep(interim, d);
  }
  return interim;
}
function dammCheckSymbol(symbols) {
  const interim = dammInterim(symbols);
  if (interim < 0) throw new RangeError("invalid symbol");
  return ALPHABET.charAt(interim);
}
function dammValid(symbolsWithCheck) {
  if (symbolsWithCheck.length < 2) return false;
  return dammInterim(symbolsWithCheck) === 0;
}
const SEPARATORS = new RegExp("[\\s\\-\\u2010-\\u2015\\u2212_]", "g");
function cleanSymbols(raw) {
  let s = raw === null || raw === void 0 ? "" : String(raw);
  if (typeof s.normalize === "function") s = s.normalize("NFKC");
  s = s.toUpperCase().replace(SEPARATORS, "").replace(/[IL]/g, "1").replace(/O/g, "0");
  const invalid = [];
  for (let i = 0; i < s.length; i++) {
    const ch = s.charAt(i);
    if (ALPHABET.indexOf(ch) < 0) invalid.push({ pos: i + 1, ch });
  }
  return { canonical: s, invalid };
}
function group(canonical, sizes) {
  const out = [];
  let at = 0;
  for (let g = 0; g < sizes.length && at < canonical.length; g++) {
    const end = g === sizes.length - 1 ? canonical.length : at + sizes[g];
    out.push(canonical.substring(at, end));
    at = end;
  }
  if (at < canonical.length) out.push(canonical.substring(at));
  return out.join("-");
}
function bytesToSymbols(bytes, nSymbols) {
  let out = "";
  for (let s = 0; s < nSymbols; s++) {
    let v = 0;
    for (let b = 0; b < 5; b++) {
      const bit = s * 5 + b;
      const byte = bit >> 3;
      const val = byte < bytes.length ? bytes[byte] >> 7 - (bit & 7) & 1 : 0;
      v = v << 1 | val;
    }
    out += ALPHABET.charAt(v);
  }
  return out;
}
function randomSymbols(random) {
  let out = "";
  for (let i = 0; i < random.length; i++) out += ALPHABET.charAt(random[i] & 31);
  return out;
}
export {
  ALPHABET,
  bytesToSymbols,
  cleanSymbols,
  dammCheckSymbol,
  dammInterim,
  dammStep,
  dammValid,
  group,
  mulx,
  randomSymbols,
  symbolValue
};
