const NORM_VERSION = 1;
const FOLD = {
  "đ": "d",
  // đ
  "ð": "d",
  // ð
  "ł": "l",
  // ł
  "ø": "o",
  // ø
  "ħ": "h",
  // ħ
  "ŧ": "t",
  // ŧ
  "ı": "i",
  // ı (dotless i)
  "ß": "ss",
  // ß
  "ς": "σ",
  // ς -> σ
  "æ": "ae",
  // æ
  "œ": "oe",
  // œ
  "þ": "th"
  // þ
};
let reMn;
let reNotLN;
let reFold;
let reEmailDrop;
function regexes() {
  if (reMn) return;
  reMn = new RegExp("\\p{Mn}", "gu");
  reNotLN = new RegExp("[^\\p{L}\\p{N}]", "gu");
  reFold = new RegExp("[\\u0111\\u00f0\\u0142\\u00f8\\u0127\\u0167\\u0131\\u00df\\u03c2\\u00e6\\u0153\\u00fe]", "g");
  reEmailDrop = new RegExp("[\\s\\p{Cc}\\p{Cf}]", "gu");
}
function normaliseSurname(raw) {
  regexes();
  let s = raw === null || raw === void 0 ? "" : String(raw);
  s = s.normalize("NFKC").toLowerCase();
  s = s.replace(reFold, function(ch) {
    return FOLD[ch];
  });
  s = s.normalize("NFD").replace(reMn, "").replace(reNotLN, "");
  return s.normalize("NFC");
}
function normaliseEmail(raw) {
  regexes();
  const s = raw === null || raw === void 0 ? "" : String(raw);
  return s.normalize("NFKC").toLowerCase().replace(reEmailDrop, "");
}
function normaliseFactor(kind, raw) {
  return kind === "e" ? normaliseEmail(raw) : normaliseSurname(raw);
}
export {
  NORM_VERSION,
  normaliseEmail,
  normaliseFactor,
  normaliseSurname
};
