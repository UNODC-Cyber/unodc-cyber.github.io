import { utf8, utf8Decode } from "./bytes";
function canonicalJson(value) {
  return enc(value, 0);
}
function canonicalBytes(value) {
  return utf8(canonicalJson(value));
}
function enc(v, depth) {
  if (depth > 32) throw new Error("canonical JSON: nesting too deep");
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!isSafeInt(v)) throw new Error("canonical JSON: only safe integers are allowed, got " + String(v));
    if (v === 0 && 1 / v < 0) throw new Error("canonical JSON: -0 is not allowed");
    return String(v);
  }
  if (Object.prototype.toString.call(v) === "[object Array]") {
    const a = v;
    const parts = [];
    for (let i = 0; i < a.length; i++) parts.push(enc(a[i], depth + 1));
    return "[" + parts.join(",") + "]";
  }
  if (typeof v === "object") {
    const o = v;
    const proto = Object.getPrototypeOf(o);
    if (proto !== Object.prototype && proto !== null) throw new Error("canonical JSON: only plain objects are allowed");
    const keys = Object.keys(o).sort();
    const parts = [];
    for (let i = 0; i < keys.length; i++) {
      const val = o[keys[i]];
      if (val === void 0) throw new Error("canonical JSON: undefined value for key " + keys[i]);
      parts.push(JSON.stringify(keys[i]) + ":" + enc(val, depth + 1));
    }
    return "{" + parts.join(",") + "}";
  }
  throw new Error("canonical JSON: unsupported value type " + typeof v);
}
function isSafeInt(n) {
  return typeof n === "number" && isFinite(n) && Math.floor(n) === n && Math.abs(n) <= 9007199254740991;
}
function parseCanonical(bytes) {
  const text = utf8Decode(bytes);
  const value = JSON.parse(text);
  if (canonicalJson(value) !== text) throw new Error("not canonical JSON");
  return value;
}
export {
  canonicalBytes,
  canonicalJson,
  parseCanonical
};
