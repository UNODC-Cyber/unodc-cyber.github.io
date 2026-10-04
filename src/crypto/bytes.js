function systemCrypto() {
  const g = typeof globalThis !== "undefined" ? globalThis : typeof self !== "undefined" ? self : void 0;
  const c = g ? g.crypto : void 0;
  if (!c || typeof c.getRandomValues !== "function") {
    throw new Error("crypto.getRandomValues is not available");
  }
  return c;
}
const systemRandom = function(n) {
  const out = new Uint8Array(n);
  const c = systemCrypto();
  for (let at = 0; at < n; at += 65536) {
    c.getRandomValues(out.subarray(at, Math.min(n, at + 65536)));
  }
  return out;
};
function utf8(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 55296 && c <= 56319 && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 56320 && d <= 57343) {
        c = 65536 + (c - 55296 << 10) + (d - 56320);
        i++;
      } else {
        c = 65533;
      }
    } else if (c >= 55296 && c <= 57343) {
      c = 65533;
    }
    if (c < 128) out.push(c);
    else if (c < 2048) out.push(192 | c >> 6, 128 | c & 63);
    else if (c < 65536) out.push(224 | c >> 12, 128 | c >> 6 & 63, 128 | c & 63);
    else out.push(240 | c >> 18, 128 | c >> 12 & 63, 128 | c >> 6 & 63, 128 | c & 63);
  }
  return new Uint8Array(out);
}
function utf8Decode(b) {
  let s = "";
  for (let i = 0; i < b.length; ) {
    const c = b[i++];
    let cp;
    if (c < 128) cp = c;
    else if (c >= 194 && c < 224) cp = (c & 31) << 6 | cont(b, i++);
    else if (c >= 224 && c < 240) {
      cp = (c & 15) << 12 | cont(b, i++) << 6 | cont(b, i++);
      if (cp < 2048 || cp >= 55296 && cp <= 57343) throw new Error("malformed UTF-8");
    } else if (c >= 240 && c < 245) {
      cp = (c & 7) << 18 | cont(b, i++) << 12 | cont(b, i++) << 6 | cont(b, i++);
      if (cp < 65536 || cp > 1114111) throw new Error("malformed UTF-8");
    } else throw new Error("malformed UTF-8");
    if (cp >= 65536) {
      cp -= 65536;
      s += String.fromCharCode(55296 + (cp >> 10), 56320 + (cp & 1023));
    } else s += String.fromCharCode(cp);
  }
  return s;
}
function cont(b, i) {
  if (i >= b.length || (b[i] & 192) !== 128) throw new Error("malformed UTF-8");
  return b[i] & 63;
}
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
function b64url(b) {
  let s = "";
  let i = 0;
  for (; i + 2 < b.length; i += 3) {
    const n = b[i] << 16 | b[i + 1] << 8 | b[i + 2];
    s += B64.charAt(n >> 18) + B64.charAt(n >> 12 & 63) + B64.charAt(n >> 6 & 63) + B64.charAt(n & 63);
  }
  if (b.length - i === 1) {
    const n = b[i] << 16;
    s += B64.charAt(n >> 18) + B64.charAt(n >> 12 & 63);
  } else if (b.length - i === 2) {
    const n = b[i] << 16 | b[i + 1] << 8;
    s += B64.charAt(n >> 18) + B64.charAt(n >> 12 & 63) + B64.charAt(n >> 6 & 63);
  }
  return s;
}
function b64urlDecode(s) {
  if (typeof s !== "string" || s.length % 4 === 1) throw new Error("bad base64url");
  const out = [];
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < s.length; i++) {
    const v = B64.indexOf(s.charAt(i));
    if (v < 0) throw new Error("bad base64url");
    acc = acc << 6 | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push(acc >> bits & 255);
    }
    acc &= (1 << bits) - 1;
  }
  if (acc !== 0) throw new Error("bad base64url (non-canonical)");
  return new Uint8Array(out);
}
function hex(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) s += (b[i] < 16 ? "0" : "") + b[i].toString(16);
  return s;
}
function hexDecode(s) {
  if (s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s)) throw new Error("bad hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}
function concat(parts) {
  let n = 0;
  for (let i = 0; i < parts.length; i++) n += parts[i].length;
  const out = new Uint8Array(n);
  let at = 0;
  for (let i = 0; i < parts.length; i++) {
    out.set(parts[i], at);
    at += parts[i].length;
  }
  return out;
}
function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
function wipe(b) {
  if (b) for (let i = 0; i < b.length; i++) b[i] = 0;
}
function ascii(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 127) throw new Error("non-ASCII protocol string");
    out[i] = c;
  }
  return out;
}
export {
  ascii,
  b64url,
  b64urlDecode,
  concat,
  equalBytes,
  hex,
  hexDecode,
  systemRandom,
  utf8,
  utf8Decode,
  wipe
};
