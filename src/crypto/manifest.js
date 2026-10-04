import { canonicalBytes, canonicalJson, parseCanonical } from "./canonical";
import { sha3B64 } from "./sha3";
const MANIFEST_SCHEMA = 3;
const MAX_EXPIRY_DAYS = 60;
const CLOCK_SKEW_MS = 864e5;
const DAY_MS = 864e5;
const SHARD_VERSION = 2;
const SHARD_NAMES = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"];
const DEFAULT_META = {
  schema: 2,
  types: { CMP: "completion", ATT: "attendance", APP: "appreciation", TRN: "contribution" }
};
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
function isIsoUtc(s) {
  return typeof s === "string" && ISO.test(s) && !isNaN(Date.parse(s));
}
function isoUtc(d) {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}
function encodeShard(entries) {
  const keys = Object.keys(entries);
  for (let i = 0; i < keys.length; i++) {
    const e = entries[keys[i]];
    if (e.s !== "V" && e.s !== "R") throw new Error("shard entry status must be V or R");
  }
  return canonicalBytes({ c: entries, v: SHARD_VERSION });
}
function buildSnapshotFiles(entries, meta) {
  const byShard = {};
  for (let i = 0; i < SHARD_NAMES.length; i++) byShard[SHARD_NAMES[i]] = {};
  const keys = Object.keys(entries);
  for (let i = 0; i < keys.length; i++) byShard[shardOfRegistryKey(keys[i])][keys[i]] = entries[keys[i]];
  const files = {};
  for (let i = 0; i < SHARD_NAMES.length; i++) files["r/" + SHARD_NAMES[i] + ".json"] = encodeShard(byShard[SHARD_NAMES[i]]);
  files["meta.json"] = canonicalBytes(meta || DEFAULT_META);
  return files;
}
function shardOfRegistryKey(registryKey) {
  const v = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".indexOf(registryKey.charAt(0));
  if (v < 0 || registryKey.length !== 86) throw new Error("bad registry key");
  return (v >> 2).toString(16);
}
function buildManifest(input) {
  if (!(input.seq >= 1) || Math.floor(input.seq) !== input.seq) throw new Error("seq must be a positive integer");
  if (!(input.entries >= 0) || Math.floor(input.entries) !== input.entries) throw new Error("entries must be a non-negative integer");
  const dateProblem = manifestDateProblem(input);
  if (dateProblem) throw new Error(dateProblem);
  if (!/^[A-Za-z0-9._-]{1,40}$/.test(input.generator)) throw new Error("generator must be a neutral version string");
  if (!/^[A-Za-z0-9._-]{1,40}$/.test(input.kid)) throw new Error("bad kid");
  const files = {};
  const paths = Object.keys(input.files);
  for (let i = 0; i < paths.length; i++) files[paths[i]] = sha3B64(input.files[paths[i]]);
  return {
    schema: MANIFEST_SCHEMA,
    seq: input.seq,
    asOf: input.asOf,
    issued: input.issued,
    expires: input.expires,
    generator: input.generator,
    entries: input.entries,
    kid: input.kid,
    files
  };
}
function encodeManifest(m) {
  return canonicalBytes(m);
}
function manifestText(m) {
  return canonicalJson(m);
}
function manifestDateProblem(m) {
  if (!isIsoUtc(m.asOf) || !isIsoUtc(m.issued) || !isIsoUtc(m.expires)) return "asOf/issued/expires must be YYYY-MM-DDTHH:MM:SSZ";
  const asOf = Date.parse(m.asOf);
  const issued = Date.parse(m.issued);
  const expires = Date.parse(m.expires);
  if (asOf > issued) return "asOf must not be after issued";
  if (expires <= issued) return "expires must be after issued";
  if (expires - issued > MAX_EXPIRY_DAYS * DAY_MS) return "expires must be at most " + MAX_EXPIRY_DAYS + " days after issued";
  return void 0;
}
function parseManifest(bytes) {
  const m = parseCanonical(bytes);
  if (!m || typeof m !== "object" || m.schema !== MANIFEST_SCHEMA) throw new Error("unsupported manifest schema");
  if (typeof m.seq !== "number" || !(m.seq >= 1) || typeof m.entries !== "number" || typeof m.kid !== "string") throw new Error("bad manifest");
  if (!isIsoUtc(m.asOf) || !isIsoUtc(m.issued) || !isIsoUtc(m.expires)) throw new Error("bad manifest dates");
  if (!m.files || typeof m.files !== "object") throw new Error("bad manifest files");
  return m;
}
function fileMatches(m, path, bytes) {
  return Object.prototype.hasOwnProperty.call(m.files, path) && m.files[path] === sha3B64(bytes);
}
function freshness(m, now) {
  const t = now.getTime();
  const asOf = Date.parse(m.asOf);
  const issued = Date.parse(m.issued);
  if (isNaN(issued) || issued > t + CLOCK_SKEW_MS || asOf > t + CLOCK_SKEW_MS) return "future";
  if (t > Date.parse(m.expires)) return "expired";
  if (t > asOf + 10 * DAY_MS) return "stale";
  return "ok";
}
function manifestDigest(bytes) {
  return sha3B64(bytes);
}
function rollbackVerdict(seq, digest, seen, minSeq) {
  if (typeof minSeq === "number" && seq < minSeq) return "below-min-seq";
  if (seen && typeof seen.seq === "number" && typeof seen.digest === "string") {
    if (seq < seen.seq) return "older-than-seen";
    if (seq === seen.seq && digest !== seen.digest) return "fork";
  }
  return "ok";
}
export {
  CLOCK_SKEW_MS,
  DEFAULT_META,
  MANIFEST_SCHEMA,
  MAX_EXPIRY_DAYS,
  SHARD_NAMES,
  SHARD_VERSION,
  buildManifest,
  buildSnapshotFiles,
  encodeManifest,
  encodeShard,
  fileMatches,
  freshness,
  isIsoUtc,
  isoUtc,
  manifestDateProblem,
  manifestDigest,
  manifestText,
  parseManifest,
  rollbackVerdict,
  shardOfRegistryKey
};
