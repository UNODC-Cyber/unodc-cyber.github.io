import { argon2id as wasmArgon2id } from "hash-wasm";
import { argon2idAsync as nobleArgon2idAsync } from "@noble/hashes/argon2.js";
function prof(id, m, t, note) {
  return { id, kdf: { alg: "argon2id", v: 19, m, t, p: 1, len: 32 }, note };
}
const KDF_FLOOR = { m: 19456, t: 2, p: 1 };
const KDF_CEILING = { m: 1048576, t: 16, p: 4 };
const SEAL_PROFILES = {
  "a2id-19m-2t-1p": prof("a2id-19m-2t-1p", 19456, 2, "floor (OWASP minimum); never used for new seals by default"),
  "a2id-32m-3t-1p": prof("a2id-32m-3t-1p", 32768, 3, "tuning ladder step 2 (low-end phone > 2 s on 47m)"),
  "a2id-47m-3t-1p": prof("a2id-47m-3t-1p", 48128, 3, "tuning ladder step 1 (low-end phone > 2 s on 64m)"),
  "a2id-64m-3t-1p": prof("a2id-64m-3t-1p", 65536, 3, "target profile for certificate seals")
};
const DEFAULT_SEAL_PROFILE = "a2id-64m-3t-1p";
function meetsFloor(k) {
  return k.m >= KDF_FLOOR.m && k.t >= KDF_FLOOR.t && k.p >= KDF_FLOOR.p;
}
function kdfHeaderProblem(k) {
  if (!k || typeof k !== "object") return "missing kdf header";
  if (k.alg !== "argon2id") return "kdf alg must be argon2id";
  if (k.v !== 19) return "kdf version must be 19";
  if (k.len !== 32) return "kdf len must be 32";
  const ints = [k.m, k.t, k.p];
  for (let i = 0; i < ints.length; i++) {
    if (typeof ints[i] !== "number" || ints[i] !== Math.floor(ints[i]) || ints[i] < 1) return "kdf m/t/p must be positive integers";
  }
  if (k.m > KDF_CEILING.m || k.t > KDF_CEILING.t || k.p > KDF_CEILING.p) return "kdf parameters exceed the accepted ceiling";
  if (k.m < 8 * k.p) return "kdf m must be at least 8*p";
  return void 0;
}
function sealProfile(id) {
  const p = Object.prototype.hasOwnProperty.call(SEAL_PROFILES, id) ? SEAL_PROFILES[id] : void 0;
  if (!p) throw new Error("unknown seal profile: " + id);
  assertSealable(p.kdf);
  return p;
}
function assertSealable(k) {
  const problem = kdfHeaderProblem(k);
  if (problem) throw new Error(problem);
  if (!meetsFloor(k)) throw new Error("kdf parameters are below the floor (m >= 19456 KiB, t >= 2, p >= 1)");
}
let wasmUnavailable = false;
function wasmFellBack() {
  return wasmUnavailable;
}
async function argon2id(password, salt, k, engine) {
  const problem = kdfHeaderProblem(k);
  if (problem) throw new Error(problem);
  const e = engine || "auto";
  if (e === "js" || e === "auto" && wasmUnavailable) return argon2idJs(password, salt, k);
  try {
    return await wasmArgon2id({
      password,
      salt,
      iterations: k.t,
      parallelism: k.p,
      memorySize: k.m,
      hashLength: k.len,
      outputType: "binary"
    });
  } catch (err) {
    if (e === "wasm") throw err;
    wasmUnavailable = true;
    return argon2idJs(password, salt, k);
  }
}
function argon2idJs(password, salt, k) {
  return nobleArgon2idAsync(password, salt, {
    t: k.t,
    m: k.m,
    p: k.p,
    dkLen: k.len,
    version: 19,
    maxmem: k.m * 1024 + 1048576,
    // Yield to the event loop at most every 100 ms: the default 10 ms tick doubles the run time
    // (measured 2026-10-03: floor profile 1205 ms at 10 ms vs 593 ms at 100 ms; sync = 578 ms).
    asyncTick: 100
  });
}
export {
  DEFAULT_SEAL_PROFILE,
  KDF_CEILING,
  KDF_FLOOR,
  SEAL_PROFILES,
  argon2id,
  assertSealable,
  kdfHeaderProblem,
  meetsFloor,
  sealProfile,
  wasmFellBack
};
