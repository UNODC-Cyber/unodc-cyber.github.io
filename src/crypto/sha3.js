import { sha3_512 as nobleSha3 } from "@noble/hashes/sha3.js";
import { createSHA3 } from "hash-wasm";
import { ascii, b64url, concat } from "./bytes";
function sha3_512(data) {
  return nobleSha3(data);
}
let wasmBroken = false;
async function sha3_512Async(data) {
  if (!wasmBroken) {
    try {
      return await sha3_512Wasm(data);
    } catch {
      wasmBroken = true;
    }
  }
  return nobleSha3(data);
}
async function sha3_512Wasm(data) {
  const h = await createSHA3(512);
  h.init();
  h.update(data);
  return h.digest("binary");
}
function taggedSha3(tag, data) {
  return nobleSha3(concat([ascii(tag), new Uint8Array([0]), data]));
}
function sha3B64(data) {
  return b64url(nobleSha3(data));
}
export {
  sha3B64,
  sha3_512,
  sha3_512Async,
  sha3_512Wasm,
  taggedSha3
};
