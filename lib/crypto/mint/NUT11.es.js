import { schnorr as t } from "@noble/curves/secp256k1";
import { sha256 as s } from "@noble/hashes/sha256";
import { parseSecret as i } from "../common/NUT11.es.js";
const d = (e) => {
  if (!e.witness)
    throw new Error("could not verify signature, no witness provided");
  const r = i(e.secret);
  return t.verify(
    e.witness.signatures[0],
    s(new TextDecoder().decode(e.secret)),
    r[1].data
  );
}, w = (e, r) => {
  if (!e.witness)
    throw new Error("could not verify signature, no witness provided");
  return t.verify(e.witness.signatures[0], s(e.B_.toHex(!0)), r);
};
export {
  d as verifyP2PKSig,
  w as verifyP2PKSigOutput
};
//# sourceMappingURL=NUT11.es.js.map
