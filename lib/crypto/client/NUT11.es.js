import { bytesToHex as o, hexToBytes as d } from "@noble/curves/abstract/utils";
import { sha256 as a } from "@noble/hashes/sha256";
import { schnorr as i } from "@noble/curves/secp256k1";
import { randomBytes as m } from "@noble/hashes/utils";
import { parseSecret as f } from "../common/NUT11.es.js";
const B = (e) => {
  const t = [
    "P2PK",
    {
      nonce: o(m(32)),
      data: e
    }
  ], n = JSON.stringify(t);
  return new TextEncoder().encode(n);
}, h = (e, t) => {
  const n = a(new TextDecoder().decode(e));
  return i.sign(n, t);
}, p = (e, t) => {
  const n = a(e);
  return i.sign(n, t);
}, b = (e, t) => {
  let n = [], r = "";
  if (t instanceof Array)
    for (const s of t)
      n.push({ priv: s, pub: o(i.getPublicKey(s)) });
  else
    r = t;
  return e.map((s) => {
    try {
      const c = f(s.secret);
      if (c[0] !== "P2PK")
        throw new Error("unknown secret type");
      if (n.length) {
        const g = n.find((u) => c[1].data === u.pub)?.priv;
        if (g)
          r = g;
        else
          throw new Error("no matching key found");
      }
      return P(s, d(r));
    } catch {
      return s;
    }
  });
}, w = (e, t) => {
  const n = e.B_.toHex(!0), r = p(n, t);
  return e.witness = { signatures: [o(r)] }, e;
}, K = (e, t) => e.map((n) => w(n, t)), P = (e, t) => (e.witness || (e.witness = {
  signatures: [o(h(e.secret, t))]
}), e);
export {
  B as createP2PKsecret,
  w as getSignedOutput,
  K as getSignedOutputs,
  P as getSignedProof,
  b as getSignedProofs,
  p as signBlindedMessage,
  h as signP2PKsecret
};
//# sourceMappingURL=NUT11.es.js.map
