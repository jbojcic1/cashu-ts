const t = (r) => {
  try {
    return r instanceof Uint8Array && (r = new TextDecoder().decode(r)), JSON.parse(r);
  } catch {
    throw new Error("can't parse secret");
  }
};
export {
  t as parseSecret
};
//# sourceMappingURL=NUT11.es.js.map
