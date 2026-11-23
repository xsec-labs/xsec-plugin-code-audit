// Preload for `node --test`: records every validateDocument call (input and result) made by the upstream tests.
const fs = require("node:fs");
const path = require("node:path");
const Module = require("node:module");
const out = process.env.GOLDEN_OUT;
const records = [];
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  const exp = origLoad.apply(this, arguments);
  if (!/validate-(findings|coverage-ledger)\.cjs$/.test(request) || exp.__wrapped) return exp;
  const kind = /findings/.test(request) ? "findings" : "ledger";
  const orig = exp.validateDocument;
  exp.validateDocument = function (...args) {
    const result = orig.apply(this, args);
    try { records.push({ kind, input: JSON.stringify(args[0]), errors: [...result] }); } catch {}
    return result;
  };
  exp.__wrapped = true;
  return exp;
};
process.on("exit", () => { if (out) fs.writeFileSync(out, JSON.stringify(records)); });
