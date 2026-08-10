// Tokenizer parity test: asserts normalizePath(path) === expect for every canonical vector.
// Source of truth: ../tokenize.vectors.json (shared across all Nemesis Shield SDKs).
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { normalizePath } from "./lib/shape.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, "..", "tokenize.vectors.json");
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8")).normalizePath;

let pass = 0;
const failures = [];
for (const { path, expect } of vectors) {
  const got = normalizePath(path);
  if (got === expect) pass++;
  else failures.push({ path, expect, got });
}

for (const f of failures) {
  console.error(`FAIL  ${JSON.stringify(f.path)}\n  expect ${JSON.stringify(f.expect)}\n  got    ${JSON.stringify(f.got)}`);
}
console.log(`${pass}/${vectors.length} pass`);
process.exit(failures.length ? 1 : 0);
