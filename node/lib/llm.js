// LLM Guard for Node — OWASP-LLM-Top-10 detection with the HashLR ML classifier shared across every
// Nemesis Shield SDK. Feature buckets are fnv1a(feature) % dim (the same hash used for HTTP sketches),
// so scores match every other language byte-for-byte. Char n-grams over a canonicalized
// (de-leetspeaked, ASCII-alnum) form catch obfuscation ("1gn0re") the regex layer misses.

import { readFileSync } from "node:fs";
import { fnv1a } from "./shape.js";

const model = JSON.parse(readFileSync(new URL("./ml_weights.json", import.meta.url), "utf8"));
const DIM = model.dim;
const BIAS = model.bias;
const WEIGHTS = model.weights;
export const ML_BLOCK_THRESHOLD = model.blockThreshold ?? 0.85;
export const ML_FLAG_THRESHOLD = model.flagThreshold ?? 0.45;

const LEET = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "8": "b", "|": "i" };
const INJECTION = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts?|context)/i,
  /disregard\s+(the\s+)?(above|previous|system)/i,
  /(reveal|show|print|repeat)\s+(your|the)\s+(system\s+)?(prompt|instructions)/i,
  /\bDAN\b|do\s+anything\s+now|developer\s+mode|jailbreak/i,
  /(bypass|ignore|disable)\s+(your\s+)?(safety|content\s+policy|guardrails?)/i,
];

function canon(text) {
  let out = "";
  for (const raw of text.toLowerCase()) {
    const c = LEET[raw] ?? raw;
    if (c >= "a" && c <= "z") out += c;
    else if (c >= "0" && c <= "9") out += c;
  }
  return out;
}

const bucket = (s) => parseInt(fnv1a(s), 16) % DIM;

function features(text) {
  const b = new Set();
  const ws = text.toLowerCase().match(/[a-z0-9']+/g) ?? [];
  for (const w of ws) b.add(bucket("w:" + w));
  for (let i = 0; i < ws.length - 1; i++) b.add(bucket("b:" + ws[i] + " " + ws[i + 1]));
  const c = canon(text);
  for (const n of [3, 4, 5]) for (let i = 0; i + n <= c.length; i++) b.add(bucket("c" + n + ":" + c.slice(i, i + n)));
  if (text.length > 2000) b.add(bucket("e:long"));
  let na = 0;
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) > 127) na++;
  if (na > 3) b.add(bucket("e:nonascii"));
  return b;
}

/** Probability (0..1) that `text` is a prompt-injection / jailbreak attempt. */
export function mlInjectionScore(text) {
  let z = BIAS;
  for (const bk of features(text)) {
    const w = WEIGHTS[String(bk)];
    if (w) z += w;
  }
  if (z < -30) return 0;
  if (z > 30) return 1;
  return 1 / (1 + Math.exp(-z));
}

/**
 * Guard a prompt: regex rules first, then the HashLR ML for obfuscation.
 * Returns { blocked, severity, kind, score, owasp }. `enforce` gates blocking.
 */
export function guardLLM(prompt, enforce = false) {
  for (const re of INJECTION) {
    if (re.test(prompt)) return { blocked: enforce, severity: "high", kind: "prompt_injection", score: 1, owasp: "LLM01" };
  }
  const s = mlInjectionScore(prompt);
  if (s >= ML_BLOCK_THRESHOLD) return { blocked: enforce, severity: "high", kind: "ml_prompt_injection", score: s, owasp: "LLM01" };
  if (s >= ML_FLAG_THRESHOLD) return { blocked: false, severity: "medium", kind: "ml_prompt_injection", score: s, owasp: "LLM01" };
  return { blocked: false, severity: "none", score: s };
}
