// LLM Guard for Node - OWASP-LLM-Top-10 detection with the HashLR ML classifier shared across every
// Nemesis Shield SDK. Feature buckets are fnv1a(feature) % dim (the same hash used for HTTP sketches),
// so scores match every other language byte-for-byte. Char n-grams over a canonicalized
// (de-leetspeaked, ASCII-alnum) form catch obfuscation ("1gn0re") the regex layer misses.

import { readFileSync } from "node:fs";
import { verify as edVerify, createPublicKey } from "node:crypto";
import { fnv1a } from "./shape.js";

const model = JSON.parse(readFileSync(new URL("./ml_weights.json", import.meta.url), "utf8"));
const DIM = model.dim; // feature space is fixed across versions - only weights/bias/thresholds swap
// Swappable model state (mutable so refreshModel() can hot-swap a newer published version in place).
let BIAS = model.bias;
let WEIGHTS = model.weights;
export let ML_BLOCK_THRESHOLD = model.blockThreshold ?? 0.85;
export let ML_FLAG_THRESHOLD = model.flagThreshold ?? 0.45;
export let MODEL_VERSION = Number(model.version ?? 1);

// Ed25519 public key (hex) that signs published models. Cloud pulls MUST carry a valid signature over
// the exact bytes; unsigned or tampered bundles are rejected and the embedded model is kept.
const MODEL_PUBLIC_KEY_HEX = "79d81a3b41966b379a9ba719155b8713f70bb341c3e8fab09fd5563a59893d28";
// SubjectPublicKeyInfo DER prefix for a raw Ed25519 public key (RFC 8410) - wrap the 32 raw bytes.
const _SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
function _verifyModelSignature(raw, sigB64) {
  if (!MODEL_PUBLIC_KEY_HEX) return true; // no key pinned - version gate + HTTPS still apply
  if (!sigB64) return false; // key pinned but bundle unsigned - reject
  try {
    const der = Buffer.concat([_SPKI_PREFIX, Buffer.from(MODEL_PUBLIC_KEY_HEX, "hex")]);
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    return edVerify(null, raw, key, Buffer.from(sigB64, "base64"));
  } catch {
    return false;
  }
}

/**
 * Hot-swap the HashLR model from a cloud URL if a newer signed version is published, so the model can
 * be retrained and pushed centrally without redeploying the SDK. Returns the new version number if
 * updated, else null. Fail-safe: on any error the current (embedded) model is kept unchanged.
 * URL defaults to env NEMESIS_MODEL_URL.
 */
export async function refreshModel(url = process.env.NEMESIS_MODEL_URL, { timeoutMs = 5000 } = {}) {
  if (!url) return null;
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeoutMs);
    const res = await fetch(url, { signal: ctl.signal });
    clearTimeout(t);
    if (!res.ok) return null;
    const raw = Buffer.from(await res.arrayBuffer());
    const sig = res.headers.get("x-model-signature");
    if (!_verifyModelSignature(raw, sig)) return null; // integrity gate
    const m = JSON.parse(raw.toString("utf8"));
    if (Number(m.version ?? 0) <= MODEL_VERSION || Number(m.dim ?? DIM) !== DIM) return null; // version/dim gate
    WEIGHTS = m.weights;
    BIAS = m.bias;
    MODEL_VERSION = Number(m.version);
    if (m.blockThreshold != null) ML_BLOCK_THRESHOLD = m.blockThreshold;
    if (m.flagThreshold != null) ML_FLAG_THRESHOLD = m.flagThreshold;
    return MODEL_VERSION;
  } catch {
    return null;
  }
}

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
