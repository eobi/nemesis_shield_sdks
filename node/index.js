// Nemesis Shield — Sentinel SDK for Node. Native SDK: computes a privacy-preserving request shape
// locally, learns your app's normal behavior, and — in enforce mode — BLOCKS off-baseline requests
// (auth bypass, path traversal, scanners, unusual methods) before your routes run. Fail-open.
//
//   import { sentinel } from "@nemesis-shield/sentinel/express";
//   app.use(sentinel({ token: process.env.NEMESIS_TOKEN }));
//
// Framework adapters: "@nemesis-shield/sentinel/express" | "/fastify" | "/koa".
export { sentinel } from "./express.js";
export { sentinelFastify } from "./fastify.js";
export { sentinelKoa } from "./koa.js";
export { SentinelClient } from "./lib/client.js";
export { buildSketch, normalizePath as pathShape } from "./lib/shape.js";

const LLM_URL = "https://shield.nemesislabs.xyz/api/v1/llm";

/** Report an LLM exchange for OWASP-LLM behavioral protection. Fire-and-forget. */
export async function reportLLM(token, exchange, opts = {}) {
  if (!token || !exchange) return;
  try {
    await fetch(opts.endpoint || LLM_URL, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ exchanges: [exchange] }),
    });
  } catch { /* fail open */ }
}
