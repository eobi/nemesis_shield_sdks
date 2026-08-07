// The exercise engine: turn discovered endpoints into realistic traffic. It authenticates once, then
// walks every route generating plausible inputs (from OpenAPI schemas + field-name heuristics, refined
// by the LLM when available), handling file uploads and reusing ids returned by earlier calls so CRUD
// flows chain. This is the traffic Nemesis Shield learns from - the more of the app it touches, the
// sooner the baseline is complete and you can enforce.

import { request } from "./http.mjs";

const rand = (() => { let s = 0x9e3779b9; return () => ((s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff); })();
const pick = (arr) => arr[Math.floor(rand() * arr.length)];

// ── Value generation ────────────────────────────────────────────────────────
function heuristicString(name = "") {
  const n = name.toLowerCase();
  if (/email/.test(n)) return `learn.${Math.floor(rand() * 1e5)}@example.com`;
  if (/pass(word)?|secret/.test(n)) return "Learn-Test-1234!";
  if (/first.?name/.test(n)) return "Ada";
  if (/last.?name|surname/.test(n)) return "Learner";
  if (/user.?name|handle|login/.test(n)) return `learner_${Math.floor(rand() * 1e4)}`;
  if (/name|title|label/.test(n)) return "Nemesis Learn sample";
  if (/phone|mobile|tel/.test(n)) return "+15551230000";
  if (/url|link|website|href/.test(n)) return "https://example.com/resource";
  if (/uuid|guid/.test(n)) return uuid();
  if (/(^|_)id$/.test(n) || /_id$/.test(n)) return uuid();
  if (/slug/.test(n)) return "learn-sample";
  if (/date|_at$|time/.test(n)) return new Date(0).toISOString();
  if (/color|colour/.test(n)) return "#3b82f6";
  if (/country/.test(n)) return "US";
  if (/currency/.test(n)) return "USD";
  if (/amount|price|total|balance/.test(n)) return "42.00";
  if (/code|token|otp/.test(n)) return "123456";
  if (/description|body|content|message|comment|note/.test(n)) return "A representative sample value produced by Nemesis Learn.";
  if (/search|q|query|term/.test(n)) return "test";
  return "learn-sample";
}
function uuid() { return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => { const r = (rand() * 16) | 0; return (c === "x" ? r : (r & 0x3) | 0x8).toString(16); }); }

// Generate a value from an OpenAPI-ish schema. `ids` is a pool of ids seen in responses (for realism).
export function genFromSchema(schema, name = "", ids = [], depth = 0) {
  if (!schema || depth > 6) return heuristicString(name);
  if (schema.example !== undefined) return schema.example;
  if (Array.isArray(schema.enum) && schema.enum.length) return schema.enum[0];
  if (schema.default !== undefined) return schema.default;
  const merged = schema.allOf ? Object.assign({}, ...schema.allOf.map((s) => s)) : schema.oneOf?.[0] || schema.anyOf?.[0] || schema;
  const type = merged.type || (merged.properties ? "object" : merged.items ? "array" : undefined);
  switch (type) {
    case "object": {
      const o = {};
      const props = merged.properties || {};
      const required = new Set(merged.required || []);
      for (const [k, v] of Object.entries(props)) { if (required.has(k) || Object.keys(o).length < 8) o[k] = genFromSchema(v, k, ids, depth + 1); }
      return o;
    }
    case "array": return [genFromSchema(merged.items || {}, name, ids, depth + 1)];
    case "integer": return Number.isFinite(merged.minimum) ? merged.minimum : /page|limit|count|size/.test(name) ? 1 : 42;
    case "number": return merged.minimum ?? 42.5;
    case "boolean": return true;
    case "string":
    default: {
      const fmt = merged.format;
      if (fmt === "email") return heuristicString("email");
      if (fmt === "uuid") return ids.length && /id/i.test(name) ? pick(ids) : uuid();
      if (fmt === "date-time") return new Date(0).toISOString();
      if (fmt === "date") return "1970-01-01";
      if (fmt === "uri" || fmt === "url") return "https://example.com/resource";
      if (fmt === "binary" || fmt === "byte") return "__FILE__";
      if (/(^|_)id$/i.test(name) && ids.length) return pick(ids);
      return heuristicString(name);
    }
  }
}

// ── Auth ────────────────────────────────────────────────────────────────────
export async function login(base, session, config, log) {
  if (!config.loginUrl) return false;
  const url = config.loginUrl.startsWith("http") ? config.loginUrl : join2(base, config.loginUrl);
  let body = config.loginBody;
  if (typeof body === "string") { try { body = JSON.parse(body); } catch { /* keep string */ } }
  const res = await request(config.loginMethod || "POST", url, { session, json: typeof body === "object" ? body : undefined, body: typeof body === "string" ? body : undefined, timeoutMs: 12000 });
  // Capture a bearer token if the response returns one (common JSON shapes).
  const tok = res.json && (res.json.token || res.json.access_token || res.json.accessToken || res.json.jwt || res.json.data?.token);
  if (tok) session.headers.authorization = `Bearer ${tok}`;
  const ok = res.ok || (res.status >= 200 && res.status < 400) || !!tok || !!session.cookieHeader();
  log?.(`  auth: ${config.loginMethod || "POST"} ${config.loginUrl} -> ${res.status}${tok ? " (bearer captured)" : session.cookieHeader() ? " (session cookie)" : ""}`);
  return ok;
}

// ── Build one request ───────────────────────────────────────────────────────
async function buildRequest(ep, base, ids, llm) {
  // Path params
  let path = ep.path;
  const pathParams = (ep.params || []).filter((p) => p.in === "path");
  const inferred = [...path.matchAll(/[:{<]([a-zA-Z0-9_]+)[}>]?/g)].map((m) => m[1]);
  const names = new Set([...pathParams.map((p) => p.name), ...inferred]);
  for (const nm of names) {
    const schema = pathParams.find((p) => p.name === nm)?.schema;
    let val = schema ? genFromSchema(schema, nm, ids) : (/id/i.test(nm) && ids.length ? pick(ids) : /id/i.test(nm) ? "1" : heuristicString(nm));
    val = encodeURIComponent(String(val));
    path = path.replace(new RegExp(`\\{${nm}\\}|:${nm}\\b|<${nm}>`, "g"), val);
  }

  // Query params
  const qp = (ep.params || []).filter((p) => p.in === "query" && (p.required || rand() < 0.5));
  const qs = new URLSearchParams();
  for (const p of qp) qs.set(p.name, String(genFromSchema(p.schema, p.name, ids)));

  // Body / form / upload
  let json, form, files = [];
  if (ep.form) {
    if (ep.method === "GET" || String(ep.form.method || "").toUpperCase() === "GET") {
      // A GET form submits its fields as the query string - never a body.
      for (const f of ep.form.fields) if (f.type !== "file") qs.set(f.name, String(heuristicString(f.name)));
    } else {
      const fd = new FormData();
      let hasFile = false;
      for (const f of ep.form.fields) {
        if (f.type === "file") { fd.append(f.name, sampleFile(f.name)); hasFile = true; }
        else fd.append(f.name, String(heuristicString(f.name)));
      }
      form = fd; if (hasFile) files.push("form-upload");
    }
  } else if (ep.body) {
    let obj = ep.body.schema ? genFromSchema(ep.body.schema, "", ids) : {};
    if (llm) obj = (await refineWithLlm(llm, ep, obj)) || obj;
    const { fixed, uploads } = extractFiles(obj);
    if (ep.body.contentType === "multipart/form-data" || uploads.length) {
      const fd = new FormData();
      for (const [k, v] of Object.entries(fixed)) fd.append(k, typeof v === "object" ? JSON.stringify(v) : String(v));
      for (const u of uploads) { fd.append(u, sampleFile(u)); files.push(u); }
      form = fd;
    } else {
      json = fixed;
    }
  }
  const url = join2(base, path) + (qs.toString() ? `?${qs}` : "");
  return { url, json, form, files };
}

// Replace "__FILE__" markers with real sample files (returns cleaned object + list of file fields).
function extractFiles(obj) {
  const uploads = [];
  const walk = (o) => {
    if (o && typeof o === "object" && !Array.isArray(o)) {
      for (const [k, v] of Object.entries(o)) { if (v === "__FILE__") { uploads.push(k); delete o[k]; } else walk(v); }
    } else if (Array.isArray(o)) o.forEach(walk);
  };
  walk(obj);
  return { fixed: obj, uploads };
}
function sampleFile(name = "file") {
  // A tiny 1x1 transparent PNG for image-ish fields, else a small text file. Realistic enough to learn.
  if (/image|photo|avatar|picture|img|logo/i.test(name)) {
    const b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
    return new File([Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))], "sample.png", { type: "image/png" });
  }
  return new File([`Nemesis Learn sample upload for "${name}".\n`], "sample.txt", { type: "text/plain" });
}

async function refineWithLlm(llm, ep, draft) {
  const sys = "You produce realistic, SAFE sample values for exercising an app's API during a learning/baseline run. Never inject attacks. Return ONLY a JSON object with the same keys as the draft, values realistic for the field names and endpoint. Keep any __FILE__ markers as-is.";
  const user = `Endpoint: ${ep.method} ${ep.path}\nDraft body JSON:\n${JSON.stringify(draft).slice(0, 2000)}\nReturn a realistic filled version.`;
  const out = await llm.completeJson(sys, user);
  return out && typeof out === "object" ? out : null;
}

// ── Run ─────────────────────────────────────────────────────────────────────
export async function runExercise({ endpoints, base, session, config, llm, log }) {
  const ids = [];
  const results = [];
  // Order: safe reads first, then creates/updates, deletes last. Auth already done by the caller.
  const order = { GET: 0, POST: 1, PUT: 2, PATCH: 3, DELETE: 4 };
  const list = [...endpoints].sort((a, b) => (order[a.method] ?? 5) - (order[b.method] ?? 5)).slice(0, config.maxRequests);

  let i = 0;
  const worker = async () => {
    while (i < list.length) {
      const ep = list[i++];
      try {
        const req = await buildRequest(ep, base, ids, llm);
        const res = await request(ep.method, req.url, { session, json: req.json, form: req.form, timeoutMs: config.timeoutMs });
        harvestIds(res.json, ids);
        results.push({ method: ep.method, path: ep.path, url: req.url, status: res.status, ms: res.ms, source: ep.source, files: req.files, error: res.error });
        log?.(`  ${statusMark(res.status)} ${ep.method.padEnd(6)} ${new URL(req.url).pathname}${req.files.length ? " ⇧upload" : ""} -> ${res.status || res.error} ${res.ms}ms`);
      } catch (e) {
        results.push({ method: ep.method, path: ep.path, status: 0, error: String(e?.message || e), source: ep.source });
      }
      if (config.delayMs) await sleep(config.delayMs);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, config.concurrency) }, worker));
  return results;
}

function harvestIds(json, ids) {
  if (!json || typeof json !== "object") return;
  const visit = (o, d = 0) => {
    if (d > 4 || !o || typeof o !== "object") return;
    for (const [k, v] of Object.entries(o)) {
      if ((/^id$/i.test(k) || /_id$/i.test(k)) && (typeof v === "string" || typeof v === "number")) { const s = String(v); if (s.length <= 64 && !ids.includes(s)) ids.push(s); }
      else if (v && typeof v === "object") visit(v, d + 1);
    }
    if (ids.length > 200) ids.length = 200;
  };
  visit(Array.isArray(json) ? { list: json } : json);
}

const statusMark = (s) => (!s ? "✗" : s < 300 ? "✓" : s < 400 ? "↺" : s < 500 ? "•" : "✗");
const join2 = (base, p) => base.replace(/\/$/, "") + (String(p).startsWith("/") ? p : "/" + p);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
