// Route discovery from three independent sources, merged. Any one is enough; together they get broad
// coverage of an app in ANY language/framework:
//   1. OpenAPI/Swagger  — the strongest signal (methods, params, body schemas, security). Zero guessing.
//   2. HTML crawl       — same-origin links + <form> actions, for server-rendered apps without a spec.
//   3. Repo static scan — regex route patterns across common frameworks, when pointed at code.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { request } from "./http.mjs";

const OPENAPI_PATHS = ["/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json", "/api/openapi.json", "/api-docs/swagger.json", "/docs/openapi.json"];

// ── 1. OpenAPI ──────────────────────────────────────────────────────────────
export async function discoverOpenApi(base, session) {
  for (const p of OPENAPI_PATHS) {
    const res = await request("GET", join2(base, p), { session, timeoutMs: 8000 });
    if (res.ok && res.json && (res.json.paths || res.json.openapi || res.json.swagger)) {
      return { spec: res.json, endpoints: parseOpenApi(res.json), specUrl: join2(base, p) };
    }
  }
  return { spec: null, endpoints: [] };
}

function parseOpenApi(spec) {
  const out = [];
  const resolve = (o) => (o && o.$ref ? deref(spec, o.$ref) : o);
  for (const [path, item] of Object.entries(spec.paths || {})) {
    for (const method of ["get", "post", "put", "patch", "delete"]) {
      const op = item[method];
      if (!op) continue;
      const params = [...(item.parameters || []), ...(op.parameters || [])].map(resolve).map((p) => ({ name: p.name, in: p.in, required: !!p.required, schema: resolve(p.schema) }));
      let body = null;
      const rb = resolve(op.requestBody);
      if (rb && rb.content) {
        const ct = rb.content["application/json"] ? "application/json" : rb.content["multipart/form-data"] ? "multipart/form-data" : rb.content["application/x-www-form-urlencoded"] ? "application/x-www-form-urlencoded" : Object.keys(rb.content)[0];
        body = { contentType: ct, schema: inlineRefs(spec, resolve(rb.content[ct]?.schema)) };
      }
      out.push({ method: method.toUpperCase(), path, source: "openapi", params, body, security: op.security || spec.security || [] });
    }
  }
  return out;
}

function deref(spec, ref) {
  const parts = ref.replace(/^#\//, "").split("/");
  let cur = spec;
  for (const k of parts) cur = cur?.[decodeURIComponent(k.replace(/~1/g, "/").replace(/~0/g, "~"))];
  return cur;
}
// Inline $refs one level deep-ish so the value generator sees real shapes (bounded to avoid cycles).
function inlineRefs(spec, schema, depth = 0) {
  if (!schema || depth > 6) return schema;
  if (schema.$ref) return inlineRefs(spec, deref(spec, schema.$ref), depth + 1);
  const s = { ...schema };
  if (s.properties) { s.properties = Object.fromEntries(Object.entries(s.properties).map(([k, v]) => [k, inlineRefs(spec, v, depth + 1)])); }
  if (s.items) s.items = inlineRefs(spec, s.items, depth + 1);
  for (const key of ["allOf", "anyOf", "oneOf"]) if (Array.isArray(s[key])) s[key] = s[key].map((v) => inlineRefs(spec, v, depth + 1));
  return s;
}

// ── 2. HTML crawl ───────────────────────────────────────────────────────────
export async function crawl(base, session, { maxPages = 40 } = {}) {
  const origin = new URL(base).origin;
  const seen = new Set(), queue = [normalizeUrl(base)], endpoints = [], links = [];
  while (queue.length && seen.size < maxPages) {
    const url = queue.shift();
    if (seen.has(url)) continue;
    seen.add(url);
    const res = await request("GET", url, { session, timeoutMs: 8000 });
    endpoints.push({ method: "GET", path: pathOf(url), source: "crawl", params: [], body: null });
    if (!res.text || !(res.headers?.["content-type"] || "").includes("html")) continue;
    for (const href of extractLinks(res.text)) {
      const abs = safeUrl(href, url);
      if (abs && abs.startsWith(origin) && !seen.has(normalizeUrl(abs)) && !isAsset(abs)) { queue.push(normalizeUrl(abs)); links.push(abs); }
    }
    for (const form of extractForms(res.text, url)) endpoints.push(form);
  }
  return { endpoints: dedupe(endpoints), pages: seen.size };
}

function extractLinks(html) {
  const out = [];
  const re = /<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)["']/gi;
  let m;
  while ((m = re.exec(html))) out.push(m[1]);
  return out;
}
function extractForms(html, pageUrl) {
  const out = [];
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let fm;
  while ((fm = formRe.exec(html))) {
    const attrs = fm[1], inner = fm[2];
    const action = (attrs.match(/\baction\s*=\s*["']([^"']*)["']/i) || [])[1] || pageUrl;
    const method = ((attrs.match(/\bmethod\s*=\s*["']([^"']*)["']/i) || [])[1] || "GET").toUpperCase();
    const enctype = (attrs.match(/\benctype\s*=\s*["']([^"']*)["']/i) || [])[1] || "";
    const fields = [];
    const inRe = /<(input|select|textarea)\b([^>]*)>/gi;
    let im;
    while ((im = inRe.exec(inner))) {
      const a = im[2];
      const name = (a.match(/\bname\s*=\s*["']([^"']*)["']/i) || [])[1];
      if (!name) continue;
      const type = (a.match(/\btype\s*=\s*["']([^"']*)["']/i) || [])[1] || (im[1].toLowerCase() === "textarea" ? "textarea" : "text");
      fields.push({ name, type });
    }
    const abs = safeUrl(action, pageUrl);
    out.push({ method, path: pathOf(abs || action), source: "crawl-form", params: [], body: null, form: { action: abs || action, method, enctype, fields } });
  }
  return out;
}

// ── 3. Repo static scan ─────────────────────────────────────────────────────
const ROUTE_PATTERNS = [
  // Node / Express / Fastify / Koa / NestJS
  { re: /\b(?:app|router|fastify|server)\.(get|post|put|patch|delete|all)\s*\(\s*[`'"]([^`'"]+)[`'"]/gi, m: 1, p: 2 },
  { re: /@(Get|Post|Put|Patch|Delete)\s*\(\s*[`'"]([^`'"]*)[`'"]/g, m: 1, p: 2 }, // NestJS / Spring-ish decorators
  // Python — FastAPI / Flask
  { re: /@\w+\.(get|post|put|patch|delete)\s*\(\s*[`'"]([^`'"]+)[`'"]/gi, m: 1, p: 2 },
  { re: /@\w+\.route\s*\(\s*[`'"]([^`'"]+)[`'"]/gi, m: null, p: 1 },
  // Django
  { re: /\bpath\s*\(\s*[`'"]([^`'"]*)[`'"]/g, m: null, p: 1 },
  { re: /\bre_path\s*\(\s*r?[`'"]\^?([^`'"$]*)/g, m: null, p: 1 },
  // Rails
  { re: /\b(get|post|put|patch|delete)\s+[`'"]([^`'"]+)[`'"]/gi, m: 1, p: 2 },
  // Laravel / PHP
  { re: /Route::(get|post|put|patch|delete|any)\s*\(\s*[`'"]([^`'"]+)[`'"]/gi, m: 1, p: 2 },
  // Spring
  { re: /@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*)?[`'"]([^`'"]+)[`'"]/g, m: null, p: 1 },
  // Go — net/http, chi, gorilla, gin, echo
  { re: /\.(GET|POST|PUT|PATCH|DELETE|HandleFunc|Handle)\s*\(\s*[`'"]([^`'"]+)[`'"]/g, m: 1, p: 2 },
];
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "vendor", "__pycache__", "target", ".venv", "venv", "out", "coverage"]);
const CODE_EXT = /\.(js|mjs|cjs|ts|tsx|jsx|py|rb|php|java|go|kt|cs)$/;

export function discoverRepo(dir, { maxFiles = 4000 } = {}) {
  const endpoints = [];
  let scanned = 0;
  const walk = (d) => {
    let entries;
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (scanned >= maxFiles) return;
      const full = join(d, e.name);
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name) && !e.name.startsWith(".")) walk(full); continue; }
      if (!CODE_EXT.test(e.name)) continue;
      scanned++;
      let src;
      try { src = readFileSync(full, "utf8"); } catch { continue; }
      const file = relative(dir, full);
      for (const pat of ROUTE_PATTERNS) {
        pat.re.lastIndex = 0;
        let m;
        while ((m = pat.re.exec(src))) {
          const method = pat.m ? m[pat.m].toUpperCase() : "GET";
          let path = m[pat.p];
          if (!path || !/^[\/:a-z]/i.test(path)) continue;
          if (!path.startsWith("/")) path = "/" + path;
          endpoints.push({ method: method === "ALL" || method === "ANY" || method === "HANDLE" || method === "HANDLEFUNC" || method === "REQUEST" ? "GET" : method, path, source: `repo:${file}`, params: [], body: null });
        }
      }
    }
  };
  walk(dir);
  return { endpoints: dedupe(endpoints), filesScanned: scanned };
}

// ── merge / util ────────────────────────────────────────────────────────────
export function mergeEndpoints(...lists) {
  const map = new Map();
  for (const ep of lists.flat()) {
    const key = `${ep.method} ${ep.path}`;
    if (!map.has(key)) map.set(key, ep);
    else { // prefer the entry that carries a schema/body/form (richer)
      const cur = map.get(key);
      if ((ep.body || ep.form || ep.params?.length) && !(cur.body || cur.form || cur.params?.length)) map.set(key, ep);
    }
  }
  return [...map.values()];
}
function dedupe(eps) { return mergeEndpoints(eps); }

const join2 = (base, p) => base.replace(/\/$/, "") + (p.startsWith("/") ? p : "/" + p);
const normalizeUrl = (u) => { try { const x = new URL(u); x.hash = ""; return x.toString(); } catch { return u; } };
const pathOf = (u) => { try { return new URL(u).pathname + (new URL(u).search || ""); } catch { return u; } };
const safeUrl = (href, baseUrl) => { try { return new URL(href, baseUrl).toString(); } catch { return null; } };
const isAsset = (u) => /\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map|pdf|zip|mp4|webp)(\?|$)/i.test(u);
