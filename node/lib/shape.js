// Local, privacy-preserving request-sketch computation. The shape is a REQUEST signature
// (method + normalized route + query param kinds + auth) — it deliberately excludes response status,
// because enforcement decides whether to block BEFORE the response exists. The value taxonomy and
// shape-input construction match the shared engine byte-for-byte, so a Node app and a Python/Go/PHP
// app produce IDENTICAL shape hashes (cross-language baseline sharing).

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const URLRE = /^https?:\/\/\S+$/i;
const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-f:]+:[0-9a-f:]+$/i;
const INT = /^-?\d+$/;
const FLOATRE = /^-?\d*\.\d+$/;
const DATE = /^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?/;
const JWT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const HEX = /^[0-9a-f]+$/i;
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
const ALPHA = /^[A-Za-z]+$/;
const ALNUM = /^[A-Za-z0-9]+$/;

function kindOf(v) {
  if (v == null || v === "") return "empty";
  if (typeof v === "boolean") return "bool";
  const s = String(v);
  if (s === "") return "empty";
  if (UUID.test(s)) return "uuid";
  if (EMAIL.test(s)) return "email";
  if (URLRE.test(s)) return "url";
  if (IPV4.test(s)) return "ipv4";
  if (IPV6.test(s)) return "ipv6";
  if (JWT.test(s)) return "jwt";
  if (DATE.test(s)) return "date";
  if (INT.test(s)) return "int";
  if (FLOATRE.test(s)) return "float";
  if (s.length >= 16 && HEX.test(s)) return "hex";
  if (s.length >= 16 && B64.test(s)) return "base64";
  if (ALPHA.test(s)) return "alpha";
  if (ALNUM.test(s)) return "alnum";
  return "string";
}

export function normalizePath(path) {
  const clean = String(path || "/").split("?")[0].split("#")[0];
  const out = clean
    .split("/")
    .map((seg) => {
      if (seg === "") return seg;
      if (seg.indexOf("..") >= 0) return "{traversal}"; // path-traversal segment (also keeps ".." out of telemetry)
      const k = kindOf(seg);
      if (k === "int" || k === "float") return "{int}";
      if (k === "uuid") return "{uuid}";
      if (k === "hex") return "{hex}";
      if (k === "base64") return "{token}";
      if (k === "alnum") return seg.length >= 12 ? "{id}" : seg;
      return seg;
    })
    .join("/");
  return out || "/";
}

// 32-bit FNV-1a over a stable string -> 8-hex-char digest.
export function fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/** Build a request sketch. `query` is an object of query params (values -> kinds only). */
export function buildSketch({ method, path, query = {}, authenticated = false, status = 0 }) {
  const route = normalizePath(path);
  const params = Object.keys(query || {})
    .sort()
    .map((name) => {
      const val = query[name];
      const isArr = Array.isArray(val);
      return { name, kind: kindOf(isArr ? val[0] : val), nested: isArr };
    });
  // Canonical shape input: keys SORTED (auth, method, params, route); params [name, kind, nested].
  const canonical = JSON.stringify({
    auth: authenticated ? 1 : 0,
    method: String(method || "GET").toUpperCase(),
    params: params.map((p) => [p.name, p.kind, p.nested ? 1 : 0]),
    route,
  });
  return {
    v: 1,
    route,
    method: String(method || "GET").toUpperCase(),
    params,
    authenticated: Boolean(authenticated),
    status,
    shape: fnv1a(canonical),
  };
}
