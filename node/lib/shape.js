// Local, privacy-preserving request-sketch computation. The shape is a REQUEST signature
// (method + normalized route + query param kinds + auth) — it deliberately excludes response status,
// because enforcement decides whether to block BEFORE the response exists. Deterministic; only needs
// to be internally consistent (the server stores whatever shape the SDK sends).

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX = /^[0-9a-f]{16,}$/i;
const INT = /^\d+$/;

export function normalizePath(path) {
  return String(path || "/")
    .split("?")[0]
    .split("/")
    .map((seg) => (INT.test(seg) ? "{int}" : UUID.test(seg) ? "{uuid}" : HEX.test(seg) ? "{hex}" : seg))
    .join("/") || "/";
}

function kindOf(v) {
  if (v == null) return "null";
  const s = String(v);
  if (INT.test(s)) return "int";
  if (UUID.test(s)) return "uuid";
  if (/^-?\d+\.\d+$/.test(s)) return "float";
  if (/^(true|false)$/i.test(s)) return "bool";
  if (/^[0-9a-f]{16,}$/i.test(s)) return "hex";
  if (/@/.test(s)) return "email";
  return "string";
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
    .map((name) => ({ name, kind: kindOf(query[name]) }));
  const canonical = JSON.stringify({
    route,
    method: String(method || "GET").toUpperCase(),
    params: params.map((p) => [p.name, p.kind]),
    auth: authenticated ? 1 : 0,
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
