// Local, privacy-preserving request-sketch computation. The shape is a REQUEST signature
// (method + normalized route + query param kinds + auth) - it deliberately excludes response status,
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
// A run of 7+ letters => reads like a word / route name, not an opaque id/token.
const WORD = /[A-Za-z]{7,}/;
// A hostname path segment (network-zone routes like example.com, sub.example.co.uk). Path segments
// almost never contain dots except hostnames, so collapsing these to {domain} stops per-domain shape
// explosion. Deliberately LOOKAHEAD-FREE so it ports byte-identically to RE2 engines (Go, Rust regex).
const DOMAIN = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i;
// A digit, used to tell a generated composite id (inc_ip_1_2_3_4_178..) from a snake_case word.
const DIGIT = /\d/;

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
  if (s.length >= 16 && B64.test(s) && !WORD.test(s)) return "base64";
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
      if (k === "alnum") return seg.length >= 12 && !WORD.test(seg) ? "{id}" : seg;
      // Hostnames (network-zone routes) collapse to {domain}; underscored generated ids that carry a
      // digit (or are very long) collapse to {id}. Route names are single words or kebab-case and never
      // carry underscores, so kebab segments like "iso-27001" stay literal.
      if (DOMAIN.test(seg)) return "{domain}";
      if (seg.indexOf("_") >= 0 && (DIGIT.test(seg) || seg.length >= 20)) return "{id}";
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

// Analytics / click-tracking query params carry no application logic and are the main cause of shape
// explosion (every ad/campaign link adds different ones). Stripped from the signature so a UTM'd
// request matches the bare route, while real params (and any attack in them) stay modeled. Shared,
// identical across every Nemesis Shield SDK so the shape hash matches everywhere.
const TRACKING_PREFIXES = ["utm_", "mtm_", "pk_", "hsa_", "matomo_", "piwik_", "ga_"];
const TRACKING_EXACT = new Set(["gclid", "gbraid", "wbraid", "dclid", "gclsrc", "fbclid", "msclkid", "twclid", "ttclid", "yclid", "igshid", "scid", "wickedid", "_ga", "_gl", "_hsenc", "_hsmi", "mc_cid", "mc_eid", "vero_id", "vero_conv", "oly_anon_id", "oly_enc_id", "_openstat", "rb_clickid", "s_cid", "epik", "sccid"]);
export function isTrackingParam(name) {
  const n = String(name).toLowerCase();
  return TRACKING_PREFIXES.some((p) => n.startsWith(p)) || TRACKING_EXACT.has(n);
}

/** Build a request sketch. `query` is an object of query params (values -> kinds only). */
export function buildSketch({ method, path, query = {}, authenticated = false, status = 0 }) {
  const route = normalizePath(path);
  const params = Object.keys(query || {})
    .filter((name) => !isTrackingParam(name))
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
