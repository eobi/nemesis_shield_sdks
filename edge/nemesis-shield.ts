/**
 * Nemesis Shield - Edge / Supabase SDK (Deno + Web-standard TypeScript).
 *
 * For serverless TypeScript runtimes: **Supabase Edge Functions**, Deno Deploy, Cloudflare Workers,
 * Vercel Edge. Learns the function's normal request behavior; in enforce mode BLOCKS off-baseline
 * requests (auth bypass, path traversal, scanners, unusual methods) before your handler runs.
 *
 * Supabase Edge Functions are **public by default** and usually run with the service_role key, which
 * steps outside RLS - so the function is the trust boundary with nothing on it. This wraps that
 * boundary with a positive-security allow-list.
 *
 *   import { withShield } from "./nemesis-shield.ts";
 *   Deno.serve(withShield(async (req) => new Response("ok"), {
 *     token: Deno.env.get("NEMESIS_TOKEN"),
 *   }));
 *
 * Serverless-safe: refreshes the compiled policy lazily (short TTL) on the request path, so a cold
 * isolate still enforces the current console mode with no redeploy. Fail-open, privacy-preserving -
 * ships only method + route shape + auth, never bodies or secrets.
 */

const DEFAULT_ENDPOINT = "https://shield.nemesislabs.xyz/api/v1/sketches";

// Full value taxonomy + sorted canon - byte-for-byte identical to the shared engine (node lib/shape.js)
// so an edge function and a Node/Python/Go/PHP/Ruby/Java/.NET/Rust app produce the SAME shape hash
// (cross-language baseline + threat-intel sharing). Previously this file used a reduced tokenizer, an
// unsorted canon, and never fed query params - those shapes did NOT match the backend family.
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
// A hostname segment (network-zone routes like example.com, sub.example.co.uk). Path segments almost
// never contain dots except hostnames, so collapsing these to {domain} stops per-domain shape explosion.
const DOMAIN = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i;
// A composite generated id (underscored, e.g. inc_ip_1_2_3_4_1785..., og_..._..). Route names are single
// words or kebab-case and never carry underscores, so an underscored segment with a digit (or very long)
// is an id, not a route -> {id}. Stops per-entity (incident/case/txn) shape explosion.
const COMPOSITE_ID = /_/;

function kindOf(v: unknown): string {
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

function fnv1a(s: string): string {
  let h = 0x811c9dc5 >>> 0;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i) & 0xff;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return ("0000000" + h.toString(16)).slice(-8);
}

export function normalizePath(path: string): string {
  const clean = String(path || "/").split("?")[0].split("#")[0];
  const out = clean
    .split("/")
    .map((seg) => {
      if (seg === "") return seg;
      if (seg.indexOf("..") >= 0) return "{traversal}"; // keeps ".." out of telemetry
      const k = kindOf(seg);
      if (k === "int" || k === "float") return "{int}";
      if (k === "uuid") return "{uuid}";
      if (k === "hex") return "{hex}";
      if (k === "base64") return "{token}";
      if (k === "alnum") return seg.length >= 12 && !WORD.test(seg) ? "{id}" : seg;
      if (DOMAIN.test(seg)) return "{domain}";
      if (COMPOSITE_ID.test(seg) && (/\d/.test(seg) || seg.length >= 20)) return "{id}";
      return seg;
    })
    .join("/");
  return out || "/";
}

export type Query = Record<string, string | string[]>;
interface Param {
  name: string;
  kind: string;
  nested: boolean;
}

// Analytics / click-tracking query params carry NO application logic and are the main cause of shape
// explosion (every ad/campaign/referral link adds different ones). We strip them from the signature so
// a UTM'd request matches the bare route, while real params - and any attack hidden in them - stay
// modeled. This list is shared across every SDK so the shape hash stays identical everywhere.
const TRACKING_PREFIXES = ["utm_", "mtm_", "pk_", "hsa_", "matomo_", "piwik_", "ga_"];
const TRACKING_EXACT = new Set([
  "gclid", "gbraid", "wbraid", "dclid", "gclsrc", "fbclid", "msclkid", "twclid", "ttclid", "yclid",
  "igshid", "scid", "wickedid", "_ga", "_gl", "_hsenc", "_hsmi", "mc_cid", "mc_eid", "vero_id",
  "vero_conv", "oly_anon_id", "oly_enc_id", "_openstat", "rb_clickid", "s_cid", "epik", "sccid",
]);
export function isTrackingParam(name: string): boolean {
  const n = name.toLowerCase();
  return TRACKING_PREFIXES.some((p) => n.startsWith(p)) || TRACKING_EXACT.has(n);
}

function paramsOf(query: Query): Param[] {
  return Object.keys(query || {})
    .filter((name) => !isTrackingParam(name))
    .sort()
    .map((name) => {
      const val = query[name];
      const isArr = Array.isArray(val);
      return { name, kind: kindOf(isArr ? (val as string[])[0] : val), nested: isArr };
    });
}

/** Convert URLSearchParams to a plain object (repeated keys → array), for buildSketch. */
export function queryToObject(sp: URLSearchParams): Query {
  const o: Query = {};
  for (const [k, v] of sp) {
    if (k in o) {
      const cur = o[k];
      o[k] = Array.isArray(cur) ? [...cur, v] : [cur as string, v];
    } else o[k] = v;
  }
  return o;
}

// Safe-unlock (break-glass): paths never blocked, so a still-learning baseline can't lock operators
// out. Prefix-matched. Override with the NEMESIS_SHIELD_BOOTSTRAP env (comma-separated).
const DEFAULT_BOOTSTRAP = ["/login", "/signin", "/sign-in", "/auth", "/oauth", "/session", "/wp-login.php", "/wp-admin"];
function envVar(name: string): string {
  try {
    // @ts-ignore Deno
    if (typeof Deno !== "undefined" && Deno.env?.get) return Deno.env.get(name) ?? "";
  } catch { /* not Deno */ }
  try {
    // @ts-ignore Node / Workers-with-process
    if (typeof process !== "undefined" && process.env) return process.env[name] ?? "";
  } catch { /* no process */ }
  return "";
}
export function neverBlock(path: string): boolean {
  const p = String(path || "/").split("?")[0].split("#")[0].toLowerCase();
  const env = envVar("NEMESIS_SHIELD_BOOTSTRAP").trim();
  const list = env ? env.split(",").map((s) => s.trim()).filter(Boolean) : DEFAULT_BOOTSTRAP;
  return list.some((b) => b && p.startsWith(b.toLowerCase()));
}

export interface ShieldOptions {
  token?: string;
  endpoint?: string;
  /** How long a cached policy is considered fresh, in ms (default 3000). */
  ttlMs?: number;
}

interface Sketch {
  route: string;
  method: string;
  authenticated: boolean;
  status: number;
  params: Param[];
  shape: string;
}

export class Shield {
  private token: string;
  private endpoint: string;
  private ttlMs: number;
  private mode = "observe";
  private shapes: Record<string, string> = {};
  private knownBad: Set<string> = new Set();
  private haveBaseline = false;
  private lastRefresh = 0;
  private refreshing: Promise<void> | null = null;
  private buffer: string[] = [];

  constructor(opts: ShieldOptions = {}) {
    this.token = opts.token ?? "";
    this.endpoint = opts.endpoint ?? DEFAULT_ENDPOINT;
    this.ttlMs = opts.ttlMs ?? 3000;
  }

  enforcing(): boolean {
    return this.mode === "enforce";
  }

  buildSketch(method: string, path: string, query: Query, authed: boolean, status: number): Sketch {
    const route = normalizePath(path);
    const params = paramsOf(query);
    // Canonical shape input: keys SORTED (auth, method, params, route); params [name, kind, nested].
    const canon = JSON.stringify({
      auth: authed ? 1 : 0,
      method: method.toUpperCase(),
      params: params.map((p) => [p.name, p.kind, p.nested ? 1 : 0]),
      route,
    });
    return { route, method: method.toUpperCase(), authenticated: authed, status, params, shape: fnv1a(canon) };
  }

  /** Positive-security verdict. Returns the block reason, or null to allow. */
  decide(shape: string): string | null {
    const per = this.shapes[shape];
    if (per === "allow") return null;
    if (per === "block") return "policy: blocked shape";
    if (this.knownBad.has(shape)) return "global threat intelligence";
    if (this.haveBaseline) return "off-baseline: unapproved behavior";
    return null;
  }

  record(s: Sketch): void {
    this.buffer.push(JSON.stringify(s)); // includes params (names + kinds, never values)
    if (this.buffer.length >= 25) void this.flush();
  }

  async flush(): Promise<void> {
    if (!this.buffer.length) return;
    const batch = this.buffer;
    this.buffer = [];
    await this.send(`[${batch.join(",")}]`);
  }

  async refresh(): Promise<void> {
    await this.send("[]");
    this.lastRefresh = Date.now();
  }

  /** Refresh at most once per TTL; dedupe concurrent refreshes. Serverless-safe. */
  private maybeRefresh(): Promise<void> {
    if (Date.now() - this.lastRefresh < this.ttlMs) return Promise.resolve();
    if (this.refreshing) return this.refreshing;
    this.refreshing = this.refresh().finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }

  private async send(sketchesJson: string): Promise<void> {
    if (!this.token) return;
    try {
      const res = await fetch(this.endpoint, {
        method: "POST",
        headers: { Authorization: `Bearer ${this.token}`, "Content-Type": "application/json" },
        body: `{"sketches":${sketchesJson}}`,
        signal: AbortSignal.timeout(3000),
      });
      if (res.ok) this.applyPolicy(await res.json());
    } catch {
      /* fail open */
    }
  }

  private applyPolicy(d: any): void {
    if (!d) return;
    if (typeof d.mode === "string") this.mode = d.mode;
    const pol = d.policy ?? {};
    if (pol.shapes && typeof pol.shapes === "object") {
      this.shapes = pol.shapes;
      this.haveBaseline = Object.keys(pol.shapes).length > 0;
    }
    this.knownBad = new Set(Array.isArray(pol.knownBad) ? pol.knownBad : []);
  }

  /** Wrap a Web-standard `(Request) => Response` handler with inline enforcement. */
  handler(fn: (req: Request) => Response | Promise<Response>): (req: Request) => Promise<Response> {
    return async (req: Request): Promise<Response> => {
      // FAIL-OPEN: the refresh + decision block is fully guarded. ANY throw in Shield internals
      // (policy refresh, URL parse, sketch build, decide) must NEVER 500 the customer's request — on
      // error we fall straight through to the wrapped handler. Only an explicit block returns 403.
      let url: URL | null = null;
      let query: Query = {};
      let authed = false;
      try {
        await this.maybeRefresh();
        url = new URL(req.url);
        query = queryToObject(url.searchParams);
        authed =
          req.headers.has("authorization") ||
          req.headers.has("cookie") ||
          req.headers.has("apikey") ||
          req.headers.has("x-api-key");
        // enforce, but never block the login/auth path (break-glass)
        if (this.enforcing() && !neverBlock(url.pathname)) {
          const reason = this.decide(this.buildSketch(req.method, url.pathname, query, authed, 0).shape);
          if (reason) {
            try {
              this.record(this.buildSketch(req.method, url.pathname, query, authed, 403));
              void this.flush();
            } catch {
              /* fail-open telemetry */
            }
            return new Response(JSON.stringify({ error: "blocked_by_nemesis_shield", reason }), {
              status: 403,
              headers: { "content-type": "application/json" },
            });
          }
        }
      } catch {
        /* fail-open: swallow any internal error and let the request proceed */
      }
      const res = await fn(req);
      try {
        const pathname = url ? url.pathname : new URL(req.url).pathname;
        this.record(this.buildSketch(req.method, pathname, query, authed, res.status));
        void this.flush();
      } catch {
        /* fail-open telemetry */
      }
      return res;
    };
  }
}

export function createShield(opts: ShieldOptions = {}): Shield {
  return new Shield(opts);
}

/** One-liner: `Deno.serve(withShield(handler, { token: Deno.env.get("NEMESIS_TOKEN") }))`. */
export function withShield(
  fn: (req: Request) => Response | Promise<Response>,
  opts: ShieldOptions = {},
): (req: Request) => Promise<Response> {
  return createShield(opts).handler(fn);
}
