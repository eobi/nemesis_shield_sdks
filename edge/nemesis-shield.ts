/**
 * Nemesis Shield — Edge / Supabase SDK (Deno + Web-standard TypeScript).
 *
 * For serverless TypeScript runtimes: **Supabase Edge Functions**, Deno Deploy, Cloudflare Workers,
 * Vercel Edge. Learns the function's normal request behavior; in enforce mode BLOCKS off-baseline
 * requests (auth bypass, path traversal, scanners, unusual methods) before your handler runs.
 *
 * Supabase Edge Functions are **public by default** and usually run with the service_role key, which
 * steps outside RLS — so the function is the trust boundary with nothing on it. This wraps that
 * boundary with a positive-security allow-list.
 *
 *   import { withShield } from "./nemesis-shield.ts";
 *   Deno.serve(withShield(async (req) => new Response("ok"), {
 *     token: Deno.env.get("NEMESIS_TOKEN"),
 *   }));
 *
 * Serverless-safe: refreshes the compiled policy lazily (short TTL) on the request path, so a cold
 * isolate still enforces the current console mode with no redeploy. Fail-open, privacy-preserving —
 * ships only method + route shape + auth, never bodies or secrets.
 */

const DEFAULT_ENDPOINT = "https://shield.nemesislabs.xyz/api/v1/sketches";

const RE_INT = /^\d+$/;
const RE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RE_HEX = /^[0-9a-f]{16,}$/i;

function fnv1a(s: string): string {
  let h = 0x811c9dc5 >>> 0;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i) & 0xff;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return ("0000000" + h.toString(16)).slice(-8);
}

export function normalizePath(path: string): string {
  path = path.split("?")[0];
  return path
    .split("/")
    .map((s) => (RE_INT.test(s) ? "{int}" : RE_UUID.test(s) ? "{uuid}" : RE_HEX.test(s) ? "{hex}" : s))
    .join("/");
}

// Request signature: method + normalized route + auth (status excluded by design).
function shapeOf(method: string, path: string, authed: boolean): string {
  const route = normalizePath(path);
  const canon = `{"route":"${route}","method":"${method.toUpperCase()}","params":[],"auth":${authed ? 1 : 0}}`;
  return fnv1a(canon);
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

  buildSketch(method: string, path: string, authed: boolean, status: number): Sketch {
    return {
      route: normalizePath(path),
      method: method.toUpperCase(),
      authenticated: authed,
      status,
      shape: shapeOf(method, path, authed),
    };
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
    this.buffer.push(
      `{"route":"${s.route}","method":"${s.method}","authenticated":${s.authenticated},"status":${s.status},"params":[],"shape":"${s.shape}"}`,
    );
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
      await this.maybeRefresh();
      const url = new URL(req.url);
      const authed =
        req.headers.has("authorization") || req.headers.has("cookie") || req.headers.has("apikey");
      if (this.enforcing()) {
        const reason = this.decide(shapeOf(req.method, url.pathname, authed));
        if (reason) {
          this.record(this.buildSketch(req.method, url.pathname, authed, 403));
          void this.flush();
          return new Response(JSON.stringify({ error: "blocked_by_nemesis_shield", reason }), {
            status: 403,
            headers: { "content-type": "application/json" },
          });
        }
      }
      const res = await fn(req);
      this.record(this.buildSketch(req.method, url.pathname, authed, res.status));
      void this.flush();
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
