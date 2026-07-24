/**
 * Nemesis Shield — Cloudflare Worker proxy for Supabase's direct DB API (PostgREST).
 *
 * The one Supabase path an in-process SDK can't guard: when a browser calls `supabase.from('table')`,
 * the request goes straight to Supabase's own servers. Route it through this Worker instead and it
 * gets the same positive-security allow-list as everything else — "this app only ever does these
 * verbs on these tables" — before it reaches your database.
 *
 *   app  ->  https://<name>.<you>.workers.dev/rest/v1/...  ->  https://<project>.supabase.co/rest/v1/...
 *
 * Only the DB API (`/rest/v1/`) is inspected; auth / storage / realtime pass straight through. Learns
 * in observe mode, blocks off-baseline table/verb/auth shapes in enforce mode, reports to the console.
 * Fail-open: if Nemesis is unreachable, traffic is forwarded untouched.
 *
 * Config: SUPABASE_URL (var) = your real project URL; NEMESIS_TOKEN (secret) = the app install token.
 */
import { createShield, type Shield } from "../../edge/nemesis-shield.ts";

export interface Env {
  SUPABASE_URL: string;
  NEMESIS_TOKEN: string;
  NEMESIS_ENDPOINT?: string;
}

interface ExecutionContext {
  waitUntil(p: Promise<unknown>): void;
  passThroughOnException(): void;
}

let shield: Shield | null = null;
let lastRefresh = 0;

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (!env.SUPABASE_URL) return new Response("proxy misconfigured: SUPABASE_URL not set", { status: 500 });
    if (!shield) shield = createShield({ token: env.NEMESIS_TOKEN, endpoint: env.NEMESIS_ENDPOINT });

    // Keep the compiled policy fresh across the warm isolate (deduped; fail-open until it lands).
    const now = Date.now();
    if (now - lastRefresh > 3000) {
      lastRefresh = now;
      ctx.waitUntil(shield.refresh().catch(() => {}));
    }

    const url = new URL(req.url);
    const path = url.pathname;
    const isDbApi = path.startsWith("/rest/"); // only guard the PostgREST DB API
    const authed = req.headers.has("authorization") || req.headers.has("apikey");

    if (isDbApi && shield.enforcing()) {
      const reason = shield.decide(shield.buildSketch(req.method, path, authed, 0).shape);
      if (reason) {
        shield.record(shield.buildSketch(req.method, path, authed, 403));
        ctx.waitUntil(shield.flush());
        return Response.json({ error: "blocked_by_nemesis_shield", reason }, { status: 403 });
      }
    }

    // Forward to the real Supabase backend (preserve method, headers, body, query).
    const backend = new URL(env.SUPABASE_URL);
    url.protocol = backend.protocol;
    url.hostname = backend.hostname;
    url.port = backend.port;
    const resp = await fetch(new Request(url.toString(), req));

    if (isDbApi) {
      shield.record(shield.buildSketch(req.method, path, authed, resp.status));
      ctx.waitUntil(shield.flush());
    }
    return resp;
  },
};
