# Nemesis Shield — Edge & Supabase (Deno / TypeScript)

Native TypeScript SDK for **serverless edge runtimes**: **Supabase Edge Functions**, Deno Deploy,
Cloudflare Workers, and Vercel Edge. Learns the function's normal request behavior; in enforce mode
**blocks off-baseline requests** (auth bypass, path traversal, scanners, unusual methods) before your
handler runs. Positive-security, fail-open, privacy-preserving.

> **Why this matters for Supabase.** Edge Functions are **public by default** — anyone on the internet
> can hit the URL, with no firewall or implicit login gate — and most run with the `service_role` key,
> which steps outside RLS. The function *is* the trust boundary, with nothing on it. This wraps that
> boundary with a learned allow-list, so only the request shapes your function actually serves get through.

## Supabase Edge Function

```ts
import { withShield } from "https://esm.sh/gh/eobi/nemesis_shield_sdks/edge/nemesis-shield.ts";

Deno.serve(
  withShield(
    async (req) => {
      // ... your function ...
      return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
    },
    { token: Deno.env.get("NEMESIS_TOKEN") },
  ),
);
```

Set the token: `supabase secrets set NEMESIS_TOKEN=nsk_your_app_token`.

Works identically on **Deno Deploy**, **Cloudflare Workers**, and **Vercel Edge** — the handler is a
plain Web-standard `(Request) => Response`.

## Serverless-safe enforcement

Edge isolates are short-lived, so instead of a background poller the SDK refreshes the compiled policy
**lazily on the request path** (short TTL, deduped) — a cold isolate still enforces the current console
mode with no redeploy. Flip observe↔enforce in the console; the next request picks it up.

## TypeScript, everywhere

There's no separate "TypeScript SDK" — TypeScript *is* the JS runtimes:

| Where your TypeScript runs | Use |
|---|---|
| **Node** backend (Express/Fastify/Koa, Next.js API routes) | [`@nemesis-shield-autogon/sentinel`](../node/) — ships `.d.ts` types |
| **Supabase Edge / Deno / CF Workers / Vercel Edge** | **this package** (`edge/`) |
| **Browser** (React/Angular/Vue/…) | [`@nemesis-shield-autogon/browser`](../browser/) — ships `.d.ts` types |

## Verified

End-to-end (learn → enforce → attack) as a Deno `Deno.serve` function against production: legit
`GET /products` → 200; auth bypass, BOLA (`/orders/999` unauth), path traversal (`/etc/passwd`) and
scanner probes (`/wp-login.php`, `/.env`, `/phpmyadmin`) all blocked (403) and reported
(`findings=11 medium=6`). `deno check` passes.

## Full coverage & safe-unlock

**Mount it first / outermost** so *every* route is inspected (not just API routes — attackers hit any path):

```
Deno.serve(withShield(handler, { token: Deno.env.get("NEMESIS_TOKEN") }));   // wraps the whole function
```

**What's inspected** (privacy-preserving): method + normalized route + **query-param structure** (names + kinds, never values) + auth flag + status. An off-baseline route, **param structure**, method, or auth state is blocked in enforce mode. Path-traversal segments normalize to `{traversal}`.

**Safe-unlock (break-glass):** the login/auth path is never blocked, so a still-learning baseline can't lock you out. Defaults: `/login /signin /sign-in /auth /oauth /session /wp-login.php /wp-admin`. Override:

```bash
export NEMESIS_SHIELD_BOOTSTRAP="/login,/admin,/healthz"
```

**Verify coverage** — in observe mode, hit a normal route, a param, and a scanner path, then confirm all three appear in the console (Activity / Behaviors):

```bash
curl -s "http://localhost:8080/" >/dev/null
curl -s "http://localhost:8080/search?q=shoes" >/dev/null
curl -s "http://localhost:8080/.env" >/dev/null   # shows up as an off-baseline behavior
```
