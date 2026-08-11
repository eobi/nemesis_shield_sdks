# Nemesis Shield - SDKs

Official, open-source SDKs for [**Nemesis Shield**](https://shield.nemesislabs.xyz) - the unified
runtime security platform (application/API/LLM shield, telemetry correlation, network/DNS, response,
and compliance). Drop one into your app and Nemesis **learns your app's normal behavior**, then
flags - and, in enforce mode, blocks - anything that deviates. It's a positive-security (allow-list)
model: instead of guessing at generic attack signatures, it enforces *"this app only ever behaves
in these ways."*

> **Building with an AI assistant?** Two ways to make your agent add Nemesis Shield **as it builds**:
> 1. **[MCP server](mcp/)** — gives Cursor, Claude Code/Desktop and Windsurf callable tools
>    (`nemesis_protect`, `nemesis_scan`, `nemesis_explain`) so the agent adds security, scans a site,
>    and explains coverage without leaving the editor.
> 2. **[AI editor rule pack](ai-rules/)** (AGENTS.md, Cursor, Windsurf, Claude Code) — drop-in rules
>    that tell the agent to add the one-line SDK by default.
>
> Both are one line per stack, safe by default (observe mode). Full verified reference:
> [`ai-rules/AGENTS.md`](ai-rules/AGENTS.md).

**Privacy by design:** the SDKs ship only behavioral *metadata* - HTTP method, the *shape* of the
path (`/orders/123` → `/orders/{int}`), status code, and whether the caller was authenticated. They
never send your request bodies, responses, secrets, or source code. Every SDK is **fail-open**: if
Nemesis is unreachable, your app is completely unaffected.

> **New app? Finish learning in minutes with [Nemesis Learn](learn/).** Drop in an SDK (observe mode),
> then run one command and the agent exercises every route of your app in dev/staging - endpoints,
> forms, uploads, CRUD flows - so the baseline completes without waiting on real traffic. It's
> language- and framework-agnostic (drives your app over HTTP), runs offline, can read your repo to
> find routes, and reports coverage back so the console shows exactly when you're ready to enforce.
> ```bash
> npx @nemesis-shield-autogon/learn --target http://localhost:3000 --app-token nsk_… --repo .
> ```

| Language | Package | Integration |
|---|---|---|
| **Node.js** | `@nemesis-shield-autogon/sentinel` | One-line Express/Connect middleware → [`node/`](node/) |
| **Python** | `nemesis-shield` | ASGI/WSGI middleware (FastAPI/Starlette/Flask) → [`python/`](python/) |
| **Go** | `github.com/eobi/nemesis_shield_sdks/go` | `net/http` middleware → [`go/`](go/) |
| **Ruby** | `nemesis_shield.rb` | Rack middleware (Rails/Sinatra) → [`ruby/`](ruby/) |
| **PHP** | `composer require nemesislabs/sentinel` | Laravel auto-discovery / `register_shutdown_function` → [`php/`](php/) |
| **WordPress** | drop-in plugin | Behavioral firewall (front end, REST & admin-ajax) **+ brute-force lockout, malware / file-integrity scan & vulnerability alerts** → [`wordpress/`](wordpress/) |
| **Java** | `io.github.eobi:sentinel` | Servlet filter / Spring Boot (JDK 11+) → [`java/`](java/) |
| **.NET / C#** | `dotnet add package NemesisShield` | ASP.NET Core middleware (net8.0 + netstandard2.0) → [`dotnet/`](dotnet/) |
| **Rust** | `cargo add nemesis-shield` | axum (tower) / actix-web middleware → [`rust/`](rust/) |
| **Edge / Supabase** (Deno TS) | `@nemesis-shield-autogon/edge` (npm) · `@nemesis-shield/edge` (JSR) | `withShield()` for Supabase Edge / Deno / CF Workers / Vercel Edge / Next.js → [`edge/`](edge/) |
| **Supabase direct DB API** | Cloudflare Worker | reverse-proxy that guards `supabase.from()` (PostgREST) - off-baseline table/verb/auth blocked before your DB → [`cloudflare-supabase-proxy/`](cloudflare-supabase-proxy/) |

### Front-end (browser)

The back-end SDKs above protect the server. The **browser SDK** protects the *other* half - the
client-side attacks a WAF and a backend never see. Built **checkout-grade** for payment / e-commerce
pages: it blocks card-skimming **data exfiltration across every channel** (fetch, XHR, beacon, image
beacons, WebSocket, EventSource), **Magecart/injected scripts**, and **form-jacking**; detects inline
tampering, field injection, and **clickjacking**; and maps directly to **PCI DSS 4.0.1 §6.4.3 &
§11.6.1** (script inventory, authorization, tamper alerting). A learned CSP you approve in the console.

| Front-end | Package | Integration |
|---|---|---|
| **React · Angular · Vue · jQuery · plain JS** | `@nemesis-shield-autogon/browser` | one `<script data-token>` tag, or `NemesisShield.init({token})` → [`browser/`](browser/) |

One SDK covers every framework - they all share the same browser primitives.

> **Using TypeScript?** There's no separate TS SDK - TypeScript is these same runtimes. Node backends
> use [`@nemesis-shield-autogon/sentinel`](node/) (ships `.d.ts`), Supabase Edge / Deno / Workers use
> [`edge/`](edge/), and TS front-ends use [`@nemesis-shield-autogon/browser`](browser/) (ships `.d.ts`).

## Get a token

1. Sign up at **[shield.nemesislabs.xyz](https://shield.nemesislabs.xyz)** (free, no card).
2. **Protect an app** - you'll get a one-time install token (`nsk_…`).
3. Add the SDK below, set the token, deploy. Traffic starts building a per-app baseline immediately;
   review learned behaviors and approve/block them in the console.

## Quick start

**Node.js**
```bash
npm install @nemesis-shield-autogon/sentinel
```
```js
import { sentinel } from "@nemesis-shield-autogon/sentinel/express";
app.use(sentinel({ token: process.env.NEMESIS_TOKEN })); // one line, zero route changes
```

**Python**
```bash
pip install nemesis-shield
```
```python
from nemesis_shield.asgi import SentinelMiddleware
app.add_middleware(SentinelMiddleware, token=os.environ["NEMESIS_TOKEN"])
```

**Go**
```go
handler := nemesis.Middleware(os.Getenv("NEMESIS_TOKEN"))(mux)
http.ListenAndServe(":8080", handler)
```

**Ruby** (Rack)
```ruby
use NemesisShield::Middleware, token: ENV["NEMESIS_TOKEN"]
```

**PHP** - `composer require nemesislabs/sentinel` (Laravel auto-discovers the middleware; raw PHP:)
```php
NemesisShield::guard(getenv('NEMESIS_TOKEN'));                                        // block off-baseline
register_shutdown_function(fn() => NemesisShield::observe(getenv('NEMESIS_TOKEN'))); // learn
```

**WordPress** - a full security plugin: the AI behavioral firewall plus brute-force login lockout, malware / file-integrity scanning, and vulnerability alerts. Drop the [`wordpress/nemesis-shield/`](wordpress/) plugin into `wp-content/plugins/`, activate, and set the token:
```php
// wp-config.php
define('NEMESIS_SHIELD_TOKEN', 'nsk_your_site_token');
```

**Java** - `io.github.eobi:sentinel` on Maven Central (Spring Boot filter, or raw:)
```java
import io.github.eobi.sentinel.NemesisShield;
var nemesis = new NemesisShield(System.getenv("NEMESIS_TOKEN"));
if (nemesis.guard(method, path, authed, exchange)) return;   // block off-baseline (403)
nemesis.observe(method, path, authed, status);               // learn
```

**.NET / C#** - `dotnet add package NemesisShield` (net8.0 + netstandard2.0 / .NET Framework 4.6.1+)
```csharp
// Program.cs - register FIRST (before UseRouting) so it inspects every request, incl. unmatched paths
app.UseMiddleware<NemesisShield.SentinelMiddleware>();   // set NEMESIS_TOKEN in env
```

**Rust** (axum / actix - see [`rust/`](rust/) for the middleware)
```rust
let shield = nemesis_shield::Client::new(std::env::var("NEMESIS_TOKEN").unwrap_or_default());
// .layer(middleware::from_fn_with_state(shield.clone(), shield_mw))
```

**Edge** (Deno / Cloudflare Workers / Vercel Edge / Supabase / Next.js middleware) - `npm i @nemesis-shield-autogon/edge` or `deno add jsr:@nemesis-shield/edge`
```ts
import { withShield } from "@nemesis-shield-autogon/edge";
// wraps any Web-standard (Request) => Response; same line on every edge runtime:
Deno.serve(withShield(handler, { token: Deno.env.get("NEMESIS_TOKEN") }));   // Supabase/Deno
// Cloudflare: export default { fetch: (req, env) => withShield(handler, { token: env.NEMESIS_TOKEN })(req) };
```

## How enforcement works (all SDKs)

Every SDK is **native**: it computes the privacy-preserving request *shape* locally, caches the
compiled policy, and makes the block decision **in-process, before your handler runs** - no proxy,
no sidecar, no per-request round-trip.

1. **Observe** (default) - the SDK records the shape of each request and builds a per-app baseline.
2. **Approve** - review learned behaviors in the console; approve the legitimate ones (auto-approved
   during the learning window).
3. **Enforce** - flip the app to enforce in the console. Requests whose shape isn't in the approved
   baseline are blocked with `403 blocked_by_nemesis_shield` and reported as findings. **No redeploy**
   - a background poller picks up the mode change (PHP refreshes a short-TTL policy cache instead).

Verified end-to-end (learn → enforce → attack, real blocking) across **8 languages / ~20 frameworks**:
Python (FastAPI/Flask/Django), Node (Express/Fastify/Koa), Go (net/http/Chi/Gin/Echo), Ruby
(Rails/Sinatra/Rack), PHP (raw/Laravel/Symfony), Java (Servlet/Spring Boot), .NET (ASP.NET Core),
Rust (axum/actix). Legit traffic passes; auth bypass, BOLA, path traversal and scanner probes blocked.

## LLM protection

The Node and Python SDKs also report LLM exchanges for OWASP-LLM-Top-10 behavioral protection
(prompt injection, jailbreak, system-prompt leak, unauthorized tool calls, sensitive output). Only
detection labels and shapes are stored - never raw prompts or responses.

```js
import { reportLLM } from "@nemesis-shield-autogon/sentinel";
await reportLLM(token, { prompt, system, response, tools, allowedTools: ["search"] });
```

## License

[MIT](LICENSE) © Autogon Inc. - use them freely, in any project.

## Coverage & safe-unlock (all SDKs)

Every backend SDK is mounted **outermost** so it sees *every* route (attacks come from any path, not just your API), and the request **shape now includes query-param structure** - names + kinds, never values - so param tampering, injected params, and type anomalies on a *known* route are caught, not just unknown paths. Path-traversal segments normalize to `{traversal}`.

Enforcement covers **every route with a break-glass**: the login/auth path is never blocked, so a still-learning baseline can't lock you out. Defaults: `/login /signin /sign-in /auth /oauth /session /wp-login.php /wp-admin`. Override per app:

```bash
export NEMESIS_SHIELD_BOOTSTRAP="/login,/admin,/healthz"
```

Verified across every SDK with live over-the-wire tests: legit traffic (incl. same-route value variation and param-order swaps) passes; unknown paths, injected/mutated params, method and auth anomalies, and 100+ CVE-pattern probes (path traversal, LFI/RFI, Log4Shell, Spring4Shell, Actuator, PHPUnit/Ignition RCE, ViewState, PostgREST table-enum, prototype pollution, NoSQL, SSTI…) are blocked.
