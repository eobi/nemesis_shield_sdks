# Nemesis Shield - SDKs

[![Protected by Nemesis](https://nemesislabs.xyz/api/badge)](https://nemesislabs.xyz/shield)

Official, open-source SDKs for [**Nemesis Shield**](https://shield.nemesislabs.xyz) - the unified
runtime security platform (application/API/LLM shield, telemetry correlation, network/DNS, response,
and compliance). Drop one into your app and Nemesis **learns your app's normal behavior**, then
flags - and, in enforce mode, blocks - anything that deviates. It's a positive-security (allow-list)
model: instead of guessing at generic attack signatures, it enforces *"this app only ever behaves
in these ways."*

> **Building with an AI assistant?** Two ways to make your agent add Nemesis Shield **as it builds**:
> 1. **[MCP server](mcp/)** — gives Cursor, Claude Code/Desktop and Windsurf 17 callable tools
>    (`nemesis_protect`, `nemesis_scan`, `nemesis_explain`, plus Omniguard fraud scoring and standalone
>    identity/AML screening via `nemesis_omniguard_verify`) so the agent adds security, scans a site,
>    screens identities, and explains coverage without leaving the editor.
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

---

# Repository guide (for maintainers)

Everything above is for developers **consuming** the SDKs. This section is for developers **working
on this repo** after the transfer. Each language SDK is self-contained and hand-written to be
byte-identical in behavior (same request shape, same policy model, same embedded LLM-Guard weights),
so there is no shared build step across languages: you develop, test and publish each one from its
own directory using that ecosystem's native tooling.

## Repository layout

```
node/        Node/JS SDK  -> npm  @nemesis-shield-autogon/sentinel  (Express/Fastify/Koa + /llm)
python/      Python SDK   -> PyPI nemesis-shield                    (ASGI/WSGI + provider wrappers)
go/          Go SDK       -> go   github.com/eobi/nemesis_shield_sdks/go
ruby/        Ruby SDK     -> gem  nemesis-shield
php/         PHP SDK      -> Packagist nemesislabs/sentinel         (Laravel auto-discovery)
java/        Java SDK     -> Maven Central io.github.eobi:sentinel
dotnet/      .NET SDK     -> NuGet NemesisShield
rust/        Rust SDK     -> crates.io nemesis-shield
edge/        Edge/Deno TS -> npm @nemesis-shield-autogon/edge · JSR @nemesis-shield/edge
browser/     Browser SDK  -> npm @nemesis-shield-autogon/browser   (Page Shield / anti-Magecart)
wordpress/   WordPress plugin (drop-in)
cloudflare-supabase-proxy/  Worker that guards supabase.from() / PostgREST

mcp/         MCP server (17 tools: nemesis_protect, nemesis_scan, nemesis_omniguard_verify, ...)
learn/       @nemesis-shield-autogon/learn - the baseline traffic driver
ai-rules/    Editor rule packs (AGENTS.md, Cursor, Windsurf, Claude Code)
create-nemesis-app/  scaffolder
demo/ examples/       runnable samples
e2e/         live over-the-wire tests (learn -> enforce -> attack) across every language
```

Each language directory has its **own README** with framework-specific setup. Start there for any
one SDK.

## Prerequisites

Only install the toolchain for the SDK you are touching: Node 18+ (node/edge/browser/mcp/learn),
Python 3.9+ (python), Go 1.21+ (go), Ruby 2.7+ (ruby), PHP 7.2+ and Composer (php), JDK 11+ and
Maven (java), .NET 8 SDK (dotnet), Rust stable (rust).

## Develop, test, publish

Work inside the SDK's directory with its native commands. The common shape:

| SDK | Install / build | Test | Publish |
|---|---|---|---|
| Node · Edge · Browser | `npm install` | `npm test` | `npm publish --access public` |
| Python | `python -m build` | `pytest` | `twine upload dist/*` |
| Go | `go build ./...` | `go test ./...` | `git tag` (module is consumed by tag) |
| Ruby | `gem build *.gemspec` | `rake test` | `gem push *.gem` |
| PHP | `composer install` | `composer test` | tag -> Packagist auto-syncs |
| Java | `mvn package` | `mvn test` | `mvn deploy` (Central) |
| .NET | `dotnet build` | `dotnet test` | `dotnet pack` + `dotnet nuget push` |
| Rust | `cargo build` | `cargo test` | `cargo publish` |

Publishing is credentialed. Get the registry tokens (npm, PyPI, Maven Central, NuGet, crates.io,
RubyGems) from the team secrets store, never from this repo. The `mcp/` server has its own publish
flow (npm + the MCP registry + Smithery); see `mcp/README.md`.

## Cross-language contract (do not drift)

Any change to behavior must land in **every** SDK identically. The invariants:

- Default ingest: `POST https://shield.nemesislabs.xyz/api/v1/sketches` (LLM: `/api/v1/llm`),
  overridable via `NEMESIS_ENDPOINT` / an `endpoint` option.
- Auth: `Authorization: Bearer nsk_…`.
- Modes: `observe` (default) -> `enforce`, flipped in the console; the SDK background-refreshes the
  compiled policy with no redeploy.
- Blocked request: HTTP `403` with `{"error":"blocked_by_nemesis_shield", ...}`.
- Break-glass allow-list (never blocked): `/login /signin /sign-in /auth /oauth /session
  /wp-login.php /wp-admin`, overridable via `NEMESIS_SHIELD_BOOTSTRAP`.
- Request shape only: method, normalized path (`/orders/123` -> `/orders/{int}`), query-param
  structure (names + kinds, never values), auth flag, status. Never bodies or secrets.
- LLM-Guard weights (`ml_weights.json`) are embedded byte-identically and Ed25519-signed;
  hot-swappable via `refreshModel()` against the pinned public key.

Every SDK is **fail-open**: if the service is unreachable, the app is unaffected. Keep it that way.

## After you change any SDK

Run the language's tests, then the relevant `e2e/` scenario (real learn -> enforce -> attack over
the wire). Do not ship an SDK that has not passed its e2e run.

## License

[MIT](LICENSE) © Autogon Inc. - use them freely, in any project.

## Coverage & safe-unlock (all SDKs)

Every backend SDK is mounted **outermost** so it sees *every* route (attacks come from any path, not just your API), and the request **shape now includes query-param structure** - names + kinds, never values - so param tampering, injected params, and type anomalies on a *known* route are caught, not just unknown paths. Path-traversal segments normalize to `{traversal}`.

Enforcement covers **every route with a break-glass**: the login/auth path is never blocked, so a still-learning baseline can't lock you out. Defaults: `/login /signin /sign-in /auth /oauth /session /wp-login.php /wp-admin`. Override per app:

```bash
export NEMESIS_SHIELD_BOOTSTRAP="/login,/admin,/healthz"
```

Verified across every SDK with live over-the-wire tests: legit traffic (incl. same-route value variation and param-order swaps) passes; unknown paths, injected/mutated params, method and auth anomalies, and 100+ CVE-pattern probes (path traversal, LFI/RFI, Log4Shell, Spring4Shell, Actuator, PHPUnit/Ignition RCE, ViewState, PostgREST table-enum, prototype pollution, NoSQL, SSTI…) are blocked.
