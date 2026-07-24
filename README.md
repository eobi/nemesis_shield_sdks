# Nemesis Shield — SDKs

Official, open-source SDKs for [**Nemesis Shield**](https://shield.nemesislabs.xyz) — the unified
runtime security platform (application/API/LLM shield, telemetry correlation, network/DNS, response,
and compliance). Drop one into your app and Nemesis **learns your app's normal behavior**, then
flags — and, in enforce mode, blocks — anything that deviates. It's a positive-security (allow-list)
model: instead of guessing at generic attack signatures, it enforces *"this app only ever behaves
in these ways."*

**Privacy by design:** the SDKs ship only behavioral *metadata* — HTTP method, the *shape* of the
path (`/orders/123` → `/orders/{int}`), status code, and whether the caller was authenticated. They
never send your request bodies, responses, secrets, or source code. Every SDK is **fail-open**: if
Nemesis is unreachable, your app is completely unaffected.

| Language | Package | Integration |
|---|---|---|
| **Node.js** | `@nemesis-shield/sentinel` | One-line Express/Connect middleware → [`node/`](node/) |
| **Python** | `nemesis-shield` | ASGI/WSGI middleware (FastAPI/Starlette/Flask) → [`python/`](python/) |
| **Go** | `github.com/eobi/nemesis_shield_sdks/go` | `net/http` middleware → [`go/`](go/) |
| **Ruby** | `nemesis_shield.rb` | Rack middleware (Rails/Sinatra) → [`ruby/`](ruby/) |
| **PHP** | `NemesisShield.php` | `register_shutdown_function` → [`php/`](php/) |
| **Java** | `NemesisShield.java` | Servlet filter / Spring Boot (JDK 11+) → [`java/`](java/) |
| **.NET / C#** | `NemesisShield.cs` | ASP.NET Core middleware → [`dotnet/`](dotnet/) |
| **Rust** | `nemesis-shield` | axum (tower) / actix-web middleware → [`rust/`](rust/) |
| **Edge / Supabase** (Deno TS) | `nemesis-shield.ts` | `withShield()` for Supabase Edge Functions / Deno / CF Workers / Vercel Edge → [`edge/`](edge/) |

### Front-end (browser)

The back-end SDKs above protect the server. The **browser SDK** protects the *other* half — the
client-side attacks a WAF and a backend never see: **Magecart/skimmers, script injection, data
exfiltration, and form-jacking**. It learns which script origins load and which endpoints the page
calls, then blocks anything off-baseline — a learned CSP you approve in the console.

| Front-end | Package | Integration |
|---|---|---|
| **React · Angular · Vue · jQuery · plain JS** | `@nemesis-shield/browser` | one `<script data-token>` tag, or `NemesisShield.init({token})` → [`browser/`](browser/) |

One SDK covers every framework — they all share the same browser primitives.

> **Using TypeScript?** There's no separate TS SDK — TypeScript is these same runtimes. Node backends
> use [`@nemesis-shield/sentinel`](node/) (ships `.d.ts`), Supabase Edge / Deno / Workers use
> [`edge/`](edge/), and TS front-ends use [`@nemesis-shield/browser`](browser/) (ships `.d.ts`).

## Get a token

1. Sign up at **[shield.nemesislabs.xyz](https://shield.nemesislabs.xyz)** (free, no card).
2. **Protect an app** — you'll get a one-time install token (`nsk_…`).
3. Add the SDK below, set the token, deploy. Traffic starts building a per-app baseline immediately;
   review learned behaviors and approve/block them in the console.

## Quick start

**Node.js**
```bash
npm install @nemesis-shield/sentinel
```
```js
import { sentinel } from "@nemesis-shield/sentinel/express";
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

**PHP**
```php
register_shutdown_function(fn() => NemesisShield::observe(getenv('NEMESIS_TOKEN')));
```

**Java** (servlet filter)
```java
var nemesis = new NemesisShield(System.getenv("NEMESIS_TOKEN"));
nemesis.report(req.getMethod(), req.getRequestURI(), res.getStatus(), authed);
```

**Rust** (axum / actix — see [`rust/`](rust/) for the middleware)
```rust
let shield = nemesis_shield::Client::new(std::env::var("NEMESIS_TOKEN").unwrap_or_default());
// .layer(middleware::from_fn_with_state(shield.clone(), shield_mw))
```

## How enforcement works (all SDKs)

Every SDK is **native**: it computes the privacy-preserving request *shape* locally, caches the
compiled policy, and makes the block decision **in-process, before your handler runs** — no proxy,
no sidecar, no per-request round-trip.

1. **Observe** (default) — the SDK records the shape of each request and builds a per-app baseline.
2. **Approve** — review learned behaviors in the console; approve the legitimate ones (auto-approved
   during the learning window).
3. **Enforce** — flip the app to enforce in the console. Requests whose shape isn't in the approved
   baseline are blocked with `403 blocked_by_nemesis_shield` and reported as findings. **No redeploy**
   — a background poller picks up the mode change (PHP refreshes a short-TTL policy cache instead).

Verified end-to-end (learn → enforce → attack, real blocking) across **8 languages / ~20 frameworks**:
Python (FastAPI/Flask/Django), Node (Express/Fastify/Koa), Go (net/http/Chi/Gin/Echo), Ruby
(Rails/Sinatra/Rack), PHP (raw/Laravel/Symfony), Java (Servlet/Spring Boot), .NET (ASP.NET Core),
Rust (axum/actix). Legit traffic passes; auth bypass, BOLA, path traversal and scanner probes blocked.

## LLM protection

The Node and Python SDKs also report LLM exchanges for OWASP-LLM-Top-10 behavioral protection
(prompt injection, jailbreak, system-prompt leak, unauthorized tool calls, sensitive output). Only
detection labels and shapes are stored — never raw prompts or responses.

```js
import { reportLLM } from "@nemesis-shield/sentinel";
await reportLLM(token, { prompt, system, response, tools, allowedTools: ["search"] });
```

## License

[MIT](LICENSE) © Autogon Inc. — use them freely, in any project.
