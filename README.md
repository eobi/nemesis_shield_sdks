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
| **Java** | `NemesisShield.java` | Servlet filter / interceptor (JDK 11+) → [`java/`](java/) |

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

## Two integration modes

- **Native SDK** (Node, Python): computes a privacy-preserving *sketch* locally and streams behavioral
  state. Lowest overhead, richest signal.
- **HTTP client** (Go, Ruby, PHP, Java): reports request metadata to the language-agnostic
  `POST /api/v1/observe` endpoint, where Nemesis computes the sketch server-side. Works from anything
  that can make an HTTP request.

Both send the same privacy-preserving data and produce the same behavioral baseline.

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
