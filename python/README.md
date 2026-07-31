# nemesis-shield — Python SDK

Native Python SDK for [Nemesis Shield](https://shield.nemesislabs.xyz). Computes a
privacy-preserving request *sketch* locally, learns your app's normal behavior, and — in **enforce
mode** — **blocks off-baseline requests** (auth bypass, path traversal, scanners, unusual methods)
before your views ever run. Positive-security: *this app only ever behaves in these ways.* Zero
dependencies (stdlib only). Fail-open: if Nemesis is unreachable, your app is unaffected.

```bash
pip install nemesis-shield
```

## One line per framework

**FastAPI / Starlette (ASGI)**
```python
from nemesis_shield.asgi import SentinelMiddleware
app.add_middleware(SentinelMiddleware, token=os.environ["NEMESIS_TOKEN"])
```

**Flask / any WSGI app**
```python
from nemesis_shield.wsgi import SentinelWSGI
app.wsgi_app = SentinelWSGI(app.wsgi_app, token=os.environ["NEMESIS_TOKEN"])
```

**Django** — add to `settings.py` and set `NEMESIS_TOKEN` in the environment:
```python
MIDDLEWARE = ["nemesis_shield.django.SentinelDjango", *MIDDLEWARE]
```

**Raw / anything** — use the client directly:
```python
from nemesis_shield import build_sketch
from nemesis_shield.client import SentinelClient
c = SentinelClient(token=os.environ["NEMESIS_TOKEN"])
c.record(build_sketch(method="GET", path="/orders/42", authenticated=True, status=200))
```

## Docs & links

Want more than the one-liner? Full per-framework code, options, and examples:

| Framework | Detailed guide & source |
|---|---|
| FastAPI / Starlette (ASGI) | [nemesis_shield/asgi.py](https://github.com/eobi/nemesis_shield_sdks/blob/main/python/nemesis_shield/asgi.py) |
| Flask / WSGI | [nemesis_shield/wsgi.py](https://github.com/eobi/nemesis_shield_sdks/blob/main/python/nemesis_shield/wsgi.py) |
| Django | [nemesis_shield/django.py](https://github.com/eobi/nemesis_shield_sdks/blob/main/python/nemesis_shield/django.py) |
| Raw client | [nemesis_shield/client.py](https://github.com/eobi/nemesis_shield_sdks/blob/main/python/nemesis_shield/client.py) |
| LLM guard | [nemesis_shield/llm.py](https://github.com/eobi/nemesis_shield_sdks/blob/main/python/nemesis_shield/llm.py) |
| Runnable examples | [python/tests](https://github.com/eobi/nemesis_shield_sdks/tree/main/python/tests) |

- **Full docs & source:** https://github.com/eobi/nemesis_shield_sdks/tree/main/python
- **Website & console:** https://shield.nemesislabs.xyz

## How enforcement works

1. **Learn** — deploy in observe mode (default). Every request is recorded as a privacy-preserving
   request signature (method + route + params + auth — never bodies or secrets). Review and approve
   the learned behaviors in the console.
2. **Enforce** — flip the app to *enforce* in the console. The SDK polls the compiled allow-list in
   the background, so **no redeploy is needed** — the console is the source of truth.
3. **Block** — any request whose signature isn't in the approved allow-list (once a baseline exists),
   is explicitly blocked, or matches global threat intel, gets a `403 blocked_by_nemesis_shield`
   before your app handles it. Everything approved passes untouched.

Verified end-to-end (learn → enforce → attack) on FastAPI, Flask, Django and raw: legitimate traffic
passes (200) while auth bypass, BOLA, path traversal and scanner probes are blocked (403) and
reported.

## LLM protection

```python
from nemesis_shield import analyze_llm
result = analyze_llm(prompt=prompt, system=system, response=response, tools=tools)
```

MIT © Autogon Inc.

## Full coverage & safe-unlock

**Mount it first / outermost** so *every* route is inspected (not just API routes — attackers hit any path):

```
app.add_middleware(SentinelMiddleware, token=os.environ["NEMESIS_TOKEN"])  # ASGI; or wrap wsgi_app outermost
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
