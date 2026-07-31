# @nemesis-shield/sentinel — Node.js

Native Node SDK for [Nemesis Shield](https://shield.nemesislabs.xyz). Learns your app's normal
behavior, and in **enforce mode BLOCKS off-baseline requests** (auth bypass, path traversal,
scanners, unusual methods) before your routes run. Positive-security, fail-open, privacy-preserving
(ships only method + route shape + auth — never bodies or secrets).

```bash
npm install @nemesis-shield/sentinel
```

## One line per framework

**Express / Connect**
```js
import { sentinel } from "@nemesis-shield/sentinel/express";
app.use(sentinel({ token: process.env.NEMESIS_TOKEN }));
```

**Fastify**
```js
import { sentinelFastify } from "@nemesis-shield/sentinel/fastify";
await app.register(sentinelFastify, { token: process.env.NEMESIS_TOKEN });
```

**Koa**
```js
import { sentinelKoa } from "@nemesis-shield/sentinel/koa";
app.use(sentinelKoa({ token: process.env.NEMESIS_TOKEN }));
```

**Raw / anything** — use the client directly:
```js
import { SentinelClient, buildSketch } from "@nemesis-shield/sentinel";
const client = new SentinelClient({ token: process.env.NEMESIS_TOKEN });
client.record(buildSketch({ method: "GET", path: "/orders/42", authenticated: true, status: 200 }));
```

## How enforcement works

Deploy in **observe** mode (default) → the SDK records privacy-preserving request signatures → review
& approve the learned behaviors in the console → flip the app to **enforce** in the console (the SDK
polls the compiled policy in the background, so **no redeploy**) → off-baseline requests get a
`403 blocked_by_nemesis_shield` before your app handles them. Approved traffic passes untouched.

Verified end-to-end (learn → enforce → attack) on **Express, Fastify and Koa**: legit traffic passes
(200); auth bypass, BOLA, path traversal and scanner probes are blocked (403) and reported.

Also exports `reportLLM(token, exchange)` for OWASP-LLM behavioral protection. MIT © Autogon Inc.

## Full coverage & safe-unlock

**Mount it first / outermost** so *every* route is inspected (not just API routes — attackers hit any path):

```
app.use(sentinel({ token: process.env.NEMESIS_TOKEN })); // BEFORE your routes and any static handler
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
