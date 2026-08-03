# Nemesis Learn

**Turn a brand-new app into an enforced one, fast.** Nemesis Learn is an agent that exercises every
route of your app in **dev or staging** - every endpoint, form, upload and CRUD flow - so Nemesis
Shield's per-app behavioral model finishes **learning** a complete baseline. Then you approve it and flip
the app to **enforce**.

It works at the **HTTP layer**, so it's **language- and framework-agnostic** (Node, Python, PHP, Go,
Java, Ruby, .NET - anything that serves HTTP). It **runs offline** on your machine against a local URL,
has **zero dependencies**, and can optionally read your **repo** (public or private) to discover routes
from source too.

> Prereq: your app already has a Nemesis Shield SDK (or the gateway) installed and is in **observe /
> learning** mode. Nemesis Learn just generates the traffic; the SDK does the learning.

## Run it

Needs Node 18+. No install required:

```bash
# against a running dev/staging app
npx @nemesis-shield/learn --target http://localhost:3000

# also discover routes from source (any language), realistic inputs via your LLM
npx @nemesis-shield/learn --target http://localhost:8000 --repo . \
  --llm-provider openai --llm-key $OPENAI_API_KEY

# learn protected routes too - log in first
npx @nemesis-shield/learn --target http://localhost:5000 \
  --login-url /api/login --login-body '{"email":"dev@acme.com","password":"devpass"}'
```

Or clone this folder and run `node src/index.mjs --target …`. Or Docker:

```bash
docker build -t nemesis-learn . && docker run --rm --network host nemesis-learn --target http://localhost:3000
```

## What it does

1. **Discovers routes** from three independent sources (any one is enough; together they cover a lot):
   - **OpenAPI / Swagger** - the strongest signal (methods, params, body schemas, security).
   - **HTML crawl** - same-origin links and `<form>` actions, for server-rendered apps without a spec.
   - **Repo static scan** - regex route patterns across Express/Fastify/Nest, FastAPI/Flask/Django,
     Rails, Laravel, Spring, Go, and more. Point `--repo` at a path or a git URL.
2. **Authenticates** once (`--login-url` + `--login-body`, or `--header`) and carries the session
   (cookies + bearer token) through the whole run, so protected routes are learned too.
3. **Exercises every route** with realistic inputs - generated from the OpenAPI schema and field-name
   heuristics, and refined by your **LLM** when provided (OpenAI, Anthropic, or a local **Ollama** for a
   fully-offline run). It handles **file uploads**, query/path params, and reuses ids returned by earlier
   calls so **CRUD flows chain**.
4. **Reports coverage** - routes discovered vs exercised, status mix, uploads, and any route that
   errored (5xx / unreachable) so you can fix it before enforcing. Written to
   `nemesis-learn-report.json`.

## Safety

This builds a **normal-behavior baseline** - it sends *representative, benign* traffic, never attacks or
injection payloads. Point it at **dev or staging**, not production data you can't recreate: it will
create/update/delete resources through the routes it finds (deletes run last).

## Options

Run `npx @nemesis-shield/learn --help` for the full list (`--max`, `--concurrency`, `--delay`,
`--timeout`, `--max-pages`, `--no-openapi`, `--no-crawl`, repeatable `--header`, …).

## The flow

```
drop in the SDK (observe) →  nemesis-learn  →  Review Queue: approve  →  flip to ENFORCE
```
