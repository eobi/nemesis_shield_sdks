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

## Bring your own LLM (optional - any provider, including private / self-hosted)

The LLM is **optional**. It only makes the generated inputs more realistic (a sensible body for
`POST /createOrder`, etc.); without one, Nemesis Learn uses OpenAPI schemas + field-name heuristics and
still exercises every route. When you do use one, **you choose the model** - hosted, self-hosted, or fully
offline. The key and prompts go **straight from your machine to the endpoint you name**; nothing about
your LLM ever touches Nemesis Shield.

```bash
# OpenAI
--llm-provider openai     --llm-key $OPENAI_API_KEY

# Anthropic
--llm-provider anthropic  --llm-key $ANTHROPIC_API_KEY  --llm-model claude-3-5-haiku-latest

# ANY OpenAI-compatible endpoint -> point --llm-base at it. This covers most private / self-hosted LLMs:
#   vLLM, LM Studio, LocalAI, text-generation-webui, Azure OpenAI, Together, Groq, OpenRouter, or your
#   own internal gateway. Use the key that endpoint expects (or a dummy one if it needs none).
--llm-provider openai --llm-base https://llm.internal.mycorp.com/v1 --llm-key $MY_LLM_KEY --llm-model my-model

# Fully offline / air-gapped - a local model, no key, nothing leaves the box:
--llm-provider ollama  --llm-base http://localhost:11434  --llm-model llama3.1
```

| Flag | Meaning |
|---|---|
| `--llm-provider` | `openai` \| `anthropic` \| `ollama`. Use `openai` for any OpenAI-compatible API. |
| `--llm-base` | Override the API base URL - this is how you point at a **private / self-hosted** model. |
| `--llm-key` | The endpoint's key (or env `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `LLM_API_KEY`). |
| `--llm-model` | Override the model name. |

**Privacy:** Nemesis Learn talks only to (a) your app and (b) the LLM endpoint you specify. Choose a
self-hosted model or Ollama and the whole run stays inside your network - suitable for regulated or
air-gapped environments.

## What it does

1. **Discovers routes** from three independent sources (any one is enough; together they cover a lot):
   - **OpenAPI / Swagger** - the strongest signal (methods, params, body schemas, security).
   - **HTML crawl** - same-origin links and `<form>` actions, for server-rendered apps without a spec.
   - **Repo static scan** - regex route patterns across Express/Fastify/Nest, FastAPI/Flask/Django,
     Rails, Laravel, Spring, Go, and more. Point `--repo` at a path or a git URL.
2. **Authenticates** once (`--login-url` + `--login-body`, or `--header`) and carries the session
   (cookies + bearer token) through the whole run, so protected routes are learned too.
3. **Exercises every route** with realistic inputs - generated from the OpenAPI schema and field-name
   heuristics, and refined by **the LLM of your choice** when provided (OpenAI, Anthropic, any
   OpenAI-compatible / **private self-hosted** endpoint, or a local **Ollama** for a fully-offline run -
   see [Bring your own LLM](#bring-your-own-llm-optional---any-provider-including-private--self-hosted)).
   It handles **file uploads**, query/path params, and reuses ids returned by earlier calls so **CRUD
   flows chain**.
4. **Reports coverage** - routes discovered vs exercised, status mix, uploads, and any route that
   errored (5xx / unreachable) so you can fix it before enforcing. Written to
   `nemesis-learn-report.json`.

## Report to Shield (baseline readiness)

Pass your app's Shield token and Nemesis Learn posts its coverage back to the app, so the portal shows a
live **baseline readiness** meter and a **ready-to-enforce** gate on the app's page - routes exercised vs
learned, behaviors to approve, and the routes the SDK saw no behavior for (so you can spot a route the SDK
isn't wired on).

```bash
npx @nemesis-shield/learn --target http://localhost:3000 --app-token nsk_live_… --repo .
```

- `--app-token <nsk_…>` - your app token (the same one the SDK uses). Also read from `NEMESIS_SHIELD_TOKEN`.
- `--report-to <url>` - Shield base URL; defaults to `https://shield.nemesislabs.xyz`. Also `NEMESIS_SHIELD_URL`.

Only **shapes** are sent - method, route template, status - never payloads. Reporting is fail-open: if
Shield is unreachable the run still completes and writes the local report. Open **Shield -> your app ->
Baseline readiness**, approve the learned behaviors, then flip to **enforce**.

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
