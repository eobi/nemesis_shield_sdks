# Turn any app into an enforced app - end to end

A framework-agnostic runbook: instrument your app, build a complete behavioral baseline in dev or
staging with **Nemesis Learn**, review it, then flip to **enforce**. Works for any language and any
framework, new or very old.

```
add the SDK (observe)  ->  nemesis-learn (exercise every route)  ->  Baseline readiness: approve  ->  ENFORCE
```

## 0. Prerequisites

- An app you can run in **dev or staging** (never learn against production data you can't recreate -
  Nemesis Learn sends POST/PUT/DELETE).
- Node 18+ on your machine (to run `npx @nemesis-shield-autogon/learn`). Nothing else is required.

## 1. Create the app in Nemesis Shield and copy its token

Console -> Applications -> Protect an app. Copy the install token (`nsk_...`, shown once). The app
starts in **observe** mode.

## 2. Instrument your app with the SDK (observe mode)

One line, at the very top of request handling so every route is seen. Pick your stack:

| Stack | Add |
|---|---|
| Node (Express) | `app.use(require('@nemesis-shield-autogon/sentinel').middleware(process.env.NEMESIS_TOKEN))` |
| Python (FastAPI/Flask) | `app.add_middleware(NemesisShield, token=os.environ['NEMESIS_TOKEN'])` |
| PHP (Laravel) | `composer require nemesislabs/sentinel` + `NEMESIS_TOKEN=` in `.env` (auto-registers) |
| Go | `mux.Use(nemesis.Middleware(os.Getenv("NEMESIS_TOKEN")))` |
| Ruby / PHP / Java / .NET / Rust / Edge | see the SDK for your language in this repo |

**Very old codebases** (CodeIgniter, classic PHP, legacy Java, etc.) - no middleware stack needed.
Drop the raw SDK in and record on shutdown, which survives even a fatal at request end:

```php
// PHP: a php -S router, or auto_prepend_file, or the top of your front controller
require 'NemesisShield.php';
$token = getenv('NEMESIS_TOKEN');
register_shutdown_function(function () use ($token) {
    if ($token) { try { NemesisShield::observe($token); } catch (\Throwable $e) {} }
});
```

Any language that can make an HTTPS POST can report over HTTP to `/api/v1/observe` - the SDK is a
convenience, not a requirement.

## 3. Point the app at dev/staging data

Use a staging or local database, not production. Nemesis Learn creates, updates and deletes resources
through the routes it finds.

## 4. Run Nemesis Learn against the running app

```bash
npx @nemesis-shield-autogon/learn \
  --target http://localhost:3000 \
  --repo . \
  --app-token nsk_your_token
```

- `--repo .` also reads your source so **no route is missed** - it understands Express/Fastify/Nest,
  FastAPI/Flask/Django, Rails/Sinatra, Laravel/Lumen/Slim, Symfony, CodeIgniter, CakePHP, Yii, Spring,
  JAX-RS, Java Servlets/Struts, ASP.NET, Go, and classic file-per-route apps (PHP/ASP/JSP/CFM/CGI).
- Add `--login-url` / `--login-body` (or `--header`) so authenticated routes are exercised too.
- Add `--llm-provider openai --llm-key ...` (or `ollama` for offline) for realistic inputs.

The agent posts its coverage to Shield. You'll see:

```
Shield: baseline recorded for "YourApp" - N behaviors learned - N in review - 0 approved.
```

## 5. Review and enforce

Console -> your app -> **Baseline readiness**:

- **Routes learned** vs exercised, and any **exercised-but-not-learned** routes (a route the SDK
  didn't record - check it's wired there).
- Approve the behaviors in review.
- When coverage is high and nothing is left in review, the panel shows **low risk to enforce**. Flip
  the app to **enforce** - off-baseline requests are now blocked in real time. No redeploy.

## Safety

Nemesis Learn sends only representative, benign traffic - never attacks. It reports **shapes** (method,
route template, status), never payloads or source. Reporting is fail-open: if Shield is unreachable the
run still completes and writes `nemesis-learn-report.json`.
