# Nemesis Shield — Laravel example (Laravel 6+ / PHP 7.2+)

Positive-security runtime protection for a Laravel app. Sentinel **learns each app's normal request
shapes** (method + route template + parameter types + auth posture) and, once you flip it to enforce,
**blocks off-baseline requests** — auth-bypass attempts, path traversal, scanner probes, unusual
methods/params. It is **fail-open** (a missing extension, a network blip, an unwritable temp dir → the
request is allowed) and **privacy-preserving** (only shapes are sent — never bodies, values or secrets).

> Great fit for **legacy / EOL apps** (e.g. Laravel 6): an allow-list model blocks *exploitation
> attempts* at the HTTP boundary even when the underlying code is still vulnerable. It is a
> compensating control, not a substitute for upgrading.

## Requirements
- **PHP 7.2+** (matches Laravel 6's own floor). On cPanel/Namecheap pick the PHP version in
  **MultiPHP Manager** (7.4 recommended; 7.2/7.3 are EOL).
- **ext-curl** enabled (default on shared hosting). Without it the SDK still runs — observe-only.
- A **per-app token** — create one app per Laravel app in the console (`shield.nemesislabs.xyz`),
  copy the token shown once.

## Install — Option A: Composer (recommended)
```bash
composer require nemesislabs/sentinel
```
Laravel **package auto-discovery** registers `NemesisShieldServiceProvider`, which prepends the
Sentinel middleware to the global stack — **no Kernel.php edit needed**. Then set the token:
```dotenv
# .env
NEMESIS_TOKEN=nsk_your_app_token
```
That's it. The app starts in **observe** mode (learn-only). It never blocks until you approve a
baseline and flip the app to **enforce** in the console.

> Publishing: this package lives in the `php/` folder of `github.com/eobi/nemesis_shield_sdks`.
> Publish that folder to Packagist as `nemesislabs/sentinel` (or point Composer at a subtree split)
> to make `composer require` resolve.

## Install — Option B: Manual (no Composer, e.g. locked-down shared hosting)
1. Copy `php/NemesisShield.php` and `php/NemesisShieldMiddleware.php` into your app, e.g.
   `app/Nemesis/`.
2. Register the middleware globally in `app/Http/Kernel.php` (see `Kernel.snippet.php` here).
3. Add `NEMESIS_TOKEN=nsk_your_app_token` to `.env`.

## Turning on blocking (per app)
1. Deploy with the token → the app **observes** and learns its normal shapes.
2. In the console, review and **approve** the learned baseline for that app.
3. Flip the app to **enforce**. From then on, requests that don't match the approved baseline are
   returned `403 {"error":"blocked_by_nemesis_shield"}`. Flip back to observe any time — no redeploy.

## Notes for Namecheap / shared hosting
- **PHP version:** set it per-domain in **MultiPHP Manager** (7.4+).
- **Env var:** `NEMESIS_TOKEN` in `.env` works because Laravel 6's dotenv populates `getenv()`. If a
  host has `putenv` disabled, set it instead via cPanel or `.htaccess`: `SetEnv NEMESIS_TOKEN nsk_...`.
- **Latency:** the compiled policy is cached in the system temp dir with a 2-second TTL, so it's a
  fast local read on almost every request and hits the network at most once per 2s per app.
- **Safety:** every failure path is fail-open — adding this to a fragile legacy app cannot take it down.

Roll the same steps across all your apps (one token each) so every app gets its own baseline and can
be enforced independently.
