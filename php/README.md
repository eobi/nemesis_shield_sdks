# Nemesis Shield - PHP

Native PHP SDK for [Nemesis Shield](https://shield.nemesislabs.xyz). Learns your app's normal
behavior; in **enforce mode BLOCKS off-baseline requests** (auth bypass, path traversal, scanners,
unusual methods) before your app runs. PHP is stateless per-request, so the compiled policy is cached
to a temp file with a short TTL and refreshed on demand. Positive-security, fail-open.

**Raw / any framework**
```php
require "NemesisShield.php";
$token = getenv("NEMESIS_TOKEN");
if (NemesisShield::guard($token)) return;   // pre-dispatch block (enforce mode)
// ... your app ...
NemesisShield::observe($token);             // record after the response
```

**Laravel (Composer, 6+ / PHP 7.2+)** - zero-config via package auto-discovery:
```bash
composer require nemesislabs/sentinel
```
```dotenv
# .env
NEMESIS_TOKEN=nsk_your_app_token
```
`NemesisShieldServiceProvider` prepends the middleware to the global stack automatically - no
`Kernel.php` edit. Full guide + manual (no-Composer) fallback + Namecheap/shared-hosting notes:
[`examples/laravel/`](../examples/laravel/). (No Composer? drop `NemesisShield.php` +
`NemesisShieldMiddleware.php` in and register the middleware yourself - see the example.)

**Symfony** - register it as a PSR-15 middleware / kernel subscriber wrapping `guard`/`observe`.

Observe (default) → learn & approve in the console → flip to **enforce** → off-baseline requests get
`403 blocked_by_nemesis_shield`. Verified end-to-end (learn → enforce → attack) on raw PHP: legit
passes (200); attacks blocked (403).

## LLM Guard (OWASP LLM Top 10)

The same HashLR ML classifier every Nemesis Shield SDK ships - catches obfuscated prompt injection
signature rules miss, scored identically in every language.

```php
require 'NemesisShieldLLM.php';

$v = NemesisShieldLLM::guardLLM($userPrompt, true); // enforce
if ($v['blocked']) {
    // refuse - $v['kind'], $v['score'], $v['owasp'] ("LLM01")
}

$score = NemesisShieldLLM::mlInjectionScore($userPrompt); // 0..1
```

Regex first, then ML. Blocks at ≥ 0.85 (high), flags at ≥ 0.45.

## Full coverage & safe-unlock

**Mount it first / outermost** so *every* route is inspected (not just API routes - attackers hit any path):

```
if (NemesisShield::guard($token)) return;   // at the very top of the request, before routing
```

**What's inspected** (privacy-preserving): method + normalized route + **query-param structure** (names + kinds, never values) + auth flag + status. An off-baseline route, **param structure**, method, or auth state is blocked in enforce mode. Path-traversal segments normalize to `{traversal}`.

**Safe-unlock (break-glass):** the login/auth path is never blocked, so a still-learning baseline can't lock you out. Defaults: `/login /signin /sign-in /auth /oauth /session /wp-login.php /wp-admin`. Override:

```bash
export NEMESIS_SHIELD_BOOTSTRAP="/login,/admin,/healthz"
```

**Verify coverage** - in observe mode, hit a normal route, a param, and a scanner path, then confirm all three appear in the console (Activity / Behaviors):

```bash
curl -s "http://localhost:8080/" >/dev/null
curl -s "http://localhost:8080/search?q=shoes" >/dev/null
curl -s "http://localhost:8080/.env" >/dev/null   # shows up as an off-baseline behavior
```
