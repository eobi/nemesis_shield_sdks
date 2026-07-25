# Nemesis Shield — PHP

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

**Laravel** — register `NemesisShieldMiddleware` (ships in this repo) globally and set `NEMESIS_TOKEN`.
**Symfony** — register it as a PSR-15 middleware / kernel subscriber wrapping `guard`/`observe`.

Observe (default) → learn & approve in the console → flip to **enforce** → off-baseline requests get
`403 blocked_by_nemesis_shield`. Verified end-to-end (learn → enforce → attack) on raw PHP: legit
passes (200); attacks blocked (403).

## LLM Guard (OWASP LLM Top 10)

The same HashLR ML classifier every Nemesis Shield SDK ships — catches obfuscated prompt injection
signature rules miss, scored identically in every language.

```php
require 'NemesisShieldLLM.php';

$v = NemesisShieldLLM::guardLLM($userPrompt, true); // enforce
if ($v['blocked']) {
    // refuse — $v['kind'], $v['score'], $v['owasp'] ("LLM01")
}

$score = NemesisShieldLLM::mlInjectionScore($userPrompt); // 0..1
```

Regex first, then ML. Blocks at ≥ 0.85 (high), flags at ≥ 0.45.
