# Nemesis Shield — Ruby

Native Ruby SDK for [Nemesis Shield](https://shield.nemesislabs.xyz). Learns your app's normal
behavior; in **enforce mode BLOCKS off-baseline requests** (auth bypass, path traversal, scanners,
unusual methods) before your app runs. One Rack middleware works with **Rails, Sinatra and any Rack
app**. Positive-security, fail-open, privacy-preserving.

**Rails** — `config/application.rb`:
```ruby
require "nemesis_shield"
config.middleware.use NemesisShield::Middleware, token: ENV["NEMESIS_TOKEN"]
```

**Sinatra**:
```ruby
require "nemesis_shield"
use NemesisShield::Middleware, token: ENV["NEMESIS_TOKEN"]
```

**Rack** (`config.ru`):
```ruby
require "nemesis_shield"
use NemesisShield::Middleware, token: ENV["NEMESIS_TOKEN"]
run MyApp
```

Observe (default) → learn & approve behaviors in the console → flip to **enforce** (the SDK polls the
policy in the background, no redeploy) → off-baseline requests get `403 blocked_by_nemesis_shield`.
Verified end-to-end (learn → enforce → attack) on Rails, Sinatra and Rack: legit passes (200);
attacks blocked (403).

## LLM Guard (OWASP LLM Top 10)

The same HashLR ML classifier every Nemesis Shield SDK ships — catches obfuscated/paraphrased prompt
injection signature rules miss, scored identically in every language.

```ruby
require "nemesis_shield_llm"

v = NemesisShield::LLM.guard_llm(user_prompt, enforce: true)
refuse! if v[:blocked]   # v[:kind], v[:score], v[:owasp] ("LLM01")

score = NemesisShield::LLM.ml_injection_score(user_prompt) # 0..1
```

Regex first, then ML. Blocks at ≥ 0.85 (high), flags at ≥ 0.45.

## Full coverage & safe-unlock

**Mount it first / outermost** so *every* route is inspected (not just API routes — attackers hit any path):

```
use NemesisShield::Middleware, token: ENV["NEMESIS_TOKEN"]   # top of the Rack stack
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
