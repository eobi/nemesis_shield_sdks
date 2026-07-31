# Nemesis Shield — .NET / C#

Native .NET SDK for [Nemesis Shield](https://shield.nemesislabs.xyz). Learns your app's normal
behavior; in **enforce mode BLOCKS off-baseline requests** (auth bypass, path traversal, scanners,
unusual methods) before your endpoints run. Positive-security, fail-open, privacy-preserving.

**ASP.NET Core** — add `NemesisShield.cs` to your project and register the middleware:
```csharp
app.UseMiddleware<NemesisShield.SentinelMiddleware>();
```
Set `NEMESIS_TOKEN` in the environment.

Observe (default) → learn & approve behaviors in the console → flip to **enforce** (the SDK polls the
policy in the background, no redeploy) → off-baseline requests get `403 blocked_by_nemesis_shield`.
Verified end-to-end (learn → enforce → attack) on ASP.NET Core: legit passes (200); auth bypass,
BOLA, path traversal and scanner probes blocked (403) and reported.

## LLM Guard (OWASP LLM Top 10)

The same HashLR ML classifier every Nemesis Shield SDK ships — catches obfuscated prompt injection
signature rules miss, scored identically in every language. Add `NemesisShieldLLM.cs` +
`ml_weights.json`.

```csharp
using NemesisShield;

var v = LlmGuard.GuardLLM(userPrompt, enforce: true);
if (v.Blocked) {
    // refuse — v.Kind, v.Score, v.Owasp ("LLM01")
}

double score = LlmGuard.MlInjectionScore(userPrompt); // 0..1
```

Regex first, then ML. Blocks at ≥ 0.85 (high), flags at ≥ 0.45.

## Central model updates (hot-swap)

The HashLR model can be retrained and pushed centrally, so SDKs pick up a new version without a redeploy:

```csharp
// Pull the latest signed model (defaults to env NEMESIS_MODEL_URL). Returns the new version, or null
// if nothing newer / rejected. Fail-safe: the embedded model is kept on any error.
int? v = LlmGuard.RefreshModel("https://shield.nemesislabs.xyz/api/v1/model/injection");
int current = LlmGuard.ModelVersion();
```

Bundles are Ed25519-signed; a pinned public key verifies the exact bytes before the swap, so unsigned or
tampered bundles are rejected. Signature verification uses **BouncyCastle** (.NET has no built-in Ed25519
on net8), so add the package to your project:

```
dotnet add package BouncyCastle.Cryptography
```

Run `RefreshModel` on startup and/or on a timer (e.g. hourly). The feature space (`dim`) is fixed across
versions; only weights, bias and thresholds swap.

## Full coverage & safe-unlock

**Mount it first / outermost** so *every* route is inspected (not just API routes — attackers hit any path):

```
app.UseMiddleware<NemesisShield.SentinelMiddleware>();   // BEFORE UseStaticFiles / UseRouting
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
