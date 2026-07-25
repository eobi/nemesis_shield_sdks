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
