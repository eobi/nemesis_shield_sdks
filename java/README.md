# Nemesis Shield - Java (JDK 11+, no runtime dependencies)

Native Java SDK for [Nemesis Shield](https://shield.nemesislabs.xyz). Learns your app's normal
behavior; in **enforce mode BLOCKS off-baseline requests** (auth bypass, path traversal, scanners,
unusual methods) before your handlers run. Background policy poller (console-driven enforce, no
redeploy). Positive-security, fail-open.

## Install (Maven Central)

**Maven**
```xml
<dependency>
  <groupId>io.github.eobi</groupId>
  <artifactId>sentinel</artifactId>
  <version>0.1.1</version>
</dependency>
```
**Gradle**
```kotlin
implementation("io.github.eobi:sentinel:0.1.1")
```
Then `import io.github.eobi.sentinel.NemesisShield;` (also `NemesisShieldFilter`, `NemesisShieldLLM`).
The trained ML model (`ml_weights.json`) ships inside the jar. Self-hosting? Set `NEMESIS_ENDPOINT`
(env) or `-Dnemesis.endpoint=` to point at your own Shield.

**Servlet / Spring Boot 3+** - register `NemesisShieldFilter` and set `NEMESIS_TOKEN`:
```java
@Bean
FilterRegistrationBean<NemesisShieldFilter> nemesis() {
    var reg = new FilterRegistrationBean<>(new NemesisShieldFilter());
    reg.addUrlPatterns("/*");
    return reg;
}
```

**Raw (com.sun HttpServer / any handler)**:
```java
var nemesis = new NemesisShield(System.getenv("NEMESIS_TOKEN"));
// start of request:
if (nemesis.guard(method, path, authed, exchange)) return;   // blocked -> 403 written
// after response:
nemesis.observe(method, path, authed, status);
```

Observe (default) → learn & approve behaviors in the console → flip to **enforce** → off-baseline
requests get `403 blocked_by_nemesis_shield`. Verified end-to-end (learn → enforce → attack) on the
raw HttpServer: legit passes (200); attacks blocked (403). The Servlet filter uses the identical
`NemesisShield` client.

## LLM Guard (OWASP LLM Top 10)

The same HashLR ML classifier every Nemesis Shield SDK ships - catches obfuscated prompt injection
signature rules miss, scored identically in every language. `NemesisShieldLLM` and the trained
`ml_weights.json` are included in the dependency (no extra setup).

```java
var v = NemesisShieldLLM.guardLLM(userPrompt, true); // enforce
if (v.blocked) {
    // refuse - v.kind, v.severity, v.owasp ("LLM01")
}

double score = NemesisShieldLLM.mlInjectionScore(userPrompt); // 0..1
```

Regex first, then ML. Blocks at ≥ 0.85 (high), flags at ≥ 0.45.

## Full coverage & safe-unlock

**Mount it first / outermost** so *every* route is inspected (not just API routes - attackers hit any path):

```
reg.addUrlPatterns("/*");   // register the filter across every URL
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
