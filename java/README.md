# Nemesis Shield — Java (JDK 11+, no dependencies)

Native Java SDK for [Nemesis Shield](https://shield.nemesislabs.xyz). Learns your app's normal
behavior; in **enforce mode BLOCKS off-baseline requests** (auth bypass, path traversal, scanners,
unusual methods) before your handlers run. Background policy poller (console-driven enforce, no
redeploy). Positive-security, fail-open.

**Servlet / Spring Boot 3+** — register `NemesisShieldFilter` and set `NEMESIS_TOKEN`:
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
