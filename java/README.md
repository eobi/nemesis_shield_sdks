# Nemesis Shield — Java (JDK 11+, no deps)

```java
var nemesis = new NemesisShield(System.getenv("NEMESIS_TOKEN"));
// in a servlet Filter/interceptor, after the response:
nemesis.report(req.getMethod(), req.getRequestURI(), res.getStatus(), authed);
```
Fail-open; async; reports only method/path-shape/status/authenticated. Token: https://shield.nemesislabs.xyz.
