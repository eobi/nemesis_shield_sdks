# Nemesis Shield — Go

Native Go SDK for [Nemesis Shield](https://shield.nemesislabs.xyz). Learns your app's normal
behavior; in **enforce mode BLOCKS off-baseline requests** (auth bypass, path traversal, scanners,
unusual methods) before your handlers run. Positive-security, fail-open, privacy-preserving.

```bash
go get github.com/eobi/nemesis_shield_sdks/go
```

## net/http (and chi)

```go
c := nemesis.New(os.Getenv("NEMESIS_TOKEN"))
http.ListenAndServe(":8080", c.Middleware(mux))   // net/http

r := chi.NewRouter()
r.Use(c.Middleware)                                // chi uses the same middleware
```

## Gin

```go
c := nemesis.New(os.Getenv("NEMESIS_TOKEN"))
g.Use(func(ctx *gin.Context) {
    r, authed := ctx.Request, ctx.GetHeader("Authorization") != ""
    if c.Enforcing() {
        if block, reason := c.Decide(c.BuildSketch(r.Method, r.URL.Path, r.URL.Query(), authed, 0)); block {
            ctx.AbortWithStatusJSON(403, gin.H{"error": "blocked_by_nemesis_shield", "reason": reason}); return
        }
    }
    ctx.Next()
    c.Record(c.BuildSketch(r.Method, r.URL.Path, r.URL.Query(), authed, ctx.Writer.Status()))
})
```

## Echo

```go
e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
    return func(ctx echo.Context) error {
        r, authed := ctx.Request(), ctx.Request().Header.Get("Authorization") != ""
        if c.Enforcing() {
            if block, reason := c.Decide(c.BuildSketch(r.Method, r.URL.Path, r.URL.Query(), authed, 0)); block {
                return ctx.JSON(403, map[string]string{"error": "blocked_by_nemesis_shield", "reason": reason})
            }
        }
        err := next(ctx)
        c.Record(c.BuildSketch(r.Method, r.URL.Path, r.URL.Query(), authed, ctx.Response().Status))
        return err
    }
})
```

Shortcut: Echo can adapt the net/http middleware directly — `e.Use(echo.WrapMiddleware(c.Middleware))`.

## Gorilla/mux

Wrap the **router**, not `r.Use(...)`. Gorilla only runs `r.Use` middleware on *matched* routes, so a
scanner hitting an unknown path (`/.env`, `/admin`) would bypass the shield. Wrapping covers every request:

```go
r := mux.NewRouter()
// ...routes...
handler := c.Middleware(r)          // NOT r.Use — see note above
http.ListenAndServe(":8080", handler)
```

## Fiber (fasthttp)

Fiber isn't net/http, so use its adaptor to run the SDK middleware inside Fiber:

```go
import fiberadaptor "github.com/gofiber/fiber/v2/middleware/adaptor"

app := fiber.New()
app.Use(fiberadaptor.HTTPMiddleware(c.Middleware))   // shield runs before your handlers
```

## Beego (MVC)

Beego's `ControllerRegister` is an `http.Handler`, so wrap it at the root:

```go
handler := c.Middleware(web.BeeApp.Handlers)
http.ListenAndServe(":8080", handler)
```

## How enforcement works

Observe (default) → learn & approve behaviors in the console → flip to **enforce** (the SDK polls the
policy in the background, no redeploy) → off-baseline requests get `403 blocked_by_nemesis_shield`.
Verified end-to-end (learn → enforce → attack) on **net/http, chi, Gin, Echo, Gorilla/mux, Fiber and
Beego**: legit passes (200); auth-bypass/BOLA, scanner probes, param tampering and method anomalies are
blocked (403) *before the handler runs*.

## LLM Guard (OWASP LLM Top 10)

Protect an LLM app/agent with the same **HashLR ML classifier** every Nemesis Shield SDK ships — it
catches obfuscated/paraphrased prompt injection that signature rules miss (e.g. `1gn0re pr3vi0us…`),
and scores **identically in every language**.

```go
import nemesis "github.com/eobi/nemesis_shield_sdks/go"

v := nemesis.GuardLLM(userPrompt, true) // true = enforce
if v.Blocked {
    // refuse — v.Kind ("prompt_injection" | "ml_prompt_injection"), v.Score, v.Owasp ("LLM01")
}

score := nemesis.MLInjectionScore(userPrompt) // 0..1, if you want the raw signal
```

Regex rules run first, then the ML for obfuscation. Blocks at score ≥ 0.85 (high), flags at ≥ 0.45.
The model (`ml_weights.json`) is embedded and can be updated centrally.

## Full coverage & safe-unlock

**Mount it first / outermost** so *every* route is inspected (not just API routes — attackers hit any path):

```
handler := client.Middleware(rootMux)   // wrap the ROOT mux so all routes are covered
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
