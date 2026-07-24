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

## How enforcement works

Observe (default) → learn & approve behaviors in the console → flip to **enforce** (the SDK polls the
policy in the background, no redeploy) → off-baseline requests get `403 blocked_by_nemesis_shield`.
Verified end-to-end on net/http, chi, Gin and Echo: legit passes (200); attacks blocked (403).
