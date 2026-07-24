# Nemesis Shield — Go

```go
import nemesis "github.com/eobi/nemesis_shield_sdks/go"

handler := nemesis.Middleware(os.Getenv("NEMESIS_TOKEN"))(mux)
http.ListenAndServe(":8080", handler)
```
Or call `nemesis.Report(token, []nemesis.Event{...})` directly. Fail-open; reports only
method/path-shape/status/authenticated. Token: https://shield.nemesislabs.xyz.
