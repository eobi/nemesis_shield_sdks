# Nemesis Shield — Rust

Native Rust SDK for [Nemesis Shield](https://shield.nemesislabs.xyz). Learns your app's normal
behavior; in **enforce mode BLOCKS off-baseline requests** (auth bypass, path traversal, scanners,
unusual methods) before your handlers run. Positive-security, fail-open, privacy-preserving — the
console flips observe↔enforce with no redeploy (a background thread polls the compiled policy).

```toml
[dependencies]
nemesis-shield = "0.1"
```

Set `NEMESIS_TOKEN` in the environment. The core is framework-agnostic; wire it into your web
framework's middleware once.

## axum (tower)

```rust
use std::sync::Arc;
use axum::{
    Router, routing::get, Json,
    extract::{State, Request},
    middleware::{self, Next},
    response::{Response, IntoResponse},
    http::StatusCode,
};
use nemesis_shield::Client;

// Feed the query-param STRUCTURE (names + kinds, never values) so param tampering on a known
// route is caught, not just unknown paths.
fn query_of(req: &Request) -> Vec<(String, String)> {
    req.uri().query().map(|q| {
        q.split('&').filter(|s| !s.is_empty()).map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (k.to_string(), v.to_string())
        }).collect()
    }).unwrap_or_default()
}

async fn shield(State(s): State<Arc<Client>>, req: Request, next: Next) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query = query_of(&req);
    let authed = req.headers().contains_key("authorization")
        || req.headers().contains_key("cookie")
        || req.headers().contains_key("x-api-key");
    // enforce, but never block the login/auth path (break-glass) so a bad baseline can't lock you out
    if s.enforcing() && !Client::never_block(&path) {
        let sk = s.build_sketch(&method, &path, &query, authed, 0);
        if let Some(reason) = s.decide(&sk) {
            s.record(s.build_sketch(&method, &path, &query, authed, 403));
            return (StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "blocked_by_nemesis_shield", "reason": reason})))
                .into_response();
        }
    }
    let resp = next.run(req).await;
    let status = resp.status().as_u16();
    s.record(s.build_sketch(&method, &path, &query, authed, status));
    resp
}

let shield_client = Client::new(std::env::var("NEMESIS_TOKEN").unwrap_or_default());
let app = Router::new()
    .route("/", get(|| async { "ok" }))
    .layer(middleware::from_fn_with_state(shield_client.clone(), shield))
    .with_state(shield_client);
```

## actix-web

```rust
use actix_web::{dev::{Service, ServiceRequest}, HttpResponse};

// In an actix middleware / wrap_fn, at request start:
let authed = req.headers().contains_key("authorization") || req.headers().contains_key("cookie");
if shield.enforcing() {
    let sk = shield.build_sketch(req.method().as_str(), req.path(), &[], authed, 0);
    if let Some(reason) = shield.decide(&sk) {
        shield.record(shield.build_sketch(req.method().as_str(), req.path(), &[], authed, 403));
        return Ok(req.into_response(
            HttpResponse::Forbidden().json(serde_json::json!({
                "error": "blocked_by_nemesis_shield", "reason": reason
            }))));
    }
}
// ... after the response, record the observed status.
```

## How enforcement works

1. **Observe** (default) — the SDK records the *shape* of every request (method + normalized route +
   auth; never bodies) and builds a per-app baseline in the console.
2. **Approve** — review learned behaviors in the console; approve the legitimate ones (auto-approved
   during the learning window).
3. **Enforce** — flip the app to enforce. Any request whose shape isn't in the approved baseline is
   blocked with `403 blocked_by_nemesis_shield` and reported as a finding. No redeploy — the SDK
   picks up the mode change on its next poll.

Verified end-to-end (learn → enforce → attack) on **axum and actix-web** (8/8 each): legit traffic
passes (200); auth bypass, BOLA, path traversal, param tampering, method and auth anomalies are
blocked (403) before the handler runs; the login path stays reachable (break-glass).

## LLM Guard (OWASP LLM Top 10)

The same HashLR ML classifier every Nemesis Shield SDK ships — catches obfuscated prompt injection
signature rules miss, scored identically in every language.

```rust
use nemesis_shield::guard_llm;

let v = guard_llm(&user_prompt, true); // enforce
if v.blocked {
    // refuse — v.kind, v.score, v.owasp ("LLM01")
}

let score = nemesis_shield::ml_injection_score(&user_prompt); // 0..1
```

Regex first, then ML. Blocks at ≥ 0.85 (high), flags at ≥ 0.45.

## Full coverage & safe-unlock

**Mount it first / outermost** so *every* route is inspected (not just API routes — attackers hit any path):

```
.layer(middleware::from_fn_with_state(shield.clone(), shield))   // outermost layer
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
