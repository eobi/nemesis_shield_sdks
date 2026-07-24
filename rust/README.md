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

async fn shield(State(s): State<Arc<Client>>, req: Request, next: Next) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let authed = req.headers().contains_key("authorization") || req.headers().contains_key("cookie");
    if s.enforcing() {
        let sk = s.build_sketch(&method, &path, &[], authed, 0);
        if let Some(reason) = s.decide(&sk) {
            s.record(s.build_sketch(&method, &path, &[], authed, 403));
            return (StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "blocked_by_nemesis_shield", "reason": reason})))
                .into_response();
        }
    }
    let resp = next.run(req).await;
    let status = resp.status().as_u16();
    s.record(s.build_sketch(&method, &path, &[], authed, status));
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

Verified end-to-end (learn → enforce → attack) on axum: legit traffic passes (200); auth bypass,
BOLA, path traversal and scanner probes are blocked (403) and reported.
