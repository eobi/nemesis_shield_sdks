//! Nemesis Shield - Sentinel SDK for Rust (native: local shape + policy cache + inline blocking).
//!
//! Learns your app's normal behavior; in enforce mode **blocks off-baseline requests** (auth bypass,
//! path traversal, scanners, unusual methods) before your handlers run. Positive-security, fail-open,
//! privacy-preserving - ships only method + route shape + auth, never bodies or secrets. The console
//! flips observe↔enforce with no redeploy (a background thread polls the compiled policy).
//!
//! ```no_run
//! use std::sync::Arc;
//! use nemesis_shield::Client;
//!
//! let shield: Arc<Client> = Client::new(std::env::var("NEMESIS_TOKEN").unwrap_or_default());
//! // In your middleware (axum/actix examples in the README):
//! let sketch = shield.build_sketch("GET", "/orders/123", &[], true, 0);
//! if shield.enforcing() {
//!     if let Some(reason) = shield.decide(&sketch) {
//!         // respond 403 { "error": "blocked_by_nemesis_shield", "reason": reason }
//!     }
//! }
//! shield.record(shield.build_sketch("GET", "/orders/123", &[], true, 200));
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use once_cell::sync::Lazy;
use regex::Regex;

// A hostname path segment (network-zone routes like example.com, sub.example.co.uk). Path segments
// almost never contain dots except hostnames, so collapsing these to {domain} stops per-domain shape
// explosion. Deliberately LOOKAHEAD-FREE so it ports byte-identically to the JS/Go reference and the
// RE2/`regex` engine here. Mirrors RE.domain in packages/shared/src/tokenize.ts.
static DOMAIN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$").unwrap());

pub const DEFAULT_ENDPOINT: &str = "https://shield.nemesislabs.xyz/api/v1/sketches";

pub mod llm;
pub use llm::{guard_llm, ml_injection_score, model_version, refresh_model, LlmVerdict};

/// A query-parameter shape (name + kind, never the value).
#[derive(Clone)]
pub struct Param {
    pub name: String,
    pub kind: String,
}

/// A privacy-preserving request signature.
pub struct Sketch {
    pub route: String,
    pub method: String,
    pub authenticated: bool,
    pub status: u16,
    pub params: Vec<Param>,
    pub shape: String,
}

struct Policy {
    mode: String,
    shapes: HashMap<String, String>, // shape -> "allow" | "block"
    known_bad: HashMap<String, ()>,
    have_baseline: bool,
}

/// Caches the compiled policy and makes fast offline decisions; ships telemetry async.
pub struct Client {
    token: String,
    endpoint: String,
    policy: RwLock<Policy>,
    buffer: Mutex<Vec<String>>,
}

impl Client {
    /// Create a client (production endpoint) and start the background policy poller.
    pub fn new(token: impl Into<String>) -> Arc<Client> {
        Self::with_endpoint(token, DEFAULT_ENDPOINT)
    }

    pub fn with_endpoint(token: impl Into<String>, endpoint: impl Into<String>) -> Arc<Client> {
        let c = Arc::new(Client {
            token: token.into(),
            endpoint: endpoint.into(),
            policy: RwLock::new(Policy {
                mode: "observe".into(),
                shapes: HashMap::new(),
                known_bad: HashMap::new(),
                have_baseline: false,
            }),
            buffer: Mutex::new(Vec::new()),
        });
        if !c.token.is_empty() {
            c.poll();
            let bg = c.clone();
            thread::spawn(move || loop {
                thread::sleep(Duration::from_secs(2));
                bg.flush();
                bg.poll();
            });
        }
        c
    }

    /// True when the console has this app in enforce mode.
    pub fn enforcing(&self) -> bool {
        self.policy.read().unwrap().mode == "enforce"
    }

    /// Break-glass: is this path on the never-block bootstrap allow-list? Prefix match, so a
    /// still-learning baseline can't lock operators out of the doors they need to fix it. Override
    /// with the NEMESIS_SHIELD_BOOTSTRAP env (comma-separated).
    pub fn never_block(path: &str) -> bool {
        const DEFAULT_BOOTSTRAP: [&str; 8] =
            ["/login", "/signin", "/sign-in", "/auth", "/oauth", "/session", "/wp-login.php", "/wp-admin"];
        let p = path.split(['?', '#']).next().unwrap_or(path).to_ascii_lowercase();
        let env = std::env::var("NEMESIS_SHIELD_BOOTSTRAP").unwrap_or_default();
        let list: Vec<String> = if env.trim().is_empty() {
            DEFAULT_BOOTSTRAP.iter().map(|s| s.to_string()).collect()
        } else {
            env.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
        };
        list.iter().any(|b| !b.is_empty() && p.starts_with(&b.to_ascii_lowercase()))
    }

    fn is_int(s: &str) -> bool {
        let t = s.strip_prefix('-').unwrap_or(s);
        !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit())
    }
    fn is_float(s: &str) -> bool {
        let t = s.strip_prefix('-').unwrap_or(s);
        match t.split_once('.') {
            Some((a, b)) => !b.is_empty() && a.bytes().all(|c| c.is_ascii_digit()) && b.bytes().all(|c| c.is_ascii_digit()),
            None => false,
        }
    }
    fn is_hex_chars(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
    }
    fn is_alpha(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphabetic())
    }
    fn is_alnum(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric())
    }
    fn is_email(s: &str) -> bool {
        if s.bytes().any(|b| b.is_ascii_whitespace()) {
            return false;
        }
        match s.split_once('@') {
            Some((l, d)) => !l.is_empty() && !d.contains('@') && match d.rsplit_once('.') {
                Some((a, b)) => !a.is_empty() && !b.is_empty(),
                None => false,
            },
            None => false,
        }
    }
    fn is_url(s: &str) -> bool {
        let l = s.to_ascii_lowercase();
        ((l.starts_with("http://") && s.len() > 7) || (l.starts_with("https://") && s.len() > 8))
            && !s.bytes().any(|b| b.is_ascii_whitespace())
    }
    fn is_ipv4(s: &str) -> bool {
        let parts: Vec<&str> = s.split('.').collect();
        parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
    }
    fn is_ipv6(s: &str) -> bool {
        s.contains(':')
            && s.bytes().any(|b| b.is_ascii_hexdigit())
            && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b':')
    }
    fn is_date(s: &str) -> bool {
        let b = s.as_bytes();
        b.len() >= 10
            && b[0..4].iter().all(|c| c.is_ascii_digit())
            && b[4] == b'-'
            && b[5].is_ascii_digit() && b[6].is_ascii_digit()
            && b[7] == b'-'
            && b[8].is_ascii_digit() && b[9].is_ascii_digit()
    }
    fn is_jwt(s: &str) -> bool {
        let parts: Vec<&str> = s.split('.').collect();
        parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
    }
    // A run of 7+ letters => reads like a word / route name, not an opaque id/token.
    fn has_word_run(s: &str) -> bool {
        let mut run = 0u32;
        for c in s.chars() {
            if c.is_ascii_alphabetic() {
                run += 1;
                if run >= 7 {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        false
    }

    fn is_b64(s: &str) -> bool {
        let core = s.trim_end_matches('=');
        let pad = s.len() - core.len();
        pad <= 2 && !core.is_empty() && core.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    }
    fn is_uuid(s: &str) -> bool {
        let b = s.as_bytes();
        b.len() == 36
            && s.char_indices().all(|(i, c)| {
                if i == 8 || i == 13 || i == 18 || i == 23 {
                    c == '-'
                } else {
                    c.is_ascii_hexdigit()
                }
            })
    }

    /// Collapse ids in a path: `/orders/123` -> `/orders/{int}`, uuids -> `{uuid}`, long hex -> `{hex}`.
    pub fn normalize_path(path: &str) -> String {
        let path = path.split('?').next().unwrap_or("");
        let path = path.split('#').next().unwrap_or(path);
        let out = path
            .split('/')
            .map(|s| {
                if s.is_empty() {
                    return s.to_string();
                }
                if s.contains("..") {
                    return "{traversal}".to_string(); // keeps ".." out of telemetry
                }
                match Self::kind_of(s) {
                    "int" | "float" => "{int}".to_string(),
                    "uuid" => "{uuid}".to_string(),
                    "hex" => "{hex}".to_string(),
                    "base64" => "{token}".to_string(),
                    // a long alnum segment is likely an id - unless it reads like a word / route name
                    "alnum" if s.len() >= 12 && !Self::has_word_run(s) => "{id}".to_string(),
                    "alnum" => s.to_string(),
                    _ => {
                        // Hostnames (network-zone routes) collapse to {domain}; underscored generated ids
                        // that carry a digit (or are very long) collapse to {id}. Route names are single
                        // words or kebab-case and never carry underscores, so kebab like "iso-27001" stays.
                        if DOMAIN_RE.is_match(s) {
                            "{domain}".to_string()
                        } else if s.contains('_')
                            && (s.bytes().any(|b| b.is_ascii_digit()) || s.len() >= 20)
                        {
                            "{id}".to_string()
                        } else {
                            s.to_string()
                        }
                    }
                }
            })
            .collect::<Vec<_>>()
            .join("/");
        if out.is_empty() {
            "/".to_string()
        } else {
            out
        }
    }

    // Canonical value taxonomy - must match the shared engine (tokenize.ts) byte-for-byte.
    fn kind_of(v: &str) -> &'static str {
        if v.is_empty() {
            "empty"
        } else if Self::is_uuid(v) {
            "uuid"
        } else if Self::is_email(v) {
            "email"
        } else if Self::is_url(v) {
            "url"
        } else if Self::is_ipv4(v) {
            "ipv4"
        } else if Self::is_ipv6(v) {
            "ipv6"
        } else if Self::is_jwt(v) {
            "jwt"
        } else if Self::is_date(v) {
            "date"
        } else if Self::is_int(v) {
            "int"
        } else if Self::is_float(v) {
            "float"
        } else if v.len() >= 16 && Self::is_hex_chars(v) {
            "hex"
        } else if v.len() >= 16 && Self::is_b64(v) && !Self::has_word_run(v) {
            "base64"
        } else if Self::is_alpha(v) {
            "alpha"
        } else if Self::is_alnum(v) {
            "alnum"
        } else {
            "string"
        }
    }

    fn fnv1a(s: &str) -> String {
        let mut h: u32 = 0x811c_9dc5;
        for &b in s.as_bytes() {
            h ^= b as u32;
            h = h.wrapping_mul(0x0100_0193);
        }
        format!("{:08x}", h)
    }

    // Canonical shape input: keys SORTED (auth, method, params, route); params [name, kind, nested];
    // status excluded so enforcement decides pre-response. Byte-identical to the shared engine.
    fn canon(route: &str, method: &str, params: &[Param], auth: bool) -> String {
        let mut p = String::from("[");
        for (i, pp) in params.iter().enumerate() {
            if i > 0 {
                p.push(',');
            }
            p.push_str(&format!("[\"{}\",\"{}\",0]", pp.name, pp.kind));
        }
        p.push(']');
        format!(
            "{{\"auth\":{},\"method\":\"{}\",\"params\":{},\"route\":\"{}\"}}",
            if auth { 1 } else { 0 },
            method.to_uppercase(),
            p,
            route
        )
    }

    /// Compute the request signature. `query` is a slice of (name, value) pairs; pass `&[]` if none.
    // Analytics / click-tracking query params carry no application logic and are the main cause of
    // shape explosion (every ad/campaign link adds different ones). Stripped from the signature so a
    // UTM'd request matches the bare route, while real params (and any attack in them) stay modeled.
    // Shared, identical across every Nemesis Shield SDK so the shape hash matches everywhere.
    fn is_tracking_param(name: &str) -> bool {
        let n = name.to_ascii_lowercase();
        const PREFIXES: [&str; 7] = ["utm_", "mtm_", "pk_", "hsa_", "matomo_", "piwik_", "ga_"];
        const EXACT: [&str; 28] = [
            "gclid", "gbraid", "wbraid", "dclid", "gclsrc", "fbclid", "msclkid", "twclid", "ttclid",
            "yclid", "igshid", "scid", "wickedid", "_ga", "_gl", "_hsenc", "_hsmi", "mc_cid",
            "mc_eid", "vero_id", "vero_conv", "oly_anon_id", "oly_enc_id", "_openstat", "rb_clickid",
            "s_cid", "epik", "sccid",
        ];
        PREFIXES.iter().any(|p| n.starts_with(p)) || EXACT.contains(&n.as_str())
    }

    pub fn build_sketch(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        authed: bool,
        status: u16,
    ) -> Sketch {
        let route = Self::normalize_path(path);
        let mut sorted: Vec<&(String, String)> =
            query.iter().filter(|(k, _)| !Self::is_tracking_param(k)).collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let params: Vec<Param> = sorted
            .iter()
            .map(|(k, v)| Param {
                name: k.clone(),
                kind: Self::kind_of(v).to_string(),
            })
            .collect();
        let shape = Self::fnv1a(&Self::canon(&route, method, &params, authed));
        Sketch {
            route,
            method: method.to_uppercase(),
            authenticated: authed,
            status,
            params,
            shape,
        }
    }

    /// Positive-security verdict. Returns the block reason, or `None` to allow.
    pub fn decide(&self, s: &Sketch) -> Option<String> {
        let p = self.policy.read().unwrap();
        match p.shapes.get(&s.shape).map(String::as_str) {
            Some("allow") => return None,
            Some("block") => return Some("policy: blocked shape".into()),
            _ => {}
        }
        if p.known_bad.contains_key(&s.shape) {
            return Some("global threat intelligence".into());
        }
        if p.have_baseline {
            return Some("off-baseline: unapproved behavior".into());
        }
        None
    }

    fn sketch_json(s: &Sketch) -> String {
        let mut p = String::from("[");
        for (i, pp) in s.params.iter().enumerate() {
            if i > 0 {
                p.push(',');
            }
            p.push_str(&format!("{{\"name\":\"{}\",\"kind\":\"{}\"}}", pp.name, pp.kind));
        }
        p.push(']');
        format!(
            "{{\"route\":\"{}\",\"method\":\"{}\",\"authenticated\":{},\"status\":{},\"params\":{},\"shape\":\"{}\"}}",
            s.route, s.method, s.authenticated, s.status, p, s.shape
        )
    }

    /// Buffer a sketch for async shipment (fire-and-forget).
    pub fn record(&self, s: Sketch) {
        let full = {
            let mut buf = self.buffer.lock().unwrap();
            buf.push(Self::sketch_json(&s));
            buf.len() >= 50
        };
        if full {
            self.flush();
        }
    }

    fn flush(&self) {
        let batch: Vec<String> = {
            let mut b = self.buffer.lock().unwrap();
            if b.is_empty() {
                return;
            }
            std::mem::take(&mut *b)
        };
        self.send(&format!("[{}]", batch.join(",")));
    }

    fn poll(&self) {
        self.send("[]");
    }

    fn send(&self, sketches_json: &str) {
        if self.token.is_empty() {
            return;
        }
        let body = format!("{{\"sketches\":{}}}", sketches_json);
        let resp = ureq::post(&self.endpoint)
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Content-Type", "application/json")
            .timeout(Duration::from_secs(3))
            .send_string(&body);
        if let Ok(r) = resp {
            if let Ok(txt) = r.into_string() {
                self.apply_policy(&txt);
            }
        }
        // any transport error: fail open (app is untouched)
    }

    fn apply_policy(&self, body: &str) {
        let v: serde_json::Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(_) => return,
        };
        let mut p = self.policy.write().unwrap();
        if let Some(m) = v.get("mode").and_then(|x| x.as_str()) {
            p.mode = m.to_string();
        }
        if let Some(pol) = v.get("policy") {
            if let Some(sh) = pol.get("shapes").and_then(|x| x.as_object()) {
                let mut next = HashMap::new();
                for (k, val) in sh {
                    next.insert(k.clone(), val.as_str().unwrap_or("allow").to_string());
                }
                p.have_baseline = !next.is_empty();
                p.shapes = next;
            }
            if let Some(kb) = pol.get("knownBad").and_then(|x| x.as_array()) {
                let mut next = HashMap::new();
                for s in kb {
                    if let Some(s) = s.as_str() {
                        next.insert(s.to_string(), ());
                    }
                }
                p.known_bad = next;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_collapses_ids() {
        assert_eq!(Client::normalize_path("/orders/123"), "/orders/{int}");
        assert_eq!(
            Client::normalize_path("/u/550e8400-e29b-41d4-a716-446655440000"),
            "/u/{uuid}"
        );
        assert_eq!(Client::normalize_path("/search?q=x"), "/search");
    }

    #[test]
    fn shape_is_stable_and_status_independent() {
        let c = Client::with_endpoint("", DEFAULT_ENDPOINT);
        let a = c.build_sketch("GET", "/orders/123", &[], true, 200);
        let b = c.build_sketch("GET", "/orders/999", &[], true, 500);
        // same route shape + method + auth => same signature regardless of id or status
        assert_eq!(a.shape, b.shape);
        // auth changes the signature
        let unauth = c.build_sketch("GET", "/orders/123", &[], false, 200);
        assert_ne!(a.shape, unauth.shape);
    }

    #[test]
    fn no_baseline_fails_open() {
        let c = Client::with_endpoint("", DEFAULT_ENDPOINT);
        let s = c.build_sketch("GET", "/anything", &[], false, 0);
        assert!(c.decide(&s).is_none()); // never block without a learned baseline
    }
}

#[cfg(test)]
mod shape_parity {
    use super::*;
    #[test]
    fn canonical_shapes() {
        let c = Client::with_endpoint("", DEFAULT_ENDPOINT);
        assert_eq!(c.build_sketch("GET", "/orders/123", &[], false, 200).shape, "3e8cf0b3");
        assert_eq!(c.build_sketch("GET", "/orders/123", &[("expand".into(), "items".into())], false, 200).shape, "440c7e37");
    }
}

#[cfg(test)]
mod deep_coverage {
    use super::*;
    use std::sync::Arc;

    fn client(mode: &str, allow: &[String], known_bad: &[String]) -> Arc<Client> {
        let c = Client::with_endpoint("", DEFAULT_ENDPOINT); // empty token -> no poller, no network
        {
            let mut p = c.policy.write().unwrap();
            p.mode = mode.to_string();
            for s in allow { p.shapes.insert(s.clone(), "allow".into()); }
            for s in known_bad { p.known_bad.insert(s.clone(), ()); }
            p.have_baseline = !allow.is_empty() || !known_bad.is_empty();
        }
        c
    }
    fn split(url: &str) -> (&str, Vec<(String, String)>) {
        match url.split_once('?') {
            Some((p, q)) => (
                p,
                q.split('&').filter(|s| !s.is_empty()).map(|kv| {
                    let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                    (k.to_string(), v.to_string())
                }).collect(),
            ),
            None => (url, vec![]),
        }
    }
    fn shape(c: &Client, m: &str, url: &str, a: bool) -> String {
        let (p, q) = split(url);
        c.build_sketch(m, p, &q, a, 0).shape
    }
    fn blocked(c: &Client, m: &str, url: &str, a: bool) -> bool {
        let (p, q) = split(url);
        if !c.enforcing() || Client::never_block(p) { return false; }
        c.decide(&c.build_sketch(m, p, &q, a, 0)).is_some()
    }

    #[test]
    fn sees_and_blocks_attacks_from_any_route() {
        let r = Client::with_endpoint("", DEFAULT_ENDPOINT);
        let allow = vec![
            shape(&r, "GET", "/", false),
            shape(&r, "GET", "/products/12345", false),
            shape(&r, "GET", "/search?q=shoes", false),
            shape(&r, "POST", "/api/orders", true),
        ];
        // query params change the shape (deep, not just route)
        assert_ne!(shape(&r, "GET", "/search?q=x", false), shape(&r, "GET", "/search?q=x&inject=1", false));
        assert_ne!(shape(&r, "GET", "/search?q=shoes", false), shape(&r, "GET", "/search?q=%27+OR+1", false));

        let c = client("enforce", &allow, &[]);
        // approved passes
        assert!(!blocked(&c, "GET", "/", false));
        assert!(!blocked(&c, "GET", "/products/999", false));
        assert!(!blocked(&c, "GET", "/search?q=boots", false));
        assert!(!blocked(&c, "POST", "/api/orders", true));
        // attacks blocked
        assert!(blocked(&c, "GET", "/.env", false));
        assert!(blocked(&c, "GET", "/wp-config.php.bak", false));
        assert!(blocked(&c, "GET", "/search?q=x&cmd=id", false)); // injected param
        assert!(blocked(&c, "POST", "/", false));                 // method anomaly
        assert!(blocked(&c, "GET", "/api/orders", false));        // auth anomaly
        assert!(blocked(&c, "GET", "/admin/config", false));

        // knownBad (global intel)
        let bad = shape(&r, "POST", "/xmlrpc.php", false);
        assert!(blocked(&client("enforce", &allow, &[bad]), "POST", "/xmlrpc.php", false));

        // safe-unlock - auth path never blocked
        assert!(!blocked(&c, "POST", "/login?next=x", false));
        assert!(!blocked(&c, "GET", "/wp-login.php", false));
        assert!(!blocked(&c, "GET", "/wp-admin/options.php", false));

        // fail-open + observe
        assert!(!blocked(&client("enforce", &[], &[]), "GET", "/.env", false));
        assert!(!blocked(&client("observe", &allow, &[]), "GET", "/.env", false));
    }
}
