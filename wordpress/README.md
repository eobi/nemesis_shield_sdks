# Nemesis Shield — WordPress

A WordPress plugin that connects your site to the [Nemesis Shield](https://shield.nemesislabs.xyz)
service for positive-security runtime protection. The service **learns your site's normal behaviour**
and, in enforce mode, has the plugin **block off-baseline requests** (auth bypass, path traversal,
scanners, unusual methods) across the front end, REST API, and admin-ajax. Privacy-preserving and
fail-open: if the service is unreachable, your site is completely unaffected.

The plugin ships **WordPress-native** classes ([`nemesis-shield/lib/`](nemesis-shield/lib/)): all
network calls go through the WordPress HTTP API (`wp_remote_post`) and the compiled policy is cached
with the Transients API. The shape/decision math is byte-for-byte identical to the shared
[PHP SDK](../php) (enforced by the parity test below), so a WordPress site is treated exactly like
every other Nemesis Shield integration. The block decision is applied **in-process** from the policy
the service returns; no proxy, no sidecar. The bundled LLM Guard classifier runs entirely on your
server.

## Install

1. Sign up at **[shield.nemesislabs.xyz](https://shield.nemesislabs.xyz)** → **Protect an app** → copy the install token (`nsk_…`).
2. Copy the [`nemesis-shield/`](nemesis-shield/) folder into `wp-content/plugins/`, or zip it and upload via **Plugins → Add New → Upload**.
3. Activate **Nemesis Shield**, then set the token one of two ways:

   **Recommended — `wp-config.php`** (keeps the token out of the database):
   ```php
   define('NEMESIS_SHIELD_TOKEN', 'nsk_your_site_token');
   ```
   **Or** in **Settings → Nemesis Shield**, paste the token.

That's it. Traffic starts building a per-site baseline immediately.

## How it works

1. **Observe** (default) — every request's privacy-preserving *shape* (method + normalized path like
   `/shop/product/123` → `/shop/product/{int}`, param kinds, and an authenticated flag — **never**
   bodies, values, cookies, or secrets) is recorded to build your baseline.
2. **Approve** — review learned behaviours in the console and approve the legitimate ones.
3. **Enforce** — flip the app to enforce in the console. Requests whose shape isn't approved are
   blocked with `403 blocked_by_nemesis_shield`. No redeploy — the mode is pulled live (short-TTL
   policy cache).

**Where it gates:** the front end and REST API (`rest_pre_dispatch`) are enforced. Regular **wp-admin
page loads, wp-login.php, and cron are never blocked** so a still-learning baseline can never lock you
out of your dashboard. Tick **Protect wp-admin** to additionally enforce the `admin-ajax` /
`admin-post` APIs (off-baseline actions blocked), while dashboard page loads stay recoverable.

**How deep the shape goes:** not just the URL. The signature includes the request method, the
normalized path, the **names + value-kinds of the query, POST-form, and REST body parameters**, and
the `admin-ajax` / `admin-post` action, so state-changing writes are distinguished instead of
collapsing into a single "POST /path". Values, bodies, cookies, and secrets are never sent.

### Settings

| Setting | Purpose |
|---|---|
| **Install token** | `nsk_…`. Overridden by the `NEMESIS_SHIELD_TOKEN` constant / `NEMESIS_TOKEN` env if set. |
| **Protect wp-admin** | Also enforce the `admin-ajax` / `admin-post` APIs (off by default). Dashboard page loads stay observe-only regardless, so you can't be locked out. |
| **Endpoint (advanced)** | Point at a self-hosted / on-prem Shield. Blank = Nemesis Shield cloud. |

### LLM Guard (optional)

If your site calls an LLM (AI chatbot, content assistant), guard the prompt before you send it — the
same OWASP-LLM-Top-10 classifier every Shield SDK ships:

```php
$v = nemesis_shield_guard_llm( $user_prompt, true ); // enforce
if ( $v['blocked'] ) {
    wp_die( 'Request blocked.' ); // $v['kind'], $v['score'], $v['owasp'] ("LLM01")
}
```

## Testing

Three ways to test locally, all included.

### 1. Deterministic behaviour test — no Docker, just PHP

Starts a local mock Shield, drives the plugin's real gate/observe logic through it, and asserts it
**understands** (reports the correct normalized shapes, matching the SDK byte-for-byte),
**gates** (blocks off-baseline / scanner / unusual-method / knownBad requests while approved ones
pass, on both the front end and REST), and **fails open**.

```bash
./run-tests.sh
```
```
1 · Understands — observe mode learns the correct, normalized shapes ✓✓✓✓✓
2 · Gates — enforce mode blocks off-baseline, approved passes         ✓✓✓✓✓
3 · Gates — global threat intelligence (knownBad)                     ✓
4 · Gates the REST API (rest_pre_dispatch)                            ✓✓
5 · Never locks the admin out (admin observe-only by default)         ✓
6 · Fails open — Shield unreachable never breaks the site            ✓
ALL 26 CHECKS PASSED
```

### 2. Real-WordPress end-to-end — Docker

Spins up **actual WordPress + MariaDB** and a mock Shield, installs and activates the plugin, then
over real HTTP: learns in observe mode → approves the learned shapes → flips to enforce → confirms
approved traffic returns `200` and scanner / off-baseline requests return `403
blocked_by_nemesis_shield`, plus fail-open when the mock is stopped.

```bash
./tests/e2e.sh            # needs Docker
docker compose down -v    # teardown
```

### 3. Interactive real WordPress — no Docker

Boots a real WordPress with the plugin active (SQLite via wp-now / WordPress Playground) so you can
click through the settings screen, test with your real install token, and run the **Plugin Check**
plugin before submitting to WordPress.org. Needs Node.

```bash
./test-local.sh          # opens http://localhost:8881 ; Ctrl-C to stop
```

Then in the browser: log in, set your token under **Settings → Nemesis Shield**, browse to generate
observed behaviors, and run **Tools → Plugin Check** after installing the Plugin Check plugin.

## Maintenance

The WP-native classes are hand-maintained here (they use the WP HTTP API + Transients, unlike the
generic PHP SDK). Only the shared ML model is synced. After the shared model changes in
[`../php`](../php), re-sync it, then run the parity test:

```bash
./sync-lib.sh     # copies ml_weights.json only
./run-tests.sh    # asserts byte-for-byte shape parity with the canonical PHP SDK
```

MIT © Nemesis Labs

## Safe-unlock (break-glass)

The front end and REST API are enforced. Regular **wp-admin page loads, wp-login.php and cron are never blocked** so a still-learning baseline can never lock you out; the `admin-ajax` / `admin-post` APIs become enforceable when you tick *Protect wp-admin* (dashboard pages stay observe-only either way, so the settings page is always reachable). The login/auth path is always break-glass — defaults `/login /signin /sign-in /auth /oauth /session /wp-login.php`, overridable with the `NEMESIS_SHIELD_BOOTSTRAP` env (comma-separated). Query, POST-form and REST body parameter structure is fed into the shape, the admin-ajax action is folded into the route, and path-traversal segments normalize to `{traversal}`.
