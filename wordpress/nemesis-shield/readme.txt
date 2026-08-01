=== Nemesis Shield ===
Contributors: davidobi023
Tags: security, firewall, waf, malware, brute-force
Requires at least: 5.9
Tested up to: 6.8
Requires PHP: 7.2
Stable tag: 1.0.0
License: MIT
License URI: https://opensource.org/licenses/MIT

Connects your site to the Nemesis Shield service for positive-security protection that blocks off-baseline requests. Privacy-preserving, fail-open.

== Description ==

Nemesis Shield connects your WordPress site to the **Nemesis Shield service**, a cloud security platform that provides **positive-security runtime protection**. Instead of chasing an endless blocklist of known attacks, the service **learns what your site normally does** and, in enforce mode, has the plugin **block anything off-baseline** (auth bypass, path traversal, vulnerability scanners, unusual methods) across the front end, the REST API, and admin-ajax.

The service is where the value lives: the behavioural learning, the approval console, the enforcement mode, and the global threat intelligence all run in the Nemesis Shield cloud. This plugin is the connector. It computes a privacy-preserving *shape* of each request, sends those shapes to the service, and applies the decision the service returns. You will need a free Nemesis Shield account to use it (sign up at [shield.nemesislabs.xyz](https://shield.nemesislabs.xyz)).

**How it works, in three steps: observe, approve, enforce.**

1. **Observe** (default). Each request's privacy-preserving *shape* is sent to the service to build your baseline: the HTTP method, a normalized path (`/shop/product/123` becomes `/shop/product/{int}`), the kinds of parameters present, and whether the caller is authenticated. **Never** bodies, values, cookies, or secrets.
2. **Approve.** Review the learned behaviours in the [Shield console](https://shield.nemesislabs.xyz) and approve the legitimate ones.
3. **Enforce.** Set the app to enforce in the console. Requests whose shape the service has not approved are blocked with `403 blocked_by_nemesis_shield`. No redeploy: the mode is pulled live.

**Privacy-preserving.** Only the abstract shape of a request is computed. Request bodies, query values, cookies, headers, and secrets are never sent.

**Fail-open by design.** If the service is ever unreachable, requests are forwarded untouched. The plugin can never take your site offline.

**Never locks you out.** The front end and REST API are enforced; **wp-admin, admin-ajax, wp-login.php, and cron are observe-only by default** so a still-learning baseline can never lock you out of your own dashboard. Tick *Protect wp-admin* to enforce there too. The login and auth paths are never blocked.

**Global threat intelligence.** Beyond your own baseline, the service's shared threat list blocks shapes seen attacking other sites (for example `POST /xmlrpc.php` floods) out of the box.

**LLM Guard (optional).** If your site calls an LLM (an AI chatbot or content assistant), guard the prompt before you send it with the bundled OWASP-LLM-Top-10 classifier, which runs entirely on your server:

`$v = nemesis_shield_guard_llm( $user_prompt, true );`
`if ( $v['blocked'] ) { wp_die( 'Request blocked.' ); }`

Nemesis Shield is part of the [Nemesis Labs](https://nemesislabs.xyz) security platform. A free tier is available.

== External services ==

This plugin connects to the Nemesis Shield service, operated by Nemesis Labs, to provide its protection. It is required for the plugin to function.

**What is sent, and when.** On each request to your site, the plugin sends a privacy-preserving *shape* of that request to `https://shield.nemesislabs.xyz/api/v1/sketches`, authenticated with the install token you configure. A shape consists of: the HTTP method, a normalized request path (numeric and identifier segments are replaced with placeholders such as `{int}`), the *kinds* of query parameters present (for example "integer" or "email", never their values), whether the request was authenticated, and the resulting HTTP status. In enforce mode the plugin also fetches the compiled allow-list policy from the same endpoint. **The plugin never sends request bodies, query values, cookie values, headers, personal data, or secrets.**

If you set a custom endpoint in the plugin settings, requests go to that endpoint instead of the Nemesis Shield cloud.

The LLM Guard helper (`nemesis_shield_guard_llm`) runs entirely on your own server using a bundled model and does not contact any external service.

- Service: Nemesis Shield (Nemesis Labs)
- Terms of Service: https://nemesislabs.xyz/legal/terms
- Privacy Policy: https://nemesislabs.xyz/legal/privacy

== Installation ==

1. Sign up at [shield.nemesislabs.xyz](https://shield.nemesislabs.xyz), choose **Protect an app**, and copy the install token (it starts with `nsk_`).
2. Install the plugin, either from **Plugins → Add New** inside WordPress, or by uploading the zip via **Plugins → Add New → Upload**.
3. Activate **Nemesis Shield**.
4. Provide the token one of two ways:
   * **Recommended.** Add `define('NEMESIS_SHIELD_TOKEN', 'nsk_your_site_token');` to `wp-config.php`. This keeps the token out of the database.
   * **Or**, paste it into **Settings → Nemesis Shield**.

That is all. Traffic immediately starts building a per-site baseline in observe mode. When you are ready, approve the learned behaviours in the console and switch the app to enforce.

== Frequently Asked Questions ==

= Will this block my real visitors? =

Not in observe mode, which is the default. Nothing is ever blocked until you review the learned behaviours in the console, approve the legitimate ones, and deliberately switch the app to enforce. Even then, wp-admin, admin-ajax, login, and cron stay observe-only unless you opt in.

= What data leaves my site? =

Only a privacy-preserving *shape* of each request: the HTTP method, a normalized path, the kinds of parameters present, and an authenticated flag. Request bodies, query values, cookies, headers, and secrets are never sent.

= What happens if Nemesis Shield is unreachable? =

The plugin fails open: requests are forwarded untouched and your site is completely unaffected. It can never take your site offline.

= Do I need a proxy, agent, or sidecar? =

No. The block decision is made in-process inside PHP, using a cached copy of your compiled policy. There is nothing else to run.

= Is there a free plan? =

Yes. Sign up at [shield.nemesislabs.xyz](https://shield.nemesislabs.xyz) and protect your first app on the free tier.

= Can I keep the token out of the database? =

Yes, and it is recommended. Define `NEMESIS_SHIELD_TOKEN` in `wp-config.php` (or set the `NEMESIS_TOKEN` environment variable). When present, the Settings field is ignored.

= Does it work with the REST API? =

Yes. The REST API is gated at `rest_pre_dispatch`, so an off-baseline route is blocked with a proper JSON 403 before its handler ever runs.

= Can I point it at a self-hosted Shield? =

Yes. Set the endpoint under **Settings → Nemesis Shield → Endpoint (advanced)**, or define `NEMESIS_SHIELD_ENDPOINT` in `wp-config.php`. Leave it blank to use the Nemesis Shield cloud.

== Screenshots ==

1. The Nemesis Shield settings screen: install token, Protect wp-admin toggle, and advanced endpoint.
2. An off-baseline request blocked with a 403 blocked_by_nemesis_shield response, stopped before WordPress ran.

== Changelog ==

= 1.0.0 =
* Initial release.
* Connects your site to the Nemesis Shield service for positive-security protection on the front end and REST API (rest_pre_dispatch), with observe / approve / enforce driven live from the console.
* All network calls use the WordPress HTTP API; the compiled policy is cached with the Transients API.
* wp-admin, admin-ajax, wp-login.php, and cron observe-only by default; optional Protect wp-admin toggle.
* Privacy-preserving request shaping: only the request shape is sent; bodies, values, and secrets never leave the site.
* Global threat-intelligence blocking from the service.
* Fail-open when the service is unreachable.
* Optional LLM Guard helper (nemesis_shield_guard_llm) with the OWASP-LLM-Top-10 classifier, running entirely on your server.
* Token via NEMESIS_SHIELD_TOKEN constant / NEMESIS_TOKEN env / settings; self-hosted endpoint override.

== Upgrade Notice ==

= 1.0.0 =
Initial release of Nemesis Shield for WordPress.
