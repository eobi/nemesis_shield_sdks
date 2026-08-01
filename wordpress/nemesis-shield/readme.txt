=== Nemesis Shield ===
Contributors: nemesislabs
Tags: security, firewall, waf, malware, brute-force
Requires at least: 5.0
Tested up to: 6.8
Requires PHP: 7.2
Stable tag: 1.0.0
License: MIT
License URI: https://opensource.org/licenses/MIT

Positive-security runtime protection: learns your site's normal behaviour, then blocks off-baseline requests before WordPress runs. Privacy-preserving, fail-open.

== Description ==

Nemesis Shield brings **positive-security runtime protection** to any WordPress site. Instead of chasing an endless blocklist of known attacks, it **learns what your site normally does** and, in enforce mode, **blocks anything off-baseline** (auth bypass, path traversal, vulnerability scanners, unusual methods) **before WordPress runs**, across the front end, the REST API, and admin-ajax.

The block decision is made **in-process**: no proxy, no sidecar, no traffic leaving your server for a third party to inspect. The plugin vendors the same native PHP SDK every Nemesis Shield integration uses, so its verdict is byte-for-byte identical to the rest of the platform.

**How it works, in three steps: observe, approve, enforce.**

1. **Observe** (default). Every request's privacy-preserving *shape* is recorded to build your baseline: the HTTP method, a normalized path (`/shop/product/123` becomes `/shop/product/{int}`), the kinds of parameters present, and whether the caller is authenticated. **Never** bodies, values, cookies, or secrets.
2. **Approve.** Review the learned behaviours in the [Shield console](https://shield.nemesislabs.xyz) and approve the legitimate ones.
3. **Enforce.** Flip the app to enforce in the console. Requests whose shape is not approved are blocked with `403 blocked_by_nemesis_shield`. No redeploy: the mode is pulled live.

**Privacy-preserving.** Only the abstract shape of a request is computed, and only locally. Request bodies, query values, cookies, headers, and secrets never leave your site.

**Fail-open by design.** If Shield is ever unreachable, requests are forwarded untouched. The plugin can never take your site offline.

**Never locks you out.** The front end and REST API are enforced; **wp-admin, admin-ajax, wp-login.php, and cron are observe-only by default** so a still-learning baseline can never lock you out of your own dashboard. Tick *Protect wp-admin* to enforce there too. The login and auth paths are never blocked.

**Global threat intelligence.** Beyond your own baseline, the shared `knownBad` list blocks shapes seen attacking other sites (for example `POST /xmlrpc.php` floods) out of the box.

**LLM Guard (optional).** If your site calls an LLM (an AI chatbot or content assistant), guard the prompt before you send it with the bundled OWASP-LLM-Top-10 classifier:

`$v = nemesis_shield_guard_llm( $user_prompt, true );`
`if ( $v['blocked'] ) { wp_die( 'Request blocked.' ); }`

Nemesis Shield is part of the [Nemesis Labs](https://nemesislabs.xyz) security platform. A free tier is available.

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
* Positive-security gate on the front end and REST API (rest_pre_dispatch), with observe / approve / enforce driven live from the console.
* wp-admin, admin-ajax, wp-login.php, and cron observe-only by default; optional Protect wp-admin toggle.
* Privacy-preserving request shaping computed in-process; bodies, values, and secrets never leave the site.
* Global threat-intelligence (knownBad) blocking.
* Fail-open when Shield is unreachable.
* Optional LLM Guard helper (nemesis_shield_guard_llm) with the OWASP-LLM-Top-10 classifier.
* Token via NEMESIS_SHIELD_TOKEN constant / NEMESIS_TOKEN env / settings; self-hosted endpoint override.

== Upgrade Notice ==

= 1.0.0 =
Initial release of Nemesis Shield for WordPress.
