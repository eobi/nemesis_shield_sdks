# Nemesis Shield — Browser (client-side)

Runtime protection for the **front-end** — the half a backend SDK can't see. It learns your page's
normal client-side behavior and, in enforce mode, **blocks**:

- **Magecart / skimmers** — scripts injected from an origin the page never normally loads.
- **Data exfiltration** — `fetch` / `XHR` / `sendBeacon` calls to rogue endpoints (card details,
  session tokens, form data leaving to an attacker origin).
- **Form-jacking** — a form silently re-pointed to submit to an attacker.

It's a learned, per-app allow-list — *"this page only ever loads these scripts and only ever talks to
these origins"* — curated in the console like a CSP you approve instead of hand-writing. First-party
traffic is always allowed, and the SDK is **fail-open**: it never breaks the page.

> Why this matters: in the 2026 Sterling Bank → Remita breach, attackers found **encryption keys in
> plaintext inside JavaScript files** and pivoted through the front-end. Client-side exposure and
> injected/exfil scripts are invisible to a WAF and to a backend SDK — this is the layer that sees them.

**One SDK for every framework.** React, Angular (incl. legacy Angular.js), Vue, jQuery, and plain
JavaScript all share the same browser primitives (`fetch`, `XMLHttpRequest`, `sendBeacon`, DOM
mutations, form submit) — so a single SDK covers all of them.

## Install

**Drop-in `<script>`** — any site, including server-rendered, jQuery, or legacy apps. No build step:
```html
<script src="nemesis-shield.js" data-token="nsk_your_app_token"></script>
```

**Bundled app** (React / Vue / Angular / Svelte) — once at bootstrap:
```js
import NemesisShield from "@nemesis-shield/browser";
NemesisShield.init({ token: import.meta.env.VITE_NEMESIS_TOKEN });
```

- **React** — call `NemesisShield.init({ token })` at the top of `main.tsx` / `index.js`, before render.
- **Angular** — in `main.ts` before `bootstrapApplication`, or an `APP_INITIALIZER`.
- **Vue** — in `main.js` before `app.mount()`.
- **jQuery / Angular.js / raw JS** — the `<script>` tag above (put it first in `<head>`).

## How enforcement works

1. **Observe** (default) — records the *origins* of scripts your page loads, endpoints it calls, and
   form targets (origins + event shapes only — never payloads, cookies, or DOM content).
2. **Approve** — review the learned client-side behaviors in the console and approve the legitimate
   ones (your CDN, analytics, payment API…). Auto-approved during the learning window.
3. **Enforce** — flip the app to enforce. Scripts/calls/forms to any un-approved origin are blocked
   in the browser and reported as findings. No redeploy — the SDK re-polls the policy.

## Verified

End-to-end against production: after learning `cdn.jsdelivr.net`, `api.stripe.com`, and
`googletagmanager.com`, enforcing the app, and re-pulling the live policy, the SDK **allowed** the
approved origins and first-party calls, and **blocked** an exfil `fetch` to `evil-exfil.ru` and an
injected `<script>` from `evil-cdn.ru`. Unit tests: `node test.cjs`.
