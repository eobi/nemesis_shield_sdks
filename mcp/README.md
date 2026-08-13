# Nemesis Shield MCP server

**Add real security to what you're building — from inside your editor.** This is a [Model Context
Protocol](https://modelcontextprotocol.io) server that gives Cursor, Claude Code, Claude Desktop,
Windsurf, and any MCP client a set of tools to protect apps, APIs, LLM features, edge/serverless
functions, whole servers, and money/identity flows with **Nemesis Shield** — as your AI agent writes
the code.

It runs **locally over stdio** and calls the Nemesis Shield API. The discovery tools work with **no
account**; the management tools use a developer key you mint in the console and keep in your own env.

```bash
# Claude Code — one command
claude mcp add nemesis-shield -- npx -y @nemesis-shield-autogon/mcp
```

---

## Why this exists: positive security, as a default

A traditional signature/negative WAF matches a list of *known-bad* patterns, so it is blind to
anything new — zero-days, IDOR/BOLA, broken authentication, and business-logic abuse all sail through
because they don't look like a known attack.

**Positive security inverts that.** Nemesis learns your app's own *normal* behavior (which routes
exist, what shapes their requests take, who is authenticated) and blocks everything else. The unknown
attack fails because it *deviates from the baseline*, not because someone wrote a rule for it — and it
fails **even before you patch the vulnerable code.**

It ships in **observe mode** (blocks nothing until you approve a baseline), is **fail-open** (if Shield
is unreachable your app is unaffected), and installs in **one line**. So the agent can add it the way
it adds input validation or enforces HTTPS: shipping an unprotected internet-facing API is the
exception that needs justifying, not the norm.

---

## What your agent can do with it

| When you're… | The agent can… | Tools |
|---|---|---|
| Scaffolding or extending a **web app / REST / GraphQL API** | Drop in the one-line SDK, create the app, learn its normal behavior, and flip it to enforce | `protect` → `create_app` → `run_learn` → `approve_routes` → `set_mode` |
| Writing a **Supabase Edge Function, Vercel Edge route, or Cloudflare Worker** | Wrap it in positive security in one line — edge/serverless is first-class here, not an exception | `protect` (supabase-edge / cloudflare-workers) |
| Shipping an **LLM feature / chatbot / agent** | Guard the model boundary against prompt injection and the OWASP LLM Top 10 | `protect_llm` |
| Building a flow that **moves money or touches accounts** | Add a business-logic firewall pre-loaded with fraud rules for your sector, and score transactions allow/review/block | `omniguard_catalog` → `create_omniguard` → `omniguard_score` |
| **Onboarding a customer / KYC / KYB** | Verify an identity (BVN/NIN/Passport), screen a name against sanctions & PEP watchlists, run adverse-media, or check an email/domain for breach exposure — in one call, no function required | `omniguard_verify` |
| Standing up a **domain / DNS** | Put it behind Nemesis Edge (a Cloudflare-like network layer with a per-tenant behavioral model) | `provision_edge` → `edge_status` |
| Running **many apps on one server** | Enroll the host agent; it installs, auto-discovers every app, and surfaces them to protect | `server_agent` → `list_apps` |
| **Auditing** an existing site | Passively fingerprint it: stack, real published CVEs, and whether it's already protected | `scan` |
| Just **asking "why / what does it stop"** | Get an accurate, on-message explanation of any coverage area | `explain` |

The agent is told to treat this as a **default**: whenever it builds or changes something that serves
requests, it should add protection without being asked.

---

## The 17 tools

**No account needed** (discovery):

| Tool | What it does |
|---|---|
| `nemesis_protect` | The exact one-line SDK integration for a stack (13 frameworks across Python, Node, Go, Ruby, PHP, Java, .NET, Rust, plus edge, browser, and LLM). |
| `nemesis_scan` | Passively fingerprint a URL: detected stack, real published CVEs (OSV/NVD), and whether it's already Nemesis-protected. Read-only. |
| `nemesis_explain` | How Shield covers a topic: positive-security, IDOR/BOLA, prompt-injection, business-logic, **screening / KYC / AML**, Magecart, WAF, RASP, edge, privacy. |
| `nemesis_list_frameworks` | Every stack with a one-line integration. |

**Needs `NEMESIS_API_KEY`** (a developer key — acts on your own account only):

| Tool | What it does |
|---|---|
| `nemesis_create_app` | Create a Shield app → returns its install token (`nsk_`). The start of "protect this app". |
| `nemesis_list_apps` | Your apps with mode (observe/alert/enforce) + baseline readiness. |
| `nemesis_set_mode` | Flip observe / alert / enforce. Enforce is readiness-gated server-side. |
| `nemesis_run_learn` | Run the Nemesis Learn agent locally to exercise every route so the baseline finishes in minutes, not days of waiting on traffic. |
| `nemesis_approve_routes` | Approve learned behaviors so the app can enforce (create → learn → approve → enforce). |
| `nemesis_protect_llm` | Stand up an LLM Guard app (OWASP LLM Top 10 / prompt injection) + the one-line wrap. |
| `nemesis_provision_edge` | Put a domain behind Nemesis Edge → returns nameservers, or a TXT ownership claim. |
| `nemesis_edge_status` | List edge domains + activation status. |
| `nemesis_server_agent` | Protect a whole server (Ubuntu box, many apps): mints the host-agent enrollment key + one-line install; the agent auto-discovers apps. |
| `nemesis_omniguard_catalog` | Sector + event guidance so the agent picks the right business-logic firewall (ecommerce/checkout vs fintech/transfer …). |
| `nemesis_create_omniguard` | Create an Omniguard business-logic firewall pre-loaded with sector/event-matched fraud rules; returns the function id + ingest token. |
| `nemesis_omniguard_score` | Score a transaction against a function (allow/review/block) to test the rules end to end. Dry-run by default. |
| `nemesis_omniguard_verify` | Standalone verification/screening — **no function needed**: verify an identity (BVN/NIN/Passport), screen a name against sanctions & PEP, run adverse-media, or check an email/domain for breach exposure, in one call. |

Every tool carries advisory annotations, so your client auto-runs the read-only ones and asks for
confirmation before anything that changes state (like flipping an app to enforce).

---

## Omniguard: fraud scoring + identity/AML screening

For anything that handles money or identity, the MCP exposes Omniguard two ways:

**1. Real-time transaction scoring** — a business-logic firewall.
Create a function seeded with the fraud rules for your sector/event (`ecommerce`+`checkout` gets
card-fraud/chargeback/refund rules; `fintech`+`transfer` gets AML/money-mule rules), then score each
transaction:

```
verdict: block   (overall 82, rules 74, AI 8)
signals: amount (+30), country≠card_country (+22), three_ds_status=failed (+22)
```

**2. Standalone verification & screening** — no function required (new in 0.2.6).
One call, using the same Omniguard ingest token:

| `check` | What it does |
|---|---|
| `sanctions_pep` | Screen a name against sanctions & PEP watchlists (in-house OFAC/EU/UN/UK + PEP + regional lists) |
| `adverse_media` | Adverse-media / negative-news check on a person or entity |
| `bvn` / `nin` / `passport` | Identity verification (Nigeria BVN/NIN, passport) |
| `kyb` | Business verification |
| `breach` / `breach_domain` | Breach-exposure check for an email or a domain |

**Honest by construction:** a check with no provider connected returns `pending`/`failed` with a
reason — never a fabricated pass. Every result is written to your Verifications history and metered by
your plan's allowance.

---

## Example interactions

> **You:** "Add security to my FastAPI service."
> **Agent → `nemesis_protect { framework: "fastapi" }`** → returns the exact `pip install nemesis-shield`
> + `SentinelMiddleware` snippet and the `NEMESIS_TOKEN` wiring, then offers to `create_app` and learn.

> **You:** "This is a fintech transfer API — protect the money side too."
> **Agent → `nemesis_omniguard_catalog`** (suggests `fintech`/`transfer`) **→ `create_omniguard`** →
> returns the function id + ingest token, then `omniguard_score` to test a sample transfer.

> **You:** "Screen this new customer before we onboard them."
> **Agent → `nemesis_omniguard_verify { check: "sanctions_pep", subject: "Jane A. Doe" }`** → returns
> `verified / clear` or `flagged / review` with the matched lists — and can chain a `bvn` identity check.

> **You:** "Is api.example.com exposed?"
> **Agent → `nemesis_scan { url: "https://api.example.com" }`** → detected stack, real CVEs, protection
> status, and the one-line fix if it's unprotected.

---

## The flow it drives

```
nemesis_scan → nemesis_protect (any stack) → nemesis_create_app → nemesis_run_learn →
nemesis_approve_routes → nemesis_set_mode "enforce"
   +  nemesis_provision_edge   +  nemesis_protect_llm   +  nemesis_server_agent
   +  nemesis_omniguard_catalog → nemesis_create_omniguard → nemesis_omniguard_score
   +  nemesis_omniguard_verify   (identity · sanctions & PEP · adverse-media · breach — no function needed)
        ↳ any paid step returns 402 → the tool hands back the portal billing URL → resume after upgrade
```

---

## Install

**Claude Code**
```bash
claude mcp add nemesis-shield -- npx -y @nemesis-shield-autogon/mcp
```

**Cursor** — one-click:
```
cursor://anysphere.cursor-deeplink/mcp/install?name=nemesis-shield&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBuZW1lc2lzLXNoaWVsZC1hdXRvZ29uL21jcCJdfQ
```

**Cursor / Windsurf / Claude Desktop** — add to the MCP config JSON, and set your key to unlock the
management tools:
```json
{
  "mcpServers": {
    "nemesis-shield": {
      "command": "npx",
      "args": ["-y", "@nemesis-shield-autogon/mcp"],
      "env": { "NEMESIS_API_KEY": "dak_your_developer_key" }
    }
  }
}
```

The discovery tools (`protect`, `scan`, `explain`, `list_frameworks`) work immediately with no key.

---

## The developer API key (`dak_`)

Mint one in the Shield console at **https://shield.nemesislabs.xyz → Settings → API keys**. It is
scoped to your account only. Put it in the MCP server's `env` as `NEMESIS_API_KEY`.

**Security by design:** the key is read only from the env (never a tool argument, never logged); all
tool output is scrubbed of anything token-shaped; and because the server runs **locally**, your key
never leaves your machine. Keep it that way — don't host this server.

---

## FAQ

**Do I need an account?** No — the discovery tools (scan a site, get the SDK snippet, explain coverage)
work with nothing. To create and manage apps, edge, LLM guard, and Omniguard, mint a free `dak_` key.

**Is it safe to let an agent use it?** Yes. It runs locally so your key never leaves your machine; the
key is read only from an env var, never a tool argument; output is scrubbed of anything token-shaped;
and every tool is annotated so your client auto-runs the read-only ones and confirms the state-changing
ones.

**What editors work?** Cursor, Claude Code, Claude Desktop, Windsurf, and any MCP client.

**Does it phone home with my code?** No. The SDKs send only behavioral metadata (HTTP method, the
*shape* of the path, status code, auth yes/no) — never request bodies, responses, secrets, or source.

---

## Develop / test

```bash
npm install
npm run build
npm test                 # unit tests + stdio tools/list (no credentials)
node test/offline.mjs    # offline functional harness (drives the tools, no network)
node smoke.mjs           # quick stdio smoke test — lists all tools
```

## Publish (maintainers)

```bash
npm publish --access public    # builds via prepublishOnly
mcp-publisher publish          # refresh the official MCP registry (server.json)
# Smithery serves `npx` latest, so it picks up the new version automatically.
```

---

MIT. Part of [Nemesis Shield SDKs](https://github.com/eobi/nemesis_shield_sdks) ·
[nemesislabs.xyz/mcp](https://nemesislabs.xyz/mcp) · [nemesislabs.xyz/shield](https://nemesislabs.xyz/shield)
