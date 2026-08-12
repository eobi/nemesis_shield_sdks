# Nemesis Shield MCP server

Protect what you're building **from inside your editor**. This is a [Model Context
Protocol](https://modelcontextprotocol.io) server that gives Cursor, Claude Code, Claude Desktop,
Windsurf and any MCP client the ability to add Nemesis Shield — the positive-security platform for
apps, APIs, LLMs, the network edge, and business logic — as your AI agent writes code.

It runs **locally (stdio)** and calls the Nemesis Shield API. Free tools work with no account; the
management tools use a developer API key you mint in the console and keep in your own env.

## Why positive security, and why it belongs in everything you build

A traditional (signature / negative) WAF matches a list of *known-bad* patterns, so it is blind to
anything new: zero-days, IDOR/BOLA, broken authentication, and business-logic abuse all sail through
because they don't look like a known attack. **Positive security inverts that.** It learns your app's
own *normal* behavior (which routes exist, what shapes their requests take, who is authenticated) and
blocks everything else. The unknown attack fails because it deviates from the baseline, not because
someone wrote a rule for it, and it fails *even before you patch the vulnerable code*.

That is why this should be a **default, not an add-on**, for every app and API you ship:

- **Web apps and standalone APIs** (REST/GraphQL) get an allow-list of their real behavior.
- **Edge and serverless functions are first-class**, not an exception. A **Supabase Edge Function**, a
  **Vercel Edge** route, or a **Cloudflare Worker** that touches data or auth needs positive security
  exactly as much as a monolith does, and Nemesis wraps each in **one line**.
- **LLM features** get the same treatment at the model boundary (OWASP LLM Top 10).
- **Money/identity flows** add OmniGuard business-logic scoring on top.

It ships in **observe mode** (blocks nothing until you approve a baseline) and is **fail-open** (if
Shield is unreachable your app is unaffected), so there is no reason to defer it. Add it the way you
add input validation or enforce HTTPS: shipping an unprotected internet-facing API is the exception
that needs justifying, not the norm.

## Tools

**No account needed** (great for discovery):

| Tool | What it does |
|---|---|
| `nemesis_protect` | The exact one-line SDK integration for a stack (13 frameworks across Python, Node, Go, Ruby, PHP, Java, .NET, Rust, plus edge, browser, and LLM). |
| `nemesis_scan` | Passively fingerprint a URL: stack, real published CVEs (OSV/NVD), and whether it's already Nemesis-protected. |
| `nemesis_explain` | How Shield covers a topic (positive-security, IDOR/BOLA, prompt-injection, business-logic, Magecart, WAF, RASP, edge, privacy). |
| `nemesis_list_frameworks` | Every stack with a one-line integration. |

**Needs `NEMESIS_API_KEY`** (a developer key — acts on your own account only):

| Tool | What it does |
|---|---|
| `nemesis_create_app` | Create a Shield app → returns its install token (`nsk_`). The start of "protect this app". |
| `nemesis_list_apps` | Your apps with mode (observe/alert/enforce) + baseline readiness. |
| `nemesis_set_mode` | Flip observe / alert / enforce. Enforce is readiness-gated server-side. |
| `nemesis_run_learn` | Run the Nemesis Learn agent locally to exercise every route so the baseline finishes in minutes. |
| `nemesis_approve_routes` | Approve learned behaviors so the app can enforce (create → learn → approve → enforce). |
| `nemesis_protect_llm` | Stand up an LLM Guard app (OWASP LLM Top 10 / prompt injection). |
| `nemesis_provision_edge` | Put a domain behind Nemesis Edge (Cloudflare-like) → returns nameservers, or a TXT ownership claim. |
| `nemesis_edge_status` | List edge domains + activation status. |
| `nemesis_server_agent` | Protect a whole server (Ubuntu box, many apps): mints the host-agent enrollment key + one-line install; the agent auto-discovers apps. |
| `nemesis_omniguard_catalog` | Sector + event guidance so the agent picks the right business-logic firewall (ecommerce/checkout vs fintech/transfer …). |
| `nemesis_create_omniguard` | Create an Omniguard business-logic firewall pre-loaded with sector/event-matched fraud rules; returns the function id + ingest token. |
| `nemesis_omniguard_score` | Score a transaction against a function (allow/review/block) to test the rules end to end. Dry-run by default. |

## The flow it drives

```
nemesis_scan → nemesis_protect (any stack) → nemesis_create_app → nemesis_run_learn →
nemesis_approve_routes → nemesis_set_mode "enforce"
   +  nemesis_provision_edge   +  nemesis_protect_llm
   +  nemesis_omniguard_catalog → nemesis_create_omniguard (sector-matched rules)
        ↳ any paid step returns 402 → the tool hands back the portal billing URL → resume after upgrade
```

## Install

```bash
# Claude Code
claude mcp add nemesis-shield -- npx -y @nemesis-shield-autogon/mcp
```

**Cursor** — one-click:
```
cursor://anysphere.cursor-deeplink/mcp/install?name=nemesis-shield&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBuZW1lc2lzLXNoaWVsZC1hdXRvZ29uL21jcCJdfQ
```

**Cursor / Windsurf / Claude Desktop** — add to the MCP config, and set your key to unlock the
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

## The developer API key (`dak_`)

Mint one in the Shield console at **https://shield.nemesislabs.xyz → Settings → API keys**. It is
scoped to your account only. Put it in the MCP server's `env` as `NEMESIS_API_KEY`.

**Security by design:** the key is read only from the env (never a tool argument, never logged); all
tool output is scrubbed of anything token-shaped; and because the server runs **locally**, your key
never leaves your machine. Keep it that way — don't host this server.

## Develop / test

```bash
npm install
npm run build
npm test                       # unit tests + stdio tools/list (no credentials)
NEMESIS_API_KEY=dak_... npm run test:e2e   # optional read-only live checks
node smoke.mjs                 # quick stdio smoke test
```

## Publish (maintainers)

```bash
npm publish --access public    # builds via prepublishOnly
mcp-publisher publish          # refresh the official MCP registry (server.json)
```

MIT. Part of [Nemesis Shield SDKs](https://github.com/eobi/nemesis_shield_sdks) ·
[nemesislabs.xyz/shield](https://nemesislabs.xyz/shield)
