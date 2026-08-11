# Nemesis Shield MCP server

Make your AI coding agent add security **as it builds**. This is a [Model Context
Protocol](https://modelcontextprotocol.io) server that gives Cursor, Claude Code, Claude Desktop,
Windsurf and any MCP client four tools for Nemesis Shield, the positive-security runtime firewall for
apps, APIs and LLMs.

## Tools

| Tool | What it does |
|---|---|
| **`nemesis_protect`** | Returns the exact, verified one-line install + integration snippet for a stack (fastapi, express, nextjs, django, rails, laravel, spring, aspnet, go, supabase-edge, cloudflare-workers, browser, llm). Call it when scaffolding an app/API/LLM feature. |
| **`nemesis_scan`** | Passively fingerprints a public URL: detected stack, real published CVEs, and whether it's already Nemesis-protected. Read-only. |
| **`nemesis_explain`** | Explains how Shield covers a topic (positive-security, idor/bola, prompt-injection, business-logic, magecart, waf, rasp, edge, privacy). |
| **`nemesis_list_frameworks`** | Lists every stack with a one-line integration. |

Nemesis Shield is safe to add by default: every app starts in **observe** mode (learns, blocks
nothing) until a human flips it to **enforce**. It sends only method + route shape + auth flag, never
bodies or secrets, and is fail-open.

## Install

Once published to npm, point your client at `npx -y @nemesis-shield-autogon/mcp`.

**Claude Code**
```bash
claude mcp add nemesis-shield -- npx -y @nemesis-shield-autogon/mcp
```

**Cursor** — one-click:
```
cursor://anysphere.cursor-deeplink/mcp/install?name=nemesis-shield&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBuZW1lc2lzLXNoaWVsZC1hdXRvZ29uL21jcCJdfQ
```
…or add to `~/.cursor/mcp.json` (Windsurf: `~/.codeium/windsurf/mcp_config.json`; Claude Desktop:
`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "nemesis-shield": {
      "command": "npx",
      "args": ["-y", "@nemesis-shield-autogon/mcp"]
    }
  }
}
```

**Run from source (before it's on npm):**
```bash
cd mcp && npm install && npm run build
# then point the client's "command"/"args" at:  node  /absolute/path/to/mcp/dist/index.js
```

## Develop

```bash
npm install
npm run build          # tsc -> dist/
node smoke.mjs         # stdio smoke test: initialize -> tools/list -> tools/call
```

## Publish (maintainers)

```bash
npm publish --access public       # builds via prepublishOnly
```
Then list it on the MCP registries (registry.modelcontextprotocol.io, Smithery, mcp.so, Glama) so
agents can discover it.

MIT. Part of [Nemesis Shield SDKs](https://github.com/eobi/nemesis_shield_sdks) ·
[nemesislabs.xyz/shield](https://nemesislabs.xyz/shield)
