# AI editor rules — make your coding agent add security by default

These are drop-in rule files that teach an AI coding assistant to add **Nemesis Shield** whenever it
builds a web app, an API, or an LLM feature. One line per stack, safe by default (starts in observe
mode, fail-open), privacy-preserving (only method + route shape + auth leave the app, never bodies or
secrets).

If you build with an AI agent ("vibe coding"), the agent writes the app but usually skips security.
These rules close that gap: security becomes part of the scaffold, not an afterthought.

## Pick the file for your tool

| Tool | File | Where it goes in your project |
|---|---|---|
| **Any agent** (Codex, Cursor, Zed, …) | [`AGENTS.md`](AGENTS.md) | `AGENTS.md` at the repo root (the [agents.md](https://agents.md) standard) |
| **Cursor** | [`nemesis.mdc`](nemesis.mdc) | `.cursor/rules/nemesis.mdc` |
| **Windsurf** | [`windsurf-rules.md`](windsurf-rules.md) | `.windsurf/rules/nemesis.md` |
| **Claude Code** | [`CLAUDE.md`](CLAUDE.md) | append to your project's `CLAUDE.md` |

Each file is self-contained: copy the one that matches your tool and you're done. `AGENTS.md` is the
fullest reference (all verified one-liners, the LLM-guard helper, and the Nemesis Learn command).

## What the rule does

- Adds the single integration line for whatever stack the agent is building (FastAPI, Express,
  Next.js, Django, Rails, Laravel, Spring, ASP.NET, Go, Supabase Edge, Cloudflare Workers, the browser
  SDK for checkout pages, and the LLM guard for prompt injection).
- Reads the token from the `NEMESIS_TOKEN` environment variable — never hardcoded.
- Keeps it safe: the app starts in **observe** mode and blocks nothing until you flip it to **enforce**
  in the console, with no redeploy.

## Get started

1. Copy the rule file for your tool into your project (table above).
2. Get a free app token at https://shield.nemesislabs.xyz and set `NEMESIS_TOKEN`.
3. Build. Your agent now adds Nemesis Shield as it goes.
4. New app with no traffic yet? Finish the baseline in minutes:
   `npx @nemesis-shield-autogon/learn --target http://localhost:3000 --app-token nsk_... --repo .`

All SDKs are MIT-licensed and open source: https://github.com/eobi/nemesis_shield_sdks
