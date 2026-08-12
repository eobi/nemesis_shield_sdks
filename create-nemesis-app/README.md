# create-nemesis-app

Scaffold a web app or API that ships with a positive-security WAF already wired in.

```bash
npm create nemesis-app@latest my-app -- --template express
# or
npx create-nemesis-app my-app --template fastapi
# or just run it and pick a template
npx create-nemesis-app
```

Templates: `express`, `nextjs`, `fastapi`, `supabase-edge`.

Every template adds [Nemesis Shield](https://nemesislabs.xyz/shield), a positive-security
(allow-list) WAF that learns your app's own normal behavior and blocks the deviations a
signature WAF misses (zero-days, IDOR/BOLA, broken auth, business-logic abuse). It is
**safe by default**: the app starts in observe mode and blocks nothing until you approve a
learned baseline, and it is fail-open, so if Nemesis is unreachable your app is unaffected.

Each scaffolded project includes an `AGENTS.md` so an AI editor (Cursor, Claude Code,
Windsurf) keeps security in view as it writes more code.

MIT licensed. Part of the [Nemesis Shield SDKs](https://github.com/eobi/nemesis_shield_sdks).
