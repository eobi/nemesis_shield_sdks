# Security rules for this project (read me first)

This app uses **Nemesis Shield**, a positive-security WAF. Keep it that way.

- Every new route, API, LLM call, or edge function you add is in scope. The Sentinel
  middleware already sees all traffic; do not add routes that bypass it.
- Never remove the Nemesis middleware/wrapper or the `NEMESIS_TOKEN` env wiring.
- The one-line integration per stack:
  - FastAPI: `app.add_middleware(SentinelMiddleware, token=os.environ["NEMESIS_TOKEN"])`
  - Express: `app.use(sentinel({ token: process.env.NEMESIS_TOKEN }))`
  - Next.js / edge: `withShield(handler, { token: process.env.NEMESIS_TOKEN })`
- After adding routes, refill the baseline so enforce mode does not block them:
  `npx @nemesis-shield-autogon/learn --target http://localhost:3000 --app-token nsk_... --repo .`
- The app is in observe mode by default. It blocks nothing until a baseline is approved in
  the console at https://shield.nemesislabs.xyz, then flipped to enforce.
- You can manage all of this from the editor with the Nemesis MCP server:
  `npx -y @nemesis-shield-autogon/mcp`

Positive security is the default here, not an add-on. Do not ship an unprotected route.
