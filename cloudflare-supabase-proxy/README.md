# Nemesis Shield — Cloudflare proxy for Supabase (direct DB API)

Supabase's auto-generated DB API (`supabase.from('table')`) hits Supabase's own servers, so an
in-process SDK can't sit in front of it. This Cloudflare Worker can: route your DB-API traffic
through it and every request gets the same **positive-security allow-list** as the rest of Nemesis
Shield — *"this app only ever runs these verbs on these tables"* — before it reaches your database.

```
your app  ->  https://<worker>.<you>.workers.dev  ->  https://<project>.supabase.co
```

- **Only `/rest/v1/` (the DB API) is inspected.** `auth`, `storage`, and `realtime` pass straight through.
- **Observe → learn → enforce**, driven from the console with no redeploy (the Worker polls the policy).
- **Fail-open**: if Nemesis is unreachable the request is forwarded untouched — the proxy never takes
  your database offline.
- What it blocks in enforce mode: a verb/table/auth shape your app never normally uses — e.g. an
  attacker with a leaked anon key doing `DELETE` on a table you only ever `SELECT`, or hitting a table
  the app never touches, or unauthenticated access to a sensitive one.

## Deploy

1. **Protect an app** in the console and copy its install token (`nsk_...`).
2. Edit `wrangler.toml` → set `SUPABASE_URL` to your real project URL.
3. Set the token as a secret and deploy:
   ```bash
   npm install
   npx wrangler secret put NEMESIS_TOKEN     # paste the nsk_... token
   npx wrangler deploy
   ```
4. Point your app's Supabase client at the Worker instead of `*.supabase.co`:
   ```js
   createClient("https://nemesis-supabase-proxy.<you>.workers.dev", SUPABASE_ANON_KEY)
   ```
   (Your `apikey` / `Authorization` headers are forwarded unchanged, so RLS keeps working exactly as
   before — this adds an allow-list *in front of* RLS, it doesn't replace it.)

Leave the app in **observe** for a day or two to build the baseline, approve the normal
table/verb shapes in the console, then flip it to **enforce**.

## How it works

It reuses the Web-standard [`edge/`](../edge/) SDK: computes a privacy-preserving shape from the
request (`/rest/v1/<table>` + HTTP verb + whether the caller was authenticated — never row data),
checks it against the compiled policy, and forwards to Supabase. Telemetry and policy refresh run in
`ctx.waitUntil` so they never add latency to the response path.
