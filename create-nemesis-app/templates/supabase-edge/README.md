# __APP_NAME__ (Supabase Edge Function)

A Supabase Edge Function wrapped with a positive-security WAF (Nemesis Shield).

```bash
# put index.ts under supabase/functions/secure-fn/
supabase secrets set NEMESIS_TOKEN=nsk_your_app_token
supabase functions deploy secure-fn
```

The `withShield` wrapper runs in observe mode until you approve a baseline, and is fail-open.
See `AGENTS.md` for the rules your AI editor should follow.
