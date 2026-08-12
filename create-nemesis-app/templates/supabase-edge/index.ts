// supabase/functions/secure-fn/index.ts
// Deploy: supabase functions deploy secure-fn
// Secret:  supabase secrets set NEMESIS_TOKEN=nsk_your_app_token
import { withShield } from "jsr:@nemesis-shield/edge";

const handler = async (req: Request): Promise<Response> => {
  // Your edge logic. This function often holds the service-role key, so it is exactly
  // the surface that needs a WAF. Positive security, observe mode until you enforce.
  return new Response(JSON.stringify({ ok: true }), {
    headers: { "content-type": "application/json" },
  });
};

Deno.serve(withShield(handler, { token: Deno.env.get("NEMESIS_TOKEN") }));
