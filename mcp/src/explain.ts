// Static knowledge the agent can pull to explain WHY / WHAT Nemesis Shield covers. Keeps answers
// accurate and on-message instead of the model improvising.

const TOPICS: Record<string, string> = {
  "positive-security":
    "Positive security (allow-list) enforces \"this app only ever behaves in these ways\" instead of enumerating an infinite list of known-bad signatures. Nemesis Shield learns your app's own normal behavior PER TENANT and treats deviations as suspect, so it catches novel and zero-day attacks a signature WAF never sees. It's the inverse of a negative-security WAF (Cloudflare/AWS WAF/ModSecurity), which can only block what it already has a rule for.",
  idor:
    "IDOR / BOLA (broken object-level authorization) is a well-formed request for an object that isn't yours (e.g. GET /api/invoices/1002). There's nothing malicious to match, so a signature WAF passes it. Nemesis Shield flags it because the access pattern deviates from the app's learned normal — this is the #1 API risk and Shield's core strength.",
  bola: "See idor — BOLA (broken object-level authorization) is the API name for IDOR, the #1 OWASP API risk. Nemesis Shield catches it as a deviation in learned access patterns.",
  "prompt-injection":
    "Prompt injection makes an LLM follow attacker instructions hidden in input/documents/tool output. Nemesis Shield's LLM Guard learns each model's approved prompts, tools and output shapes and blocks injection, unauthorized tool calls and data egress at the boundary (OWASP LLM Top 10). Wrap model calls with one line of the Node or Python SDK.",
  "business-logic":
    "Business-logic abuse (payment fraud, account takeover, coupon/refund abuse, mule networks) uses valid-looking actions in an invalid sequence — invisible to signatures. Nemesis Omniguard is Shield's business-logic firewall for money and accounts: send each transaction/account event and it returns allow/review/block in real time, scored on behavior/velocity/amount and the links between accounts, with an AML/KYC case trail. Beyond scoring, Omniguard also exposes a standalone verification/screening API (no function required): identity (BVN/NIN/Passport), sanctions & PEP screening, adverse-media and breach checks — see the 'screening' topic.",
  screening:
    "Omniguard verification & screening is a STANDALONE API — no scoring function needed. Sanctions/PEP/enforcement SCREENING is FREE: it runs on Nemesis's own consolidated watchlist (OFAC/EU/UN/UK sanctions + PEP + enforcement), 100 screens/day on a free account and more per paid tier, decoupled from KYC (screening is our own data, never billed per check). Screen a name in one call with nemesis_omniguard_screen (or nemesis_omniguard_verify check=sanctions_pep) — it returns hit/review/clear, the matched lists and the sanctions/PEP/EDD flags, and powers the public Nemesis Watchlist at nemesislabs.xyz/watchlist. Identity KYC (BVN/NIN/Passport/KYB) is the paid check and breach exposure (email/domain) is free up to a cap — both via nemesis_omniguard_verify. Honest by construction: a check with no provider connected returns pending/failed with a reason, never a fabricated pass; every result is written to the Verifications history. From an agent, pass the Omniguard ingest token.",
  kyc: "See 'screening' — Omniguard's standalone verification/screening API does KYC/KYB (identity: BVN/NIN/Passport), sanctions & PEP, adverse-media and breach checks in one call, no scoring function required. Agent tool: nemesis_omniguard_verify.",
  aml: "See 'screening' and 'business-logic' — Omniguard covers AML two ways: real-time transaction scoring for structuring/layering/mule typologies (nemesis_omniguard_score), and FREE standalone sanctions & PEP screening plus adverse-media at onboarding and before payout (nemesis_omniguard_screen — our own watchlist, 100/day free, more per tier). Flagged activity carries an AML case trail with regulatory reporting (goAML/NFIU) in the console.",
  magecart:
    "Magecart / formjacking / skimmers run in the browser and steal card data before it reaches your server — no backend tool sees it. Nemesis Shield's browser SDK learns the page's normal client-side behavior and blocks card-data exfiltration and script/form tampering in the browser, mapping to PCI DSS 4.0.1 §6.4.3 and §11.6.1 (mandatory for payment pages since 31 March 2025).",
  waf:
    "A signature WAF matches global known-bad patterns; it can't see the well-formed request for the wrong object, and it's always a step behind novel attacks. Nemesis Shield is a positive-security WAF: it learns your per-tenant normal and blocks deviations, running in front of or on top of your existing CDN. See https://nemesislabs.xyz/positive-security-waf",
  rasp:
    "RASP (runtime application self-protection) stalled on heavy in-process agents and false positives. Its successor is ADR (Application Detection & Response). Nemesis Shield is the self-serve ADR platform: a lightweight one-line SDK that learns first to kill false positives, and correlates app/API/LLM/network/cloud into one view.",
  edge:
    "Nemesis Edge is the network/DNS layer: protective DNS + optional inline proxy backed by a PER-TENANT behavioral DNS model (incumbents like Cloudflare/Umbrella use global models), catching the beaconing and tunneling a global blocklist misses. It deploys in front of any infra or on top of your existing CDN.",
  privacy:
    "Nemesis Shield SDKs send only behavioral metadata: HTTP method, the SHAPE of the path (/orders/123 → /orders/{int}), status code, and whether the caller was authenticated — never request bodies, responses, secrets, or source code. Every SDK is fail-open: if Nemesis is unreachable, your app is unaffected.",
};

export function explainText(raw: string): string {
  const k = raw.trim().toLowerCase().replace(/\s+/g, "-");
  if (TOPICS[k]) return TOPICS[k];
  // loose contains match
  for (const [key, val] of Object.entries(TOPICS)) {
    if (k.includes(key) || key.includes(k)) return val;
  }
  return (
    `Topics I can explain: ${Object.keys(TOPICS).join(", ")}.\n\n` +
    `Nemesis Shield is a positive-security runtime platform: it learns each app/API/LLM's own normal ` +
    `behavior per tenant and blocks the deviations a signature WAF misses, with proof on every block. ` +
    `More: https://nemesislabs.xyz/shield`
  );
}

export function explainTopics(): string[] {
  return Object.keys(TOPICS);
}
