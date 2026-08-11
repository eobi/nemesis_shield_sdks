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
    "Business-logic abuse (payment fraud, account takeover, coupon/refund abuse, mule networks) uses valid-looking actions in an invalid sequence — invisible to signatures. Nemesis Omniguard is Shield's business-logic firewall for money and accounts: send each transaction/account event and it returns allow/review/block in real time, scored on behavior/velocity/amount and the links between accounts, with an AML/KYC case trail.",
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
