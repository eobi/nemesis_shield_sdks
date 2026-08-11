// Omniguard sector + event catalog, so the MCP can give personalized business-logic guidance: it picks
// the right sector and event for what the developer is building, and each combination seeds the fraud
// rules that actually matter for it (ecommerce+checkout ≠ fintech+transfer). Mirrors the server's
// og-starter-rules; the server is the source of truth for the actual rules seeded.

export const SECTORS: Array<{ key: string; label: string }> = [
  { key: "fintech", label: "Fintech / PSP" },
  { key: "banking", label: "Banking / Finance" },
  { key: "lending", label: "Lending / BNPL" },
  { key: "card", label: "Card / Payments" },
  { key: "ecommerce", label: "E-commerce / Retail" },
  { key: "marketplace", label: "Marketplace" },
  { key: "crypto", label: "Crypto / Digital assets" },
  { key: "igaming", label: "iGaming / Betting" },
  { key: "health", label: "Healthcare" },
  { key: "insurance", label: "Insurance" },
  { key: "energy", label: "Energy / Utilities" },
  { key: "education", label: "Education / EdTech" },
  { key: "general", label: "General / other" },
];

// event -> a short description of what it protects (the fraud classes its rules cover).
export const EVENTS: Record<string, string> = {
  transfer: "money transfers — AML typologies, structuring, layering, money mules, APP scams",
  payout: "payouts/disbursements — money-mule, layering, reseller abuse",
  deposit: "deposits — AML structuring, card fraud, card testing",
  withdrawal: "withdrawals — layering, account takeover",
  checkout: "checkout/payments — card fraud, card testing, BIN risk, chargeback & refund abuse, promo/gift-card/loyalty abuse, triangulation",
  order: "order placement — card & payment fraud, chargebacks, reshipping, promo abuse",
  wallet_funding: "wallet funding — card fraud/testing, BIN risk, token fraud, crypto ramp",
  topup: "top-ups — card fraud/testing, BIN risk, reconnection abuse",
  registration: "signups — registration/synthetic-identity abuse, multi-accounting, bot automation",
  login: "logins — account takeover, bot automation, multi-accounting",
  kyc: "KYC — synthetic & medical identity fraud",
  account_update: "account changes — account takeover, identity fraud, SCA",
  loan_application: "loan applications — lending fraud, synthetic identity, first-party fraud, bust-out",
  loan_disbursement: "loan disbursements — lending fraud, money mules, bust-out",
  claim: "insurance claims — claims fraud, duplicate billing, upcoding, medical identity theft",
  subscription: "subscriptions — subscription abuse, card fraud, promo/refund abuse",
  refund: "refunds — refund abuse, first-party & chargeback fraud, promo abuse",
  tuition_payment: "tuition — financial-aid fraud, card fraud, chargebacks",
};

// Best-effort: map a free-text description of what the developer is building to a (sector, event).
export function suggestOmniguard(text: string): { industry?: string; event?: string } {
  const t = text.toLowerCase();
  const sector = SECTORS.find((s) => t.includes(s.key) || t.includes(s.label.toLowerCase().split(" ")[0]!));
  const event = Object.keys(EVENTS).find((e) => t.includes(e) || t.includes(e.replace("_", " ")));
  return { industry: sector?.key, event };
}

export function omniguardCatalog(): string {
  return (
    "Sectors: " + SECTORS.map((s) => s.key).join(", ") + "\n" +
    "Events:\n" + Object.entries(EVENTS).map(([e, d]) => `  ${e} — ${d}`).join("\n")
  );
}
