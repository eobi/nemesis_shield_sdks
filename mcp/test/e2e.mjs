// Live, read-only end-to-end check against the Nemesis Shield API. Safe to run against a real account:
// it only performs GETs (list apps / edge zones / omniguard functions) plus a bad-key check.
//
//   Run:  NEMESIS_API_KEY=dak_... node test/e2e.mjs
//
// Skips (exit 0) if NEMESIS_API_KEY isn't set, so `npm test` stays green without credentials.
const BASE = process.env.NEMESIS_API_BASE || "https://shield.nemesislabs.xyz";
const KEY = process.env.NEMESIS_API_KEY;

if (!KEY) {
  console.log("SKIP e2e: set NEMESIS_API_KEY=dak_... (from the Shield console) to run the live check.");
  process.exit(0);
}

let failed = 0;
const check = (name, cond, extra = "") => {
  console.log(`${cond ? "ok" : "FAIL"} - ${name}${extra ? "  (" + extra + ")" : ""}`);
  if (!cond) failed++;
};
const get = async (path, key = KEY) => {
  const r = await fetch(BASE + path, { headers: { authorization: `Bearer ${key}` } });
  let d;
  try { d = await r.json(); } catch { d = {}; }
  return { status: r.status, d };
};

const apps = await get("/api/v1/apps");
check("GET /api/v1/apps returns 200 + list", apps.status === 200 && Array.isArray(apps.d.apps), `status ${apps.status}, ${apps.d.count} apps`);

const edge = await get("/api/v1/edge/zones");
check("GET /api/v1/edge/zones returns 200 + list", edge.status === 200 && Array.isArray(edge.d.zones), `status ${edge.status}, ${edge.d.count} zones`);

const og = await get("/api/v1/omniguard/functions");
check("GET /api/v1/omniguard/functions returns 200 + list", og.status === 200 && Array.isArray(og.d.functions), `status ${og.status}, ${og.d.count} functions`);

const bad = await get("/api/v1/apps", "dak_this_is_not_a_real_key");
check("bad key is rejected with 401", bad.status === 401, `status ${bad.status}`);

// Live FREE sanctions/PEP screening (the nemesis_omniguard_screen path) — needs an Omniguard INGEST token
// (not the dak_ API key). Guarded so npm test stays green without it. Proves screening is free + metered.
const OG = process.env.OMNIGUARD_INGEST_TOKEN;
if (!OG) {
  console.log("skip - set OMNIGUARD_INGEST_TOKEN=... to exercise the live free screening check.");
} else {
  const post = async (body, key = OG) => {
    const r = await fetch(BASE + "/api/v1/omniguard/verify", {
      method: "POST",
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    let d; try { d = await r.json(); } catch { d = {}; }
    return { status: r.status, d };
  };
  const hit = await post({ check: "sanctions_pep", subject: "Vladimir Putin" });
  check("free screening: sanctioned name returns 200 + a hit", hit.status === 200 && (hit.d.risk === "hit" || hit.d.data?.sanctionsHit === true), `status ${hit.status}, risk ${hit.d.risk}`);
  check("free screening: provider is the Nemesis Watchlist (our own data)", /nemesis|watchlist/i.test(String(hit.d.provider ?? "")), `provider ${hit.d.provider}`);
  check("free screening: returns matched lists", Array.isArray(hit.d.data?.lists) && hit.d.data.lists.length > 0, `${hit.d.data?.lists?.length ?? 0} lists`);
  const clean = await post({ check: "sanctions_pep", subject: "Zzqxwv Nomatch Nobody" });
  check("free screening: a clean name does not hit", clean.status === 200 && clean.d.risk !== "hit", `risk ${clean.d.risk}`);
  const badTok = await post({ check: "sanctions_pep", subject: "x" }, "not_a_real_ingest_token");
  check("screening rejects a bad ingest token with 401", badTok.status === 401, `status ${badTok.status}`);
}

console.log(failed ? `\n${failed} check(s) failed` : "\nAll live checks passed");
process.exit(failed ? 1 : 0);
