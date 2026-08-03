// Coverage report — what the run touched, so you know the baseline is complete enough to enforce.

export function buildReport({ target, discovered, results, startedAt, finishedAt }) {
  const byMethod = {}, byClass = { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, err: 0 };
  const errors = [], uploads = [];
  for (const r of results) {
    byMethod[r.method] = (byMethod[r.method] || 0) + 1;
    const c = !r.status ? "err" : r.status < 300 ? "2xx" : r.status < 400 ? "3xx" : r.status < 500 ? "4xx" : "5xx";
    byClass[c]++;
    if (c === "err" || c === "5xx") errors.push({ method: r.method, path: r.path, status: r.status, error: r.error });
    if (r.files && r.files.length) uploads.push({ method: r.method, path: r.path });
  }
  const discoveredKeys = new Set(discovered.map((e) => `${e.method} ${e.path}`));
  const exercisedKeys = new Set(results.map((r) => `${r.method} ${r.path}`));
  const notExercised = [...discoveredKeys].filter((k) => !exercisedKeys.has(k));
  const bySource = {};
  for (const e of discovered) { const s = e.source.split(":")[0]; bySource[s] = (bySource[s] || 0) + 1; }

  const reached = byClass["2xx"] + byClass["3xx"] + byClass["4xx"]; // server responded (traffic learned)
  const coverage = results.length ? Math.round((reached / results.length) * 100) : 0;

  return {
    target,
    startedAt, finishedAt,
    durationMs: Date.parse(finishedAt) - Date.parse(startedAt),
    discovered: { total: discovered.length, bySource },
    exercised: { total: results.length, byMethod, byStatus: byClass, uploads: uploads.length },
    coveragePct: coverage,
    reachedServer: reached,
    notExercised,
    errors: errors.slice(0, 50),
    uploads: uploads.slice(0, 50),
    requests: results,
  };
}

export function printSummary(rep, out) {
  const line = (s = "") => out(s);
  line("");
  line("──────────────────────────────────────────────────────────");
  line("  Nemesis Learn — baseline run complete");
  line("──────────────────────────────────────────────────────────");
  line(`  Target        ${rep.target}`);
  line(`  Discovered    ${rep.discovered.total} routes  (${Object.entries(rep.discovered.bySource).map(([k, v]) => `${k}:${v}`).join("  ")})`);
  line(`  Exercised     ${rep.exercised.total} requests in ${(rep.durationMs / 1000).toFixed(1)}s`);
  const s = rep.exercised.byStatus;
  line(`  Responses     ${s["2xx"]} × 2xx · ${s["3xx"]} × 3xx · ${s["4xx"]} × 4xx · ${s["5xx"]} × 5xx · ${s.err} failed`);
  line(`  Methods       ${Object.entries(rep.exercised.byMethod).map(([k, v]) => `${k}:${v}`).join("  ")}`);
  line(`  Uploads       ${rep.exercised.uploads} file upload${rep.exercised.uploads === 1 ? "" : "s"} exercised`);
  line(`  Server reached ${rep.reachedServer}/${rep.exercised.total} (${rep.coveragePct}%) — this is the traffic Shield learned`);
  if (rep.errors.length) {
    line("");
    line(`  ⚠ ${rep.errors.length} route(s) errored (5xx / unreachable) — worth a look before enforce:`);
    for (const e of rep.errors.slice(0, 10)) line(`     ${String(e.status || e.error).padEnd(7)} ${e.method} ${e.path}`);
  }
  line("");
  line("  Next: open Nemesis Shield → your app → Review Queue, approve the learned");
  line("  behaviors, then flip the app to ENFORCE. The routes above are now baselined.");
  line("──────────────────────────────────────────────────────────");
  line("");
}
