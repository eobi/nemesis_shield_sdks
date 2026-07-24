// Sentinel client for Node — local policy cache (fast inline decisions), async batched fail-open
// shipper, and a background policy poller so the console can flip enforce/observe with no redeploy.
import { buildSketch } from "./shape.js";

const DEFAULT_ENDPOINT = "https://shield.nemesislabs.xyz/api/v1/sketches";

export class SentinelClient {
  constructor({ token, endpoint = DEFAULT_ENDPOINT, mode = "observe", batchSize = 50, flushInterval = 5000, transport = null } = {}) {
    if (!token) throw new Error("Nemesis Sentinel: token is required");
    this.token = token;
    this.endpoint = endpoint;
    this.mode = mode;
    this.batchSize = batchSize;
    this.flushInterval = flushInterval;
    this._transport = transport; // (batch, token) => Promise<policyResponse|null> (tests)
    this._policy = { shapes: {}, knownBad: [] };
    this._haveBaseline = false;
    this._buffer = [];
    if (!transport && flushInterval > 0) {
      this.refresh(); // prime on startup
      this._timer = setInterval(() => { this.flush().catch(() => {}); this.refresh().catch(() => {}); }, flushInterval);
      if (this._timer.unref) this._timer.unref();
    }
  }

  // ── positive-security decision ──────────────────────────────────────────
  decide(sketch) {
    const per = this._policy.shapes[sketch.shape];
    if (per === "allow") return { action: "allow" };
    if (per === "block") return { action: "block", reason: "policy: blocked shape" };
    if ((this._policy.knownBad || []).includes(sketch.shape)) return { action: "block", reason: "global threat intelligence" };
    if (this._haveBaseline) return { action: "block", reason: "off-baseline: unapproved behavior" };
    return { action: "allow" }; // no baseline yet -> fail open
  }
  shouldBlock(verdict) { return this.mode === "enforce" && verdict.action === "block"; }

  _mergePolicy(p) {
    if (p.shapes != null) { this._policy.shapes = p.shapes; if (Object.keys(p.shapes).length) this._haveBaseline = true; }
    if (p.knownBad != null) this._policy.knownBad = p.knownBad;
  }

  // ── telemetry (fail-open) ───────────────────────────────────────────────
  record(sketch) {
    try {
      this._buffer.push(sketch);
      if (this._buffer.length >= this.batchSize) this.flush().catch(() => {});
    } catch { /* never break the host app */ }
  }

  async flush() {
    if (!this._buffer.length) return;
    const batch = this._buffer; this._buffer = [];
    const res = await this._send(batch);
    if (res) { if (res.policy) this._mergePolicy(res.policy); if (res.mode) this.mode = res.mode; }
  }

  async refresh() {
    const res = await this._send([]);
    if (res) { if (res.policy) this._mergePolicy(res.policy); if (res.mode) this.mode = res.mode; }
  }

  async _send(batch) {
    try {
      if (this._transport) return await this._transport(batch, this.token);
      const r = await fetch(this.endpoint, {
        method: "POST",
        headers: { Authorization: `Bearer ${this.token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ sketches: batch }),
      });
      return r.ok ? await r.json() : null;
    } catch { return null; }
  }
}

export { buildSketch, DEFAULT_ENDPOINT };
