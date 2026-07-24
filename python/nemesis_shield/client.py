"""Sentinel client for Python — local policy cache (fast decisions), async batched fail-open
shipper. Mirrors the Node client's contract."""

import json
import threading
import urllib.request
import urllib.error

DEFAULT_ENDPOINT = "https://ingest.nemesisshield.com/v1/sketches"


class SentinelClient:
    def __init__(
        self,
        token: str,
        endpoint: str = DEFAULT_ENDPOINT,
        mode: str = "observe",
        sample_rate: float = 1.0,
        batch_size: int = 50,
        flush_interval: float = 5.0,
        transport=None,
        on_error=None,
    ):
        if not token:
            raise ValueError("Nemesis Sentinel: token is required")
        self.token = token
        self.endpoint = endpoint
        self.mode = mode
        self.sample_rate = sample_rate
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._transport = transport  # callable(batch, token) -> dict|None (tests)
        self._on_error = on_error
        self._policy = {"shapes": {}, "knownBad": []}
        self._buffer: list[dict] = []
        self._lock = threading.Lock()
        self._rng = __import__("random").Random()  # local, not for security

    # ── policy / decisions ────────────────────────────────────────────────
    def set_policy(self, policy: dict):
        self._policy = {
            "shapes": policy.get("shapes") or {},
            "knownBad": policy.get("knownBad") or [],
        }

    def decide(self, sketch: dict) -> dict:
        shape = sketch.get("shape")
        per_app = self._policy["shapes"].get(shape)
        if per_app == "block":
            return {"action": "block", "reason": "policy: blocked shape"}
        if shape in (self._policy.get("knownBad") or []):
            return {"action": "block", "reason": "global threat intelligence"}
        return {"action": "allow"}

    def should_block(self, verdict: dict) -> bool:
        return self.mode == "enforce" and verdict.get("action") == "block"

    # ── telemetry (fail-open) ─────────────────────────────────────────────
    def record(self, sketch: dict):
        try:
            if self._rng.random() > self.sample_rate:
                return
            with self._lock:
                self._buffer.append(sketch)
                full = len(self._buffer) >= self.batch_size
            if full:
                self.flush()
        except Exception as e:  # never let telemetry break the host app
            if self._on_error:
                self._on_error(e)

    def flush(self):
        with self._lock:
            if not self._buffer:
                return
            batch = self._buffer
            self._buffer = []
        try:
            res = (self._transport or self._http)(batch, self.token)
            if res and res.get("policy"):
                self._merge_policy(res["policy"])
        except Exception as e:
            if self._on_error:
                self._on_error(e)  # drop batch; downtime is worse than telemetry loss

    def _merge_policy(self, p: dict):
        self._policy["shapes"].update(p.get("shapes") or {})
        if p.get("knownBad") is not None:
            self._policy["knownBad"] = p["knownBad"]

    def _http(self, batch, token):
        data = json.dumps({"sketches": batch}).encode()
        req = urllib.request.Request(
            self.endpoint,
            data=data,
            headers={"content-type": "application/json", "authorization": f"Bearer {token}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=3) as r:
                return json.loads(r.read().decode())
        except (urllib.error.URLError, TimeoutError, ValueError):
            return None
