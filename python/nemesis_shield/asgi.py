"""ASGI middleware for FastAPI / Starlette. The developer's one line:

    from nemesis_shield.asgi import SentinelMiddleware
    app.add_middleware(SentinelMiddleware, token=os.environ["NEMESIS_TOKEN"])

Observes every request/response, builds a privacy-preserving sketch, ships it async, and (only in
enforce mode, only for known-bad shapes) blocks. Fail-open throughout.
"""

import time
from .client import SentinelClient
from .sketch import build_sketch


class SentinelMiddleware:
    def __init__(self, app, token: str, endpoint: str | None = None, mode: str = "observe", **kw):
        self.app = app
        self.client = SentinelClient(token, endpoint=endpoint or SentinelClient.__init__.__defaults__[0], mode=mode, **kw)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start = time.time()
        method = scope.get("method", "GET")
        raw_path = scope.get("path", "/")
        qs = scope.get("query_string", b"").decode()
        # query-param STRUCTURE (names + kinds, never values) so param tampering on a known route
        # is off-baseline, not just unknown paths.
        from urllib.parse import parse_qsl
        query = dict(parse_qsl(qs, keep_blank_values=True))
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        header_names = list(headers.keys())
        authenticated = any(h in headers for h in ("authorization", "cookie", "x-api-key"))

        def sketch_for(status: int) -> dict:
            return build_sketch(
                method=method,
                path=raw_path,
                query=query,
                header_names=header_names,
                authenticated=authenticated,
                content_type=headers.get("content-type"),
                status=status,
                duration_ms=(time.time() - start) * 1000,
            )

        # enforce: block known-bad request shapes before dispatch (status 0 = pre-response)
        if self.client.mode == "enforce" and not self.client.never_block(raw_path):
            verdict = self.client.decide(sketch_for(0))
            if self.client.should_block(verdict):
                self.client.record(sketch_for(403))
                await _send_block(send, verdict.get("reason"))
                return

        status_holder = {"status": 200}

        async def send_wrapper(event):
            if event["type"] == "http.response.start":
                status_holder["status"] = event["status"]
            await send(event)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            try:
                self.client.record(sketch_for(status_holder["status"]))
            except Exception:
                pass  # fail-open: never let telemetry break the response


async def _send_block(send, reason):
    import json

    body = json.dumps({"error": "blocked_by_nemesis_shield", "reason": reason}).encode()
    await send({"type": "http.response.start", "status": 403,
                "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": body})
