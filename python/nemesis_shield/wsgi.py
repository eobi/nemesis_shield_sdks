"""WSGI middleware for Flask / Django-WSGI / any WSGI app. The developer's one line:

    from nemesis_shield.wsgi import SentinelWSGI
    app.wsgi_app = SentinelWSGI(app.wsgi_app, token=os.environ["NEMESIS_TOKEN"])

Observes every request, ships a privacy-preserving sketch, and - in enforce mode - blocks
off-baseline requests (403) before the app ever sees them. Fail-open throughout.
"""

import json
from urllib.parse import parse_qsl

from .client import SentinelClient, DEFAULT_ENDPOINT
from .sketch import build_sketch


class SentinelWSGI:
    def __init__(self, app, token: str, endpoint: str | None = None, mode: str = "observe", **kw):
        self.app = app
        self.client = SentinelClient(token, endpoint=endpoint or DEFAULT_ENDPOINT, mode=mode, **kw)

    def _info(self, environ):
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")
        qs = environ.get("QUERY_STRING", "")
        # query-param STRUCTURE (names + kinds, never values) so param tampering on a known route
        # is caught, not just unknown paths.
        query = dict(parse_qsl(qs, keep_blank_values=True))
        content_type = environ.get("CONTENT_TYPE")
        authed = bool(environ.get("HTTP_AUTHORIZATION") or environ.get("HTTP_COOKIE") or environ.get("HTTP_X_API_KEY"))
        return method, path, query, content_type, authed

    def __call__(self, environ, start_response):
        method, path, query, content_type, authed = self._info(environ)

        def _sketch(status):
            return build_sketch(method=method, path=path, query=query, authenticated=authed,
                                content_type=content_type, status=status)

        # enforce: block off-baseline shapes before dispatch
        if self.client.mode == "enforce" and not self.client.never_block(path):
            verdict = self.client.decide(_sketch(0))
            if self.client.should_block(verdict):
                try:
                    self.client.record(_sketch(403))
                except Exception:
                    pass
                body = json.dumps({"error": "blocked_by_nemesis_shield", "reason": verdict.get("reason")}).encode()
                start_response("403 Forbidden", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
                return [body]

        captured = {"status": 200}

        def sr(status, headers, exc_info=None):
            try:
                captured["status"] = int(str(status).split()[0])
            except Exception:
                pass
            return start_response(status, headers, exc_info) if exc_info else start_response(status, headers)

        result = self.app(environ, sr)
        try:
            self.client.record(_sketch(captured["status"]))
        except Exception:
            pass  # fail-open
        return result
