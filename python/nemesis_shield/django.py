"""Django middleware. Add to settings.py:

    MIDDLEWARE = ["nemesis_shield.django.SentinelDjango", ...]

and set NEMESIS_TOKEN (or NEMESIS_SHIELD_TOKEN) in the environment. Observes every request; in
enforce mode blocks off-baseline requests (403) before your views run. Fail-open.
"""

import os

from .client import SentinelClient, DEFAULT_ENDPOINT
from .sketch import build_sketch

_client = None


def _get_client():
    global _client
    if _client is None:
        token = os.environ.get("NEMESIS_TOKEN") or os.environ.get("NEMESIS_SHIELD_TOKEN") or ""
        endpoint = os.environ.get("NEMESIS_ENDPOINT") or DEFAULT_ENDPOINT
        try:
            flush = float(os.environ.get("NEMESIS_SHIELD_FLUSH", "5"))
        except ValueError:
            flush = 5.0
        _client = SentinelClient(token, endpoint=endpoint, mode="observe", flush_interval=flush) if token else None
    return _client


class SentinelDjango:
    def __init__(self, get_response):
        self.get_response = get_response
        self.client = _get_client()

    def __call__(self, request):
        if not self.client:
            return self.get_response(request)
        method = request.method
        path = request.path
        authed = bool(request.headers.get("Authorization") or request.headers.get("Cookie") or request.headers.get("X-Api-Key"))

        if self.client.mode == "enforce":
            verdict = self.client.decide(build_sketch(method=method, path=path, authenticated=authed, status=0))
            if self.client.should_block(verdict):
                try:
                    self.client.record(build_sketch(method=method, path=path, authenticated=authed, status=403))
                except Exception:
                    pass
                from django.http import JsonResponse
                return JsonResponse({"error": "blocked_by_nemesis_shield", "reason": verdict.get("reason")}, status=403)

        response = self.get_response(request)
        try:
            self.client.record(build_sketch(method=method, path=path, authenticated=authed, status=response.status_code))
        except Exception:
            pass
        return response
