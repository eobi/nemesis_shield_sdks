"""Live demo app - a real WSGI server guarded by the Python SDK (SentinelWSGI). Returns 200 for
everything; the shield decides what to block. Token + endpoint from env."""
import os
import sys
from socketserver import ThreadingMixIn
from wsgiref.simple_server import make_server, WSGIServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "python"))
from nemesis_shield.wsgi import SentinelWSGI


def app(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"ok"]


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


port = int(os.environ.get("PORT", "8801"))
wrapped = SentinelWSGI(app, os.environ["NEMESIS_TOKEN"],
                       endpoint=os.environ.get("NEMESIS_ENDPOINT"), flush_interval=0.5)
make_server("127.0.0.1", port, wrapped, server_class=ThreadingWSGIServer).serve_forever()
