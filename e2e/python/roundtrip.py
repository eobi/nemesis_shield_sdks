"""E2E live round-trip for the Python SDK. Builds a real sketch per fixed route via the SDK's own
build_sketch, prints the shape hash, then POSTs the batch to the LIVE sketches endpoint."""
import json
import os
import urllib.error
import urllib.request

from nemesis_shield import build_sketch

TOKEN = os.environ.get("NEMESIS_TOKEN", "")
ENDPOINT = "https://shield.nemesislabs.xyz/api/v1/sketches"
ROUTES = [
    ("GET", "/app/incidents/inc_ip_1_2_3_4_1786400000000"),
    ("GET", "/app/network/autogon.ai"),
    ("GET", "/app/applications/f47ac10b-58cc-4372-a567-0e02b2c3d479"),
]

sketches = []
for method, path in ROUTES:
    s = build_sketch(method=method, path=path, authenticated=False, status=200)
    print(f"SHAPE {path} route={s['route']} hash={s['shape']}")
    sketches.append(s)

data = json.dumps({"sketches": sketches}).encode()
req = urllib.request.Request(
    ENDPOINT,
    data=data,
    headers={"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"},
    method="POST",
)
try:
    with urllib.request.urlopen(req) as resp:
        print(f"POST_STATUS {resp.status}")
except urllib.error.HTTPError as e:
    print(f"POST_STATUS {e.code}")
except Exception as e:  # noqa: BLE001
    print(f"POST_STATUS ERR {e}")
