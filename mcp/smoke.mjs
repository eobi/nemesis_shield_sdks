// Minimal stdio JSON-RPC smoke test: initialize -> tools/list -> tools/call. No MCP client dep.
import { spawn } from "node:child_process";

const child = spawn("node", ["dist/index.js"], { stdio: ["pipe", "pipe", "inherit"] });
let buf = "";
const seen = {};
child.stdout.on("data", (d) => {
  buf += d.toString();
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.id) seen[msg.id] = msg;
    if (msg.id === 2) {
      console.log("TOOLS:", (msg.result?.tools || []).map((t) => t.name).join(", "));
    }
    if (msg.id === 3) {
      console.log("PROTECT(fastapi) ->\n" + (msg.result?.content?.[0]?.text || JSON.stringify(msg)).split("\n").slice(0, 6).join("\n"));
    }
    if (msg.id === 4) {
      console.log("EXPLAIN(idor) ->\n" + (msg.result?.content?.[0]?.text || "").slice(0, 160));
      child.kill();
      process.exit(0);
    }
  }
});
const send = (o) => child.stdin.write(JSON.stringify(o) + "\n");
send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "smoke", version: "0" } } });
send({ jsonrpc: "2.0", method: "notifications/initialized" });
send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "nemesis_protect", arguments: { framework: "fastapi" } } });
send({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "nemesis_explain", arguments: { topic: "idor" } } });
setTimeout(() => { console.error("timeout"); child.kill(); process.exit(1); }, 8000);
