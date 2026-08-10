// E2E live round-trip for the Node SDK. Builds a real sketch for each fixed route via the SDK's
// own buildSketch (so the shape hash is the SDK's, not a reimplementation), prints the shape hash,
// then POSTs the batch to the LIVE sketches endpoint and prints the HTTP status.
import { buildSketch } from "./lib/shape.js";

const token = process.env.NEMESIS_TOKEN || "";
const ENDPOINT = "https://shield.nemesislabs.xyz/api/v1/sketches";
const ROUTES = [
  ["GET", "/app/incidents/inc_ip_1_2_3_4_1786400000000"],
  ["GET", "/app/network/autogon.ai"],
  ["GET", "/app/applications/f47ac10b-58cc-4372-a567-0e02b2c3d479"],
];

const sketches = [];
for (const [method, path] of ROUTES) {
  const s = buildSketch({ method, path, authenticated: false, status: 200 });
  console.log(`SHAPE ${path} route=${s.route} hash=${s.shape}`);
  sketches.push(s);
}

try {
  const r = await fetch(ENDPOINT, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ sketches }),
  });
  console.log(`POST_STATUS ${r.status}`);
} catch (e) {
  console.log(`POST_STATUS ERR ${e}`);
}
