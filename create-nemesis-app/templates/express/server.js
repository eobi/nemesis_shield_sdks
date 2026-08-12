const express = require("express");
const { sentinel } = require("@nemesis-shield-autogon/sentinel/express");

const app = express();
app.use(express.json());

// Positive-security WAF. Registered before the routes so it sees every request,
// including ones that match no handler. Observe mode until you approve a baseline.
app.use(sentinel({ token: process.env.NEMESIS_TOKEN }));

app.get("/", (_req, res) => res.json({ ok: true }));

// Example object route. This is exactly the shape IDOR/BOLA attacks abuse:
// a well-formed request for an object id. Your handler must still check ownership,
// and Nemesis catches the access pattern that deviates from this user's normal.
app.get("/api/orders/:id", (req, res) => {
  res.json({ id: req.params.id, note: "check ownership here" });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`listening on http://localhost:${port}`));
