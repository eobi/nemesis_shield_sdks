# @nemesis-shield/sentinel — Node.js

```bash
npm install @nemesis-shield/sentinel
```
```js
import { sentinel } from "@nemesis-shield/sentinel/express";
app.use(sentinel({ token: process.env.NEMESIS_TOKEN }));
```
Options: `{ token, endpoint?, authed?(req)=>boolean, shapePaths? }`. Also exports `report(token, events)`
and `reportLLM(token, exchange)`. Fail-open; ships only method/path-shape/status/authenticated.
Get a token at https://shield.nemesislabs.xyz → Protect an app.
