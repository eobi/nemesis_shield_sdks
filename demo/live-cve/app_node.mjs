// Live demo app — a real Node http server guarded by the Express/Connect adapter. The adapter is
// framework-agnostic enough to run on raw http (req.url/headers, res.statusCode/end/on("finish")).
import http from "http";
import { sentinel } from "../../node/express.js";

const mw = sentinel({
  token: process.env.NEMESIS_TOKEN,
  endpoint: process.env.NEMESIS_ENDPOINT,
  flushInterval: 500,
});

http
  .createServer((req, res) =>
    mw(req, res, () => {
      res.statusCode = 200;
      res.setHeader("content-type", "text/plain");
      res.end("ok");
    })
  )
  .listen(Number(process.env.PORT), "127.0.0.1");
