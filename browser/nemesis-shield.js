/*!
 * Nemesis Shield — Browser SDK (client-side runtime protection).
 *
 * Learns your page's normal CLIENT-SIDE behavior — which script origins load, which origins the page
 * calls (fetch/XHR/beacon), and where forms submit — then in enforce mode BLOCKS deviations:
 * Magecart/skimmer scripts injected from unapproved origins, data exfiltration to rogue endpoints,
 * and form-jacking. A learned, per-app allow-list — like a CSP the app owner curates in the console.
 *
 * Works with React, Angular, Vue, jQuery, and plain JavaScript — it hooks the browser primitives
 * (fetch / XMLHttpRequest / sendBeacon / DOM mutations / form submit), which every framework shares.
 * Fail-open (never breaks the page), privacy-preserving (ships only origins + event shapes, never
 * payloads or DOM content), first-party traffic is always allowed.
 *
 *   <!-- drop-in on any site (raw JS, jQuery, legacy Angular.js, server-rendered) -->
 *   <script src="nemesis-shield.js" data-token="nsk_your_app_token"></script>
 *
 *   // or in a bundled app (React/Vue/Angular), once at bootstrap:
 *   import NemesisShield from "@nemesis-shield/browser";
 *   NemesisShield.init({ token: import.meta.env.VITE_NEMESIS_TOKEN });
 */
(function (root, factory) {
  var mod = factory();
  if (typeof module === "object" && module.exports) module.exports = mod;
  if (root) root.NemesisShield = mod;
  // Auto-init when included as <script src=... data-token=...>
  try {
    if (typeof document !== "undefined") {
      var cs = document.currentScript;
      var tok = cs && cs.getAttribute && cs.getAttribute("data-token");
      if (tok) mod.init({ token: tok });
    }
  } catch (e) {
    /* never break the host page */
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  var DEFAULT_ENDPOINT = "https://shield.nemesislabs.xyz/api/v1/sketches";

  function fnv1a(s) {
    var h = 0x811c9dc5 >>> 0;
    for (var i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i) & 0xff;
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return ("0000000" + h.toString(16)).slice(-8);
  }

  function originOf(url, base) {
    try {
      return new URL(url, base || undefined).origin.toLowerCase();
    } catch (e) {
      return null;
    }
  }

  // Client-side event -> a sketch that flows through the SAME server pipeline as backend requests.
  // "route" carries the scheme: script://<origin>, connect://<origin>, form://<origin>.
  function shapeOf(kind, origin) {
    var K = kind.toUpperCase();
    var route = kind + "://" + origin;
    var canon = '{"route":"' + route + '","method":"' + K + '","params":[],"auth":0}';
    return { route: route, method: K, shape: fnv1a(canon) };
  }

  function createShield(opts) {
    opts = opts || {};
    var env = opts.env || (typeof window !== "undefined" ? window : globalThis);
    var token = opts.token || env.NEMESIS_TOKEN || "";
    var endpoint = opts.endpoint || DEFAULT_ENDPOINT;
    var selfOrigin = (
      opts.selfOrigin ||
      (env.location && env.location.origin) ||
      ""
    ).toLowerCase();
    var fetchImpl = opts.fetch || (env.fetch ? env.fetch.bind(env) : null);

    var state = { mode: "observe", shapes: {}, knownBad: {}, haveBaseline: false };
    var buffer = [];

    function applyPolicy(d) {
      if (!d) return;
      if (d.mode) state.mode = d.mode;
      var pol = d.policy || {};
      if (pol.shapes) {
        state.shapes = pol.shapes;
        state.haveBaseline = Object.keys(pol.shapes).length > 0;
      }
      state.knownBad = {};
      (pol.knownBad || []).forEach(function (s) {
        state.knownBad[s] = 1;
      });
    }

    function decide(shape) {
      var per = state.shapes[shape];
      if (per === "allow") return null;
      if (per === "block") return "policy: blocked shape";
      if (state.knownBad[shape]) return "global threat intelligence";
      if (state.haveBaseline) return "off-baseline: unapproved behavior";
      return null;
    }

    function post(sketchesJson) {
      if (!token || !fetchImpl) return Promise.resolve();
      return fetchImpl(endpoint, {
        method: "POST",
        headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
        body: '{"sketches":' + sketchesJson + "}",
        keepalive: true,
      })
        .then(function (r) {
          return r && r.ok ? r.json() : null;
        })
        .then(applyPolicy)
        .catch(function () {
          /* fail open */
        });
    }

    function record(kind, origin, status) {
      var s = shapeOf(kind, origin);
      buffer.push(
        '{"route":"' +
          s.route +
          '","method":"' +
          s.method +
          '","authenticated":false,"status":' +
          status +
          ',"params":[],"shape":"' +
          s.shape +
          '"}'
      );
      if (buffer.length >= 25) flush();
    }
    function flush() {
      if (!buffer.length) return;
      var b = buffer;
      buffer = [];
      post("[" + b.join(",") + "]");
    }
    function refresh() {
      post("[]");
    }

    // Core verdict for a client-side event. Records it, returns true to BLOCK.
    function shouldBlock(kind, origin) {
      if (!origin || origin === selfOrigin) return false; // first-party is always allowed
      if (state.mode !== "enforce") {
        record(kind, origin, 200);
        return false;
      }
      var reason = decide(shapeOf(kind, origin).shape);
      record(kind, origin, reason ? 403 : 200);
      return !!reason;
    }

    // ---- browser instrumentation (all wrapped in try/catch so the page is never broken) ----
    function installNetwork() {
      if (env.fetch) {
        var orig = env.fetch.bind(env);
        env.fetch = function (input, init) {
          try {
            var url = typeof input === "string" ? input : input && input.url;
            if (shouldBlock("connect", originOf(url, selfOrigin)))
              return Promise.reject(new Error("blocked_by_nemesis_shield"));
          } catch (e) {}
          return orig(input, init);
        };
      }
      if (env.XMLHttpRequest && env.XMLHttpRequest.prototype) {
        var P = env.XMLHttpRequest.prototype;
        var O = P.open;
        P.open = function (m, u) {
          try {
            this.__nsOrigin = originOf(u, selfOrigin);
          } catch (e) {}
          return O.apply(this, arguments);
        };
        var S = P.send;
        P.send = function () {
          try {
            if (shouldBlock("connect", this.__nsOrigin)) {
              this.abort();
              return;
            }
          } catch (e) {}
          return S.apply(this, arguments);
        };
      }
      if (env.navigator && env.navigator.sendBeacon) {
        var SB = env.navigator.sendBeacon.bind(env.navigator);
        env.navigator.sendBeacon = function (u, data) {
          try {
            if (shouldBlock("connect", originOf(u, selfOrigin))) return false;
          } catch (e) {}
          return SB(u, data);
        };
      }
    }

    function inspectNode(n) {
      try {
        if (!n || n.nodeType !== 1) return;
        var tag = n.tagName;
        if ((tag === "SCRIPT" || tag === "IFRAME") && n.src) {
          if (shouldBlock("script", originOf(n.src, selfOrigin))) {
            if (tag === "SCRIPT") n.type = "javascript/blocked";
            if (n.parentNode) n.parentNode.removeChild(n);
          }
        }
      } catch (e) {}
    }

    function installDom() {
      if (!env.document) return;
      try {
        var ss = env.document.getElementsByTagName("script");
        for (var i = 0; i < ss.length; i++)
          if (ss[i].src) shouldBlock("script", originOf(ss[i].src, selfOrigin));
      } catch (e) {}
      if (!env.MutationObserver) return;
      var mo = new env.MutationObserver(function (muts) {
        for (var i = 0; i < muts.length; i++) {
          var added = muts[i].addedNodes || [];
          for (var j = 0; j < added.length; j++) inspectNode(added[j]);
        }
      });
      try {
        mo.observe(env.document.documentElement || env.document, {
          childList: true,
          subtree: true,
        });
      } catch (e) {}
    }

    function installForms() {
      if (!env.document || !env.document.addEventListener) return;
      env.document.addEventListener(
        "submit",
        function (e) {
          try {
            var f = e.target;
            if (f && f.action && shouldBlock("form", originOf(f.action, selfOrigin)))
              e.preventDefault();
          } catch (err) {}
        },
        true
      );
    }

    function install() {
      if (!token) return api;
      installNetwork();
      installDom();
      installForms();
      refresh();
      if (env.setInterval)
        env.setInterval(function () {
          flush();
          refresh();
        }, 5000);
      return api;
    }

    var api = {
      install: install,
      refresh: refresh,
      flush: flush,
      decide: decide,
      shapeOf: shapeOf,
      shouldBlock: shouldBlock,
      _applyPolicy: applyPolicy,
      _state: state,
    };
    return api;
  }

  return {
    createShield: createShield,
    init: function (opts) {
      return createShield(opts).install();
    },
    shapeOf: shapeOf,
    fnv1a: fnv1a,
  };
});
