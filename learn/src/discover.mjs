// Route discovery from independent sources, merged. Any one is enough; together they aim for COMPLETE
// coverage of an app in ANY language/framework, new or very old — because a route missed here becomes a
// false block the day you enforce. The goal is a seamless observe -> enforce transition.
//
//   1. OpenAPI/Swagger  — the strongest signal (methods, params, body schemas, security). Zero guessing.
//   2. HTML crawl       — same-origin links, <form> actions, sitemap.xml, and URLs embedded in JS.
//   3. Repo static scan — framework route patterns + config files + file/controller conventions:
//        modern:  Express/Fastify/Koa/Nest, FastAPI/Flask/Django, Rails/Sinatra, Laravel/Lumen/Slim,
//                 Spring, Go (chi/gin/echo/gorilla), ASP.NET (MVC + minimal APIs).
//        legacy:  CodeIgniter, CakePHP, Symfony (annotations/attributes), Yii, JAX-RS, Java Servlets,
//                 Struts, classic PHP (file-per-route), classic ASP/.aspx/.jsp/.cfm, Perl/CGI.

import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { request } from "./http.mjs";

const OPENAPI_PATHS = ["/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs", "/v2/api-docs", "/swagger/v1/swagger.json", "/api/openapi.json", "/api-docs/swagger.json", "/docs/openapi.json", "/api/swagger.json", "/swagger/docs/v1"];

// ── 1. OpenAPI ──────────────────────────────────────────────────────────────
export async function discoverOpenApi(base, session) {
  for (const p of OPENAPI_PATHS) {
    const res = await request("GET", join2(base, p), { session, timeoutMs: 8000 });
    if (res.ok && res.json && (res.json.paths || res.json.openapi || res.json.swagger)) {
      return { spec: res.json, endpoints: parseOpenApi(res.json), specUrl: join2(base, p) };
    }
  }
  return { spec: null, endpoints: [] };
}

function parseOpenApi(spec) {
  const out = [];
  const resolve = (o) => (o && o.$ref ? deref(spec, o.$ref) : o);
  const basePath = spec.basePath || ""; // swagger 2.0
  for (const [path, item] of Object.entries(spec.paths || {})) {
    for (const method of ["get", "post", "put", "patch", "delete", "options", "head"]) {
      const op = item[method];
      if (!op) continue;
      const params = [...(item.parameters || []), ...(op.parameters || [])].map(resolve).map((p) => ({ name: p.name, in: p.in, required: !!p.required, schema: resolve(p.schema) }));
      let body = null;
      const rb = resolve(op.requestBody);
      if (rb && rb.content) {
        const ct = rb.content["application/json"] ? "application/json" : rb.content["multipart/form-data"] ? "multipart/form-data" : rb.content["application/x-www-form-urlencoded"] ? "application/x-www-form-urlencoded" : Object.keys(rb.content)[0];
        body = { contentType: ct, schema: inlineRefs(spec, resolve(rb.content[ct]?.schema)) };
      } else if (Array.isArray(op.parameters)) {
        // swagger 2.0 body parameter
        const bp = op.parameters.map(resolve).find((p) => p.in === "body");
        if (bp) body = { contentType: "application/json", schema: inlineRefs(spec, resolve(bp.schema)) };
      }
      out.push({ method: method.toUpperCase(), path: basePath + path, source: "openapi", params, body, security: op.security || spec.security || [] });
    }
  }
  return out;
}

function deref(spec, ref) {
  const parts = ref.replace(/^#\//, "").split("/");
  let cur = spec;
  for (const k of parts) cur = cur?.[decodeURIComponent(k.replace(/~1/g, "/").replace(/~0/g, "~"))];
  return cur;
}
function inlineRefs(spec, schema, depth = 0) {
  if (!schema || depth > 6) return schema;
  if (schema.$ref) return inlineRefs(spec, deref(spec, schema.$ref), depth + 1);
  const s = { ...schema };
  if (s.properties) { s.properties = Object.fromEntries(Object.entries(s.properties).map(([k, v]) => [k, inlineRefs(spec, v, depth + 1)])); }
  if (s.items) s.items = inlineRefs(spec, s.items, depth + 1);
  for (const key of ["allOf", "anyOf", "oneOf"]) if (Array.isArray(s[key])) s[key] = s[key].map((v) => inlineRefs(spec, v, depth + 1));
  return s;
}

// ── 2. HTML crawl (links + forms + sitemap + JS-embedded URLs) ────────────────
export async function crawl(base, session, { maxPages = 40 } = {}) {
  const origin = new URL(base).origin;
  const seen = new Set(), queue = [normalizeUrl(base)], endpoints = [];

  // Seed from sitemap.xml + robots.txt so we don't rely on link-reachability alone.
  for (const seed of ["/sitemap.xml", "/sitemap_index.xml", "/robots.txt"]) {
    const res = await request("GET", join2(base, seed), { session, timeoutMs: 6000 });
    if (res.ok && res.text) for (const u of extractSeedUrls(res.text)) { const a = safeUrl(u, base); if (a && a.startsWith(origin) && !isAsset(a)) queue.push(normalizeUrl(a)); }
  }

  while (queue.length && seen.size < maxPages) {
    const url = queue.shift();
    if (seen.has(url)) continue;
    seen.add(url);
    const res = await request("GET", url, { session, timeoutMs: 8000 });
    endpoints.push({ method: "GET", path: pathOf(url), source: "crawl", params: [], body: null });
    if (!res.text) continue;
    const isHtml = (res.headers?.["content-type"] || "").includes("html");
    // JS-embedded API URLs (fetch/axios/XHR/string literals) — catches SPA + AJAX endpoints.
    for (const u of extractJsUrls(res.text)) {
      const abs = safeUrl(u, url);
      if (abs && abs.startsWith(origin) && !isAsset(abs)) endpoints.push({ method: "GET", path: pathOf(abs), source: "crawl-js", params: [], body: null });
    }
    if (!isHtml) continue;
    for (const href of extractLinks(res.text)) {
      const abs = safeUrl(href, url);
      if (abs && abs.startsWith(origin) && !seen.has(normalizeUrl(abs)) && !isAsset(abs)) queue.push(normalizeUrl(abs));
    }
    for (const form of extractForms(res.text, url)) endpoints.push(form);
  }
  return { endpoints: dedupe(endpoints), pages: seen.size };
}

function extractLinks(html) {
  const out = [];
  for (const re of [/<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)["']/gi, /<(?:link|area)\b[^>]*\bhref\s*=\s*["']([^"'#]+)["']/gi]) {
    let m; while ((m = re.exec(html))) out.push(m[1]);
  }
  return out;
}
function extractSeedUrls(text) {
  const out = [];
  let m;
  const loc = /<loc>\s*([^<\s]+)\s*<\/loc>/gi;      // sitemap
  while ((m = loc.exec(text))) out.push(m[1]);
  const rob = /^\s*(?:Allow|Disallow|Sitemap)\s*:\s*(\S+)/gim; // robots
  while ((m = rob.exec(text))) if (m[1] && m[1] !== "/") out.push(m[1]);
  return out;
}
function extractJsUrls(text) {
  const out = [];
  let m;
  // fetch("/x"), axios.get('/x'), $.ajax({url:"/x"}), url: "/x", "/api/..." string literals
  const res = [
    /\bfetch\s*\(\s*[`'"]([^`'"]+)[`'"]/gi,
    /\b(?:axios|http|api)\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*[`'"]([^`'"]+)[`'"]/gi,
    /\burl\s*:\s*[`'"](\/[^`'"]+)[`'"]/gi,
    /[`'"](\/(?:api|v\d|rest|graphql|ajax)\/[^`'"?\s]{1,120})[`'"]/gi,
  ];
  for (const re of res) { while ((m = re.exec(text))) if (m[1] && m[1].startsWith("/")) out.push(m[1]); }
  return out.slice(0, 200);
}
function extractForms(html, pageUrl) {
  const out = [];
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let fm;
  while ((fm = formRe.exec(html))) {
    const attrs = fm[1], inner = fm[2];
    const action = (attrs.match(/\baction\s*=\s*["']([^"']*)["']/i) || [])[1] || pageUrl;
    const method = ((attrs.match(/\bmethod\s*=\s*["']([^"']*)["']/i) || [])[1] || "GET").toUpperCase();
    const enctype = (attrs.match(/\benctype\s*=\s*["']([^"']*)["']/i) || [])[1] || "";
    const fields = [];
    const inRe = /<(input|select|textarea)\b([^>]*)>/gi;
    let im;
    while ((im = inRe.exec(inner))) {
      const a = im[2];
      const name = (a.match(/\bname\s*=\s*["']([^"']*)["']/i) || [])[1];
      if (!name) continue;
      const type = (a.match(/\btype\s*=\s*["']([^"']*)["']/i) || [])[1] || (im[1].toLowerCase() === "textarea" ? "textarea" : "text");
      fields.push({ name, type });
    }
    const abs = safeUrl(action, pageUrl);
    out.push({ method, path: pathOf(abs || action), source: "crawl-form", params: [], body: null, form: { action: abs || action, method, enctype, fields } });
  }
  return out;
}

// ── 3. Repo static scan ──────────────────────────────────────────────────────
// Framework route DSLs, gated by file extension so one language's syntax can't false-match another's
// (e.g. Ruby's `get "x"` must not fire on PHP's `$req->get('x')`). p = path group; m = method group (null=GET).
const ROUTE_PATTERNS = [
  // Node: Express / Fastify / Koa / Hapi / restify
  { ext: ["js", "mjs", "cjs", "ts", "tsx", "jsx"], re: /\b(?:app|router|fastify|server|api|route[rs]?)\s*\.\s*(get|post|put|patch|delete|options|head|all)\s*\(\s*[`'"]([^`'"]+)[`'"]/gi, m: 1, p: 2 },
  { ext: ["js", "mjs", "cjs", "ts", "tsx", "jsx"], re: /\b(?:app|router)\s*\.\s*route\s*\(\s*[`'"]([^`'"]+)[`'"]/gi, m: null, p: 1 },
  // NestJS / TS decorators
  { ext: ["ts", "tsx", "js", "jsx"], re: /@(Get|Post|Put|Patch|Delete|All|Options|Head)\s*\(\s*[`'"]([^`'"]*)[`'"]\s*\)/g, m: 1, p: 2 },
  // Python: FastAPI / Flask / Bottle / Starlette
  { ext: ["py"], re: /@\w+\s*\.\s*(get|post|put|patch|delete|route)\s*\(\s*[`'"]([^`'"]+)[`'"]/gi, m: 1, p: 2 },
  { ext: ["py"], re: /\badd_url_rule\s*\(\s*[`'"]([^`'"]+)[`'"]/gi, m: null, p: 1 },
  { ext: ["py"], re: /\b(?:path|re_path|url)\s*\(\s*r?[`'"]\^?([^`'"$]*)/g, m: null, p: 1 }, // Django
  // Ruby: Rails (routes.rb) / Sinatra
  { ext: ["rb"], re: /\b(get|post|put|patch|delete)\s+[`'"]([^`'"]+)[`'"]/gi, m: 1, p: 2 },
  { ext: ["rb"], re: /\bmatch\s+[`'"]([^`'"]+)[`'"]/gi, m: null, p: 1 },
  // PHP: Laravel / Lumen
  { ext: ["php"], re: /Route::(get|post|put|patch|delete|options|any|match)\s*\(\s*[`'"]([^`'"]+)[`'"]/gi, m: 1, p: 2 },
  // PHP: Slim / Silex / Lumen closures — $app->get('/x', ...)  (require a leading-slash path to avoid $x->get('field'))
  { ext: ["php"], re: /\$\w+\s*->\s*(get|post|put|patch|delete|options|any|map)\s*\(\s*[`'"](\/[^`'"]*)[`'"]/gi, m: 1, p: 2 },
  // PHP: Symfony annotations + PHP8 attributes
  { ext: ["php"], re: /(?:@Route|#\[\s*Route)\s*\(\s*(?:path\s*[:=]\s*)?[`'"]([^`'"]+)[`'"]/g, m: null, p: 1 },
  // PHP: CakePHP router
  { ext: ["php"], re: /(?:Router::connect|\$routes\s*->\s*connect|\$routes\s*->\s*(?:get|post|put|patch|delete))\s*\(\s*[`'"](\/[^`'"]*)[`'"]/gi, m: null, p: 1 },
  // Java: Spring MVC / WebFlux
  { ext: ["java", "kt", "scala", "groovy"], re: /@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*[`'"]([^`'"]+)[`'"]/g, m: null, p: 1 },
  // Java: JAX-RS
  { ext: ["java", "kt", "scala"], re: /@Path\s*\(\s*[`'"]([^`'"]+)[`'"]/g, m: null, p: 1 },
  // Java: Servlet 3 annotation
  { ext: ["java", "kt"], re: /@WebServlet\s*\(\s*(?:value\s*=\s*|urlPatterns\s*=\s*)?\{?\s*[`'"]([^`'"]+)[`'"]/g, m: null, p: 1 },
  // .NET: ASP.NET attributes + minimal APIs
  { ext: ["cs"], re: /\[\s*Http(Get|Post|Put|Patch|Delete)\s*\(\s*[`'"]([^`'"]+)[`'"]/g, m: 1, p: 2 },
  { ext: ["cs"], re: /\[\s*Route\s*\(\s*[`'"]([^`'"]+)[`'"]/g, m: null, p: 1 },
  { ext: ["cs"], re: /\.\s*Map(?:Get|Post|Put|Patch|Delete)?\s*\(\s*[`'"]([^`'"]+)[`'"]/g, m: null, p: 1 },
  // Go: chi / gorilla / gin / echo / net-http
  { ext: ["go"], re: /\.\s*(GET|POST|PUT|PATCH|DELETE|Handle|HandleFunc)\s*\(\s*[`'"]([^`'"]+)[`'"]/g, m: 1, p: 2 },
];

// RESTful resource expansions (Rails `resources :x`, Laravel `Route::resource('x')`).
function expandResource(name) {
  const n = name.replace(/^\//, "");
  return [
    { method: "GET", path: `/${n}` }, { method: "POST", path: `/${n}` },
    { method: "GET", path: `/${n}/new` }, { method: "GET", path: `/${n}/{id}` },
    { method: "GET", path: `/${n}/{id}/edit` }, { method: "PUT", path: `/${n}/{id}` },
    { method: "PATCH", path: `/${n}/{id}` }, { method: "DELETE", path: `/${n}/{id}` },
  ];
}

// Parse framework config/manifest files that declare routes declaratively.
function parseConfigRoutes(name, src, file) {
  const eps = [];
  const push = (method, path) => { let p = normPath(path); if (p) eps.push({ method: normMethod(method), path: p, source: `repo-config:${file}`, params: [], body: null }); };

  // CodeIgniter application/config/routes.php  — $route['from'] = 'controller/method';
  if (/routes\.php$/i.test(name) && /\$route\s*\[/.test(src)) {
    const re = /\$route\s*\[\s*[`'"]([^`'"]+)[`'"]\s*\]\s*=/g; let m;
    const skip = new Set(["default_controller", "translate_uri_dashes", "404_override"]);
    while ((m = re.exec(src))) { const key = m[1]; if (skip.has(key)) continue; push("GET", "/" + key.replace(/\(:any\)/g, "*").replace(/\(:num\)/g, "*")); }
  }
  // Java web.xml  — <url-pattern>/foo/*</url-pattern>
  if (/web\.xml$/i.test(name)) {
    const re = /<url-pattern>\s*([^<\s]+)\s*<\/url-pattern>/gi; let m;
    while ((m = re.exec(src))) push("GET", m[1].replace(/\*$/, ""));
  }
  // Struts  — <action name="save" ...>  -> /save.action and /save
  if (/struts.*\.xml$/i.test(name) || /struts\.xml$/i.test(name)) {
    const re = /<action\b[^>]*\bname\s*=\s*["']([^"'*]+)["']/gi; let m;
    while ((m = re.exec(src))) { push("GET", "/" + m[1] + ".action"); push("GET", "/" + m[1]); }
  }
  // Rails resources :posts / resource :profile
  if (/routes\.rb$/i.test(name)) {
    let m; const rr = /\bresources?\s+:([a-z_][a-z0-9_]*)/gi;
    while ((m = rr.exec(src))) for (const e of expandResource(m[1])) eps.push({ ...e, source: `repo-config:${file}`, params: [], body: null });
  }
  // Laravel Route::resource('photos', ...) / apiResource
  if (/\.php$/i.test(name)) {
    let m; const lr = /Route::(?:api)?resource\s*\(\s*[`'"]([^`'"]+)[`'"]/g;
    while ((m = lr.exec(src))) for (const e of expandResource(m[1])) eps.push({ ...e, source: `repo-config:${file}`, params: [], body: null });
  }
  return eps;
}

// Controller-convention routing: CodeIgniter / CakePHP / Yii map URLs to controller class + public
// method (no route table). Only applied to files under a controllers/ directory.
const CTRL_DENY = new Set(["index", "__construct", "__destruct", "__get", "__set", "__call", "__callstatic",
  "beforefilter", "afterfilter", "beforerender", "afteraction", "beforeaction", "initialize", "init",
  "behaviors", "accesscontrol", "actions", "filters", "rules"]);
// Bases that mean "URL maps to controller/method by convention". Laravel/Symfony are route-table
// frameworks and must NOT be convention-expanded (their controllers aren't reachable by name).
const CONV_BASE = /\b(CI_Controller|MY_Controller|MX_Controller|REST_Controller|AppController|CController|Controller)\b/;
function parseControllerConvention(name, src, file) {
  if (!/(^|[\\/])controllers?[\\/]/i.test(file)) return [];
  // Skip route-table frameworks masquerading with a "Controller" base.
  if (/Illuminate\\|use\s+Symfony\\|namespace\s+App\\Http\\Controllers|extends\s+AbstractController/.test(src)) return [];
  const cls = src.match(/class\s+([A-Za-z_]\w*)\s+extends\s+([A-Za-z_\\]*)/);
  if (!cls) return [];
  const base = cls[2].split("\\").pop();
  // Require a genuine convention base OR Yii-style action* methods; otherwise don't invent routes.
  if (!CONV_BASE.test(base) && !/function\s+action[A-Z]/.test(src)) return [];
  let ctrl = cls[1].replace(/Controller$/i, "");   // Cake/Yii strip the suffix; CI names are bare
  if (!ctrl) return [];
  ctrl = ctrl.charAt(0).toLowerCase() + ctrl.slice(1);
  const eps = [{ method: "GET", path: `/${ctrl}`, source: `repo-ctrl:${file}`, params: [], body: null }];
  const seen = new Set();
  const mre = /public\s+function\s+([a-z_]\w*)\s*\(/gi; let m;
  while ((m = mre.exec(src))) {
    let fn = m[1];
    if (fn.startsWith("_")) continue;                 // magic + private-by-convention
    const yii = fn.match(/^action([A-Z]\w*)$/);       // Yii: actionLogin -> /ctrl/login
    if (yii) fn = yii[1].charAt(0).toLowerCase() + yii[1].slice(1);
    if (CTRL_DENY.has(fn.toLowerCase()) || seen.has(fn)) continue;
    seen.add(fn);
    eps.push({ method: "GET", path: `/${ctrl}/${fn}`, source: `repo-ctrl:${file}`, params: [], body: null });
  }
  return eps;
}

// Class/controller-level route prefix. Method decorators give the suffix (`@Get(':id')`) but the real
// path includes the class prefix (`@Controller('users')` -> /users/:id). Missing this = a wrong path =
// a route the SDK never learns = a false block on enforce. Same-file detection (one controller/file).
function classPrefix(src, ext) {
  if (["ts", "tsx", "js", "jsx"].includes(ext)) {
    const m = src.match(/@Controller\s*\(\s*[`'"]([^`'"]*)[`'"]/); // NestJS @Controller('users')
    if (m) return m[1];
    return null;
  }
  if (["java", "kt", "scala", "groovy"].includes(ext)) {
    // Spring class-level @RequestMapping — the one immediately preceding the class/interface declaration.
    const m = src.match(/@RequestMapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*[`'"]([^`'"]+)[`'"][\s\S]{0,500}?\b(?:public\s+|final\s+|abstract\s+)*(?:class|interface)\s/);
    if (m) return m[1];
    return null;
  }
  return null;
}
// Join a normalized prefix with a normalized path -> single clean path.
function joinPrefix(prefix, path) {
  const a = String(prefix).replace(/\/+$/, "");
  const b = path === "/" ? "" : path;
  return (a + b) || "/";
}

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "vendor", "__pycache__", "target", ".venv", "venv", "out", "coverage", "bower_components", ".svn"]);
// Files we scan for route DSLs / config / controllers.
const CODE_EXT = /\.(js|mjs|cjs|ts|tsx|jsx|py|rb|php|java|kt|scala|go|cs|xml)$/;
// Files a classic web server serves directly (one URL per file). Legacy-app catch-all.
const SERVE_EXT = /\.(php|phtml|php[3457]|asp|aspx|ashx|asmx|jsp|jspx|cfm|cfc|cgi|pl|py|do|action|html?|shtml)$/i;
// For the file-per-route pass, ignore framework SOURCE dirs (not web-served).
const NONSERVE_SEG = /(^|[\\/])(app|src|lib|libs|config|configs|database|db|migrations|storage|tests?|spec|resources|bootstrap|routes|system|application[\\/](?!controllers)|node_modules|vendor|target|\.git|includes?[\\/]internal)([\\/]|$)/i;
const WEBROOT_DIRS = ["public", "public_html", "www", "htdocs", "wwwroot", "web", "webroot", "html"];

function detectWebRoot(dir) {
  for (const w of WEBROOT_DIRS) {
    const p = join(dir, w);
    try { if (statSync(p).isDirectory()) return p; } catch { /* nope */ }
  }
  return dir; // classic layout: the repo root is the docroot
}

// A served file -> its URL path (index.* collapses to the directory).
function fileToRoute(full, webRoot, file) {
  let rel = relative(webRoot, full).split(sep).join("/");
  rel = rel.replace(/\/?index\.(php|phtml|html?|asp|aspx|jsp|jspx|cfm|cgi|pl)$/i, "/");
  if (!rel.startsWith("/")) rel = "/" + rel;
  rel = rel.replace(/\/{2,}/g, "/");
  return { method: "GET", path: rel || "/", source: `repo-file:${file}`, params: [], body: null };
}

export function discoverRepo(dir, { maxFiles = 8000 } = {}) {
  const endpoints = [];
  let scanned = 0;
  const webRoot = detectWebRoot(dir);
  const walk = (d) => {
    let entries;
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (scanned >= maxFiles) return;
      const full = join(d, e.name);
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name) && !(e.name.startsWith(".") && e.name.length > 1)) walk(full); continue; }
      const file = relative(dir, full).split(sep).join("/");

      // (a) File-per-route pass — classic PHP/ASP/JSP/CFM/CGI sites. Only inside the docroot and not in
      //     framework source dirs. This is the "nothing missing" catch-all for convention-routed apps.
      if (SERVE_EXT.test(e.name) && full.startsWith(webRoot) && !NONSERVE_SEG.test(file)) {
        endpoints.push(fileToRoute(full, webRoot, file));
      }

      if (!CODE_EXT.test(e.name)) continue;
      scanned++;
      let src;
      try { src = readFileSync(full, "utf8"); } catch { continue; }
      if (src.length > 2_000_000) continue; // skip generated/minified megafiles

      // (b) Declarative config routes (CI routes.php, web.xml, struts.xml, Rails/Laravel resources).
      for (const ep of parseConfigRoutes(e.name, src, file)) endpoints.push(ep);
      // (c) Controller-convention routes (CodeIgniter/CakePHP).
      for (const ep of parseControllerConvention(e.name, src, file)) endpoints.push(ep);
      // (d) Framework route DSL patterns — only those matching this file's language.
      const ext = (e.name.match(/\.([a-z0-9]+)$/i) || [])[1]?.toLowerCase();
      const prefixRaw = ext ? classPrefix(src, ext) : null;         // NestJS @Controller / Spring class @RequestMapping
      const prefix = prefixRaw ? normPath(prefixRaw) : null;
      for (const pat of ROUTE_PATTERNS) {
        if (ext && !pat.ext.includes(ext)) continue;
        pat.re.lastIndex = 0;
        let m;
        while ((m = pat.re.exec(src))) {
          const method = pat.m ? m[pat.m] : "GET";
          let path = normPath(pat.p ? m[pat.p] : "");
          if (!path) continue;
          // Compose the class prefix (unless this capture IS the class-level mapping itself).
          if (prefix && prefix !== "/" && path !== prefix) path = joinPrefix(prefix, path);
          endpoints.push({ method: normMethod(method), path, source: `repo:${file}`, params: [], body: null });
        }
      }
      // Bare method decorators under a controller (@Post(), @GetMapping()) = the controller's index route.
      if (prefix && prefix !== "/" && ["ts", "tsx", "js", "jsx", "java", "kt"].includes(ext)) {
        const bare = /@(Get|Post|Put|Patch|Delete|All)(?:Mapping)?\s*\(\s*\)/g;
        let bm;
        while ((bm = bare.exec(src))) endpoints.push({ method: normMethod(bm[1] === "All" ? "GET" : bm[1]), path: prefix, source: `repo:${file}`, params: [], body: null });
      }
    }
  };
  walk(dir);
  return { endpoints: dedupe(endpoints), filesScanned: scanned };
}

// ── merge / util ──────────────────────────────────────────────────────────────
export function mergeEndpoints(...lists) {
  const map = new Map();
  for (const ep of lists.flat()) {
    if (!ep || !ep.path) continue;
    const key = `${ep.method} ${ep.path}`;
    if (!map.has(key)) map.set(key, ep);
    else {
      const cur = map.get(key);
      if ((ep.body || ep.form || ep.params?.length) && !(cur.body || cur.form || cur.params?.length)) map.set(key, ep);
    }
  }
  return [...map.values()];
}
function dedupe(eps) { return mergeEndpoints(eps); }

function normMethod(method) {
  const m = String(method || "GET").toUpperCase();
  return ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"].includes(m) ? m : "GET";
}
// Clean + validate a captured path. Rejects obvious non-routes; normalizes framework placeholders.
function normPath(raw) {
  if (!raw) return null;
  let p = String(raw).trim();
  if (!p) return null;
  if (/^(https?:)?\/\//i.test(p)) { try { p = new URL(p.startsWith("//") ? "http:" + p : p).pathname; } catch { return null; } }
  p = p.split("?")[0].split("#")[0];
  // Rails/Sinatra "get 'foo'" style, Yii "foo/bar" — ensure a leading slash.
  if (!p.startsWith("/")) p = "/" + p;
  // Normalize placeholders: :id  {id}  <id>  <int:id>  (:num)  *  -> {seg}
  p = p.replace(/\(:num\)/g, "{id}").replace(/\(:any\)/g, "{seg}")
       .replace(/<[^>]*?([a-z_]\w*)>/gi, "{$1}")
       .replace(/:([a-z_]\w*)/gi, "{$1}");
  p = p.replace(/\\+/g, "").replace(/\/{2,}/g, "/");
  // Reject values that are clearly not URL paths (spaces, PHP vars, regex leftovers, code fragments).
  if (/[\s$()=;]/.test(p)) return null;
  if (p.length > 200) return null;
  if (!/^\/[\w\-./{}*~%]*$/.test(p)) return null;
  return p;
}

const join2 = (base, p) => base.replace(/\/$/, "") + (String(p).startsWith("/") ? p : "/" + p);
const normalizeUrl = (u) => { try { const x = new URL(u); x.hash = ""; return x.toString(); } catch { return u; } };
const pathOf = (u) => { try { return new URL(u).pathname + (new URL(u).search || ""); } catch { return u; } };
const safeUrl = (href, baseUrl) => { try { return new URL(href, baseUrl).toString(); } catch { return null; } };
const isAsset = (u) => /\.(css|js|mjs|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|pdf|zip|gz|mp4|mp3|webp|webm|avif)(\?|$)/i.test(u);
