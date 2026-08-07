package io.github.eobi.sentinel;

// Nemesis Shield - Sentinel SDK for Java (native, JDK 11+, no dependencies). Learns your app's normal
// behavior; in enforce mode blocks off-baseline requests (auth bypass, path traversal, scanners,
// unusual methods) before your handlers run. Positive-security, fail-open, privacy-preserving.
//
//   var nemesis = new NemesisShield(System.getenv("NEMESIS_TOKEN"));
//   // in a servlet Filter / interceptor / handler, at the start of a request:
//   if (nemesis.guard(method, path, authed, resp)) return;   // blocked -> 403 written
//   // after the response:
//   nemesis.observe(method, path, authed, status);

import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NemesisShield {
    private static final String ENDPOINT = "https://shield.nemesislabs.xyz/api/v1/sketches";
    // Canonical value taxonomy - matches the shared engine (tokenize.ts) byte-for-byte.
    private static final Pattern INT = Pattern.compile("^-?\\d+$");
    private static final Pattern FLOAT = Pattern.compile("^-?\\d*\\.\\d+$");
    private static final Pattern UUID = Pattern.compile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final Pattern EMAIL = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
    private static final Pattern URL = Pattern.compile("(?i)^https?://\\S+$");
    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}$");
    private static final Pattern IPV6 = Pattern.compile("(?i)^[0-9a-f:]+:[0-9a-f:]+$");
    private static final Pattern DATE = Pattern.compile("^\\d{4}-\\d{2}-\\d{2}([T ]\\d{2}:\\d{2}(:\\d{2})?)?");
    private static final Pattern JWT = Pattern.compile("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$");
    private static final Pattern HEX = Pattern.compile("(?i)^[0-9a-f]+$");
    private static final Pattern B64 = Pattern.compile("^[A-Za-z0-9+/]+={0,2}$");
    private static final Pattern ALPHA = Pattern.compile("^[A-Za-z]+$");
    private static final Pattern ALNUM = Pattern.compile("^[A-Za-z0-9]+$");
    // A run of 7+ letters => reads like a word / route name, not an opaque id/token.
    private static final Pattern WORD = Pattern.compile("[A-Za-z]{7,}");

    static String kindOf(String s) {
        if (s == null || s.isEmpty()) return "empty";
        if (UUID.matcher(s).matches()) return "uuid";
        if (EMAIL.matcher(s).matches()) return "email";
        if (URL.matcher(s).matches()) return "url";
        if (IPV4.matcher(s).matches()) return "ipv4";
        if (IPV6.matcher(s).matches()) return "ipv6";
        if (JWT.matcher(s).matches()) return "jwt";
        if (DATE.matcher(s).lookingAt()) return "date";
        if (INT.matcher(s).matches()) return "int";
        if (FLOAT.matcher(s).matches()) return "float";
        if (s.length() >= 16 && HEX.matcher(s).matches()) return "hex";
        if (s.length() >= 16 && B64.matcher(s).matches() && !WORD.matcher(s).find()) return "base64";
        if (ALPHA.matcher(s).matches()) return "alpha";
        if (ALNUM.matcher(s).matches()) return "alnum";
        return "string";
    }

    // Parse a raw query string ("a=1&b=x") into the canonical params array [[name,kind,nested],...],
    // sorted + deduped by name (repeated key -> nested). Values are classified, never kept.
    // Analytics / click-tracking query params carry no application logic and are the main cause of
    // shape explosion (every ad/campaign link adds different ones). Stripped from the signature so a
    // UTM'd request matches the bare route, while real params (and any attack in them) stay modeled.
    // Shared, identical across every Nemesis Shield SDK so the shape hash matches everywhere.
    private static final String[] TRACKING_PREFIXES = {"utm_", "mtm_", "pk_", "hsa_", "matomo_", "piwik_", "ga_"};
    private static final java.util.Set<String> TRACKING_EXACT = new java.util.HashSet<>(java.util.Arrays.asList(
        "gclid", "gbraid", "wbraid", "dclid", "gclsrc", "fbclid", "msclkid", "twclid", "ttclid", "yclid",
        "igshid", "scid", "wickedid", "_ga", "_gl", "_hsenc", "_hsmi", "mc_cid", "mc_eid", "vero_id",
        "vero_conv", "oly_anon_id", "oly_enc_id", "_openstat", "rb_clickid", "s_cid", "epik", "sccid"));

    private static boolean isTrackingParam(String name) {
        String n = name.toLowerCase();
        for (String p : TRACKING_PREFIXES) if (n.startsWith(p)) return true;
        return TRACKING_EXACT.contains(n);
    }

    private static String paramsCanon(String query) {
        if (query == null || query.isEmpty()) return "[]";
        java.util.TreeMap<String, String> first = new java.util.TreeMap<>();
        java.util.Set<String> multi = new java.util.HashSet<>();
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String k = eq >= 0 ? pair.substring(0, eq) : pair;
            String v = eq >= 0 ? pair.substring(eq + 1) : "";
            try {
                k = java.net.URLDecoder.decode(k, java.nio.charset.StandardCharsets.UTF_8);
                v = java.net.URLDecoder.decode(v, java.nio.charset.StandardCharsets.UTF_8);
            } catch (Exception ignored) { }
            if (isTrackingParam(k)) continue;
            if (first.containsKey(k)) multi.add(k); else first.put(k, v);
        }
        StringBuilder sb = new StringBuilder("[");
        boolean firstItem = true;
        for (var e : first.entrySet()) {
            if (!firstItem) sb.append(',');
            firstItem = false;
            sb.append("[\"").append(esc(e.getKey())).append("\",\"").append(kindOf(e.getValue()))
              .append("\",").append(multi.contains(e.getKey()) ? 1 : 0).append(']');
        }
        return sb.append(']').toString();
    }

    private final String token;
    private final String endpoint;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    private volatile String mode = "observe";
    private volatile boolean haveBaseline = false;
    private final Map<String, String> shapes = new ConcurrentHashMap<>();
    private final Map<String, Boolean> knownBad = new ConcurrentHashMap<>();

    public NemesisShield(String token) {
        this.token = token;
        this.endpoint = resolveEndpoint();
        if (token != null && !token.isEmpty()) {
            refresh();
            Thread t = new Thread(() -> {
                while (true) {
                    try { Thread.sleep(2000); refresh(); } catch (Exception ignored) {}
                }
            });
            t.setDaemon(true);
            t.start();
        }
    }

    /** The sketches endpoint. Defaults to the Nemesis Shield cloud; override with the NEMESIS_ENDPOINT
     *  env var (or -Dnemesis.endpoint=...) to point at a self-hosted / on-prem Shield or a local mock. */
    private static String resolveEndpoint() {
        String p = System.getProperty("nemesis.endpoint");
        if (p != null && !p.isEmpty()) return p;
        String e = System.getenv("NEMESIS_ENDPOINT");
        return (e != null && !e.isEmpty()) ? e : ENDPOINT;
    }

    public boolean enforcing() { return "enforce".equals(mode); }

    // Safe-unlock (break-glass): paths never blocked, so a still-learning baseline can't lock operators
    // out of the doors they need to fix it. Prefix-matched. Override with NEMESIS_SHIELD_BOOTSTRAP env.
    private static final String[] DEFAULT_BOOTSTRAP =
            {"/login", "/signin", "/sign-in", "/auth", "/oauth", "/session", "/wp-login.php", "/wp-admin"};

    private static String[] bootstrap() {
        String env = System.getenv("NEMESIS_SHIELD_BOOTSTRAP");
        if (env != null && !env.trim().isEmpty()) {
            java.util.List<String> out = new java.util.ArrayList<>();
            for (String p : env.split(",")) { p = p.trim(); if (!p.isEmpty()) out.add(p); }
            return out.toArray(new String[0]);
        }
        return DEFAULT_BOOTSTRAP;
    }

    /** Break-glass: is this path on the never-block bootstrap allow-list? Prefix match. */
    public static boolean neverBlock(String path) {
        if (path == null) return false;
        int q = path.indexOf('?'); if (q >= 0) path = path.substring(0, q);
        int h = path.indexOf('#'); if (h >= 0) path = path.substring(0, h);
        String p = path.toLowerCase();
        for (String b : bootstrap()) { if (!b.isEmpty() && p.startsWith(b.toLowerCase())) return true; }
        return false;
    }

    public static String normalizePath(String path) {
        if (path == null) return "/";
        int q = path.indexOf('?');
        if (q >= 0) path = path.substring(0, q);
        int h = path.indexOf('#');
        if (h >= 0) path = path.substring(0, h);
        String[] segs = path.split("/", -1);
        for (int i = 0; i < segs.length; i++) {
            if (segs[i].isEmpty()) continue;
            if (segs[i].contains("..")) { segs[i] = "{traversal}"; continue; } // keeps ".." out of telemetry
            switch (kindOf(segs[i])) {
                case "int": case "float": segs[i] = "{int}"; break;
                case "uuid": segs[i] = "{uuid}"; break;
                case "hex": segs[i] = "{hex}"; break;
                case "base64": segs[i] = "{token}"; break;
                case "alnum": if (segs[i].length() >= 12 && !WORD.matcher(segs[i]).find()) segs[i] = "{id}"; break;
            }
        }
        String out = String.join("/", segs);
        return out.isEmpty() ? "/" : out;
    }

    private static String fnv1a(String s) {
        int h = 0x811c9dc5;
        for (int i = 0; i < s.length(); i++) {
            h ^= (s.charAt(i) & 0xff);
            h *= 0x01000193;
        }
        return String.format("%08x", h & 0xffffffffL);
    }

    /** Request signature: method + normalized route + query-param shapes + auth (status excluded). */
    public String shapeOf(String method, String path, String query, boolean authed) {
        String route = normalizePath(path);
        // canonical shape input: keys SORTED (auth, method, params, route); status excluded by design.
        String canon = "{\"auth\":" + (authed ? 1 : 0) + ",\"method\":\"" + esc(method.toUpperCase())
                + "\",\"params\":" + paramsCanon(query) + ",\"route\":\"" + esc(route) + "\"}";
        return fnv1a(canon);
    }

    public String shapeOf(String method, String path, boolean authed) {
        return shapeOf(method, path, (String) null, authed);
    }

    /** Positive-security verdict for a shape. Returns the block reason, or null to allow. */
    public String decide(String shape) {
        String per = shapes.get(shape);
        if ("allow".equals(per)) return null;
        if ("block".equals(per)) return "policy: blocked shape";
        if (knownBad.containsKey(shape)) return "global threat intelligence";
        if (haveBaseline) return "off-baseline: unapproved behavior";
        return null;
    }

    private static String esc(String s) { return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\""); }

    private String sketchJson(String method, String path, String query, boolean authed, int status) {
        String route = normalizePath(path);
        return "{\"route\":\"" + esc(route) + "\",\"method\":\"" + esc(method.toUpperCase())
                + "\",\"authenticated\":" + authed + ",\"status\":" + status
                + ",\"params\":" + paramsCanon(query) + ",\"shape\":\"" + shapeOf(method, path, query, authed) + "\"}";
    }

    /** Record an observed request (fire-and-forget). */
    public void observe(String method, String path, String query, boolean authed, int status) {
        send("[" + sketchJson(method, path, query, authed, status) + "]");
    }

    public void observe(String method, String path, boolean authed, int status) {
        observe(method, path, null, authed, status);
    }

    private void refresh() { send("[]"); }

    private void send(String sketchesJson) {
        if (token == null || token.isEmpty()) return;
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(endpoint))
                    .header("Authorization", "Bearer " + token)
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(3))
                    .POST(HttpRequest.BodyPublishers.ofString("{\"sketches\":" + sketchesJson + "}"))
                    .build();
            HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() == 200) applyPolicy(res.body());
        } catch (Exception ignored) { /* fail open */ }
    }

    // Targeted parse of {"mode":"..","policy":{"shapes":{"h":"allow",..},"knownBad":[..]}}
    private void applyPolicy(String body) {
        Matcher m = Pattern.compile("\"mode\"\\s*:\\s*\"(\\w+)\"").matcher(body);
        if (m.find()) mode = m.group(1);
        int si = body.indexOf("\"shapes\"");
        if (si >= 0) {
            int open = body.indexOf('{', si);
            int close = open >= 0 ? body.indexOf('}', open) : -1;
            if (open >= 0 && close > open) {
                shapes.clear();
                Matcher pm = Pattern.compile("\"([0-9a-f]{8})\"\\s*:\\s*\"(allow|block)\"").matcher(body.substring(open, close));
                while (pm.find()) shapes.put(pm.group(1), pm.group(2));
                if (!shapes.isEmpty()) haveBaseline = true;
            }
        }
        int ki = body.indexOf("\"knownBad\"");
        if (ki >= 0) {
            int open = body.indexOf('[', ki);
            int close = open >= 0 ? body.indexOf(']', open) : -1;
            if (open >= 0 && close > open) {
                knownBad.clear();
                Matcher km = Pattern.compile("\"([0-9a-f]{8})\"").matcher(body.substring(open, close));
                while (km.find()) knownBad.put(km.group(1), true);
            }
        }
    }

    /**
     * Gate for a com.sun HttpServer / raw handler: if the request is off-baseline in enforce mode,
     * writes a 403 and returns true. Otherwise returns false (let the app handle it).
     */
    public boolean guard(String method, String path, boolean authed, com.sun.net.httpserver.HttpExchange ex) throws java.io.IOException {
        if (!enforcing() || neverBlock(path)) return false;
        String query = ex.getRequestURI().getRawQuery();
        String reason = decide(shapeOf(method, path, query, authed));
        if (reason == null) return false;
        observe(method, path, query, authed, 403);
        byte[] out = ("{\"error\":\"blocked_by_nemesis_shield\",\"reason\":\"" + esc(reason) + "\"}").getBytes();
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(403, out.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(out); }
        return true;
    }
}
