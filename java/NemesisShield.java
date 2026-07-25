// Nemesis Shield — Sentinel SDK for Java (native, JDK 11+, no dependencies). Learns your app's normal
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
    private static final Pattern INT = Pattern.compile("^\\d+$");
    private static final Pattern UUID = Pattern.compile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final Pattern HEX = Pattern.compile("(?i)^[0-9a-f]{16,}$");

    private final String token;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    private volatile String mode = "observe";
    private volatile boolean haveBaseline = false;
    private final Map<String, String> shapes = new ConcurrentHashMap<>();
    private final Map<String, Boolean> knownBad = new ConcurrentHashMap<>();

    public NemesisShield(String token) {
        this.token = token;
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

    public boolean enforcing() { return "enforce".equals(mode); }

    public static String normalizePath(String path) {
        if (path == null) return "/";
        int q = path.indexOf('?');
        if (q >= 0) path = path.substring(0, q);
        String[] segs = path.split("/", -1);
        for (int i = 0; i < segs.length; i++) {
            if (INT.matcher(segs[i]).matches()) segs[i] = "{int}";
            else if (UUID.matcher(segs[i]).matches()) segs[i] = "{uuid}";
            else if (HEX.matcher(segs[i]).matches()) segs[i] = "{hex}";
        }
        return String.join("/", segs);
    }

    private static String fnv1a(String s) {
        int h = 0x811c9dc5;
        for (int i = 0; i < s.length(); i++) {
            h ^= (s.charAt(i) & 0xff);
            h *= 0x01000193;
        }
        return String.format("%08x", h & 0xffffffffL);
    }

    /** Request signature: method + normalized route + auth (status excluded by design). */
    public String shapeOf(String method, String path, boolean authed) {
        String route = normalizePath(path);
        // canonical shape input: keys SORTED (auth, method, params, route); status excluded by design.
        String canon = "{\"auth\":" + (authed ? 1 : 0) + ",\"method\":\"" + method.toUpperCase()
                + "\",\"params\":[],\"route\":\"" + route + "\"}";
        return fnv1a(canon);
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

    private String sketchJson(String method, String path, boolean authed, int status) {
        String route = normalizePath(path);
        return "{\"route\":\"" + esc(route) + "\",\"method\":\"" + esc(method.toUpperCase())
                + "\",\"authenticated\":" + authed + ",\"status\":" + status
                + ",\"params\":[],\"shape\":\"" + shapeOf(method, path, authed) + "\"}";
    }

    /** Record an observed request (fire-and-forget). */
    public void observe(String method, String path, boolean authed, int status) {
        send("[" + sketchJson(method, path, authed, status) + "]");
    }

    private void refresh() { send("[]"); }

    private void send(String sketchesJson) {
        if (token == null || token.isEmpty()) return;
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(ENDPOINT))
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
        if (!enforcing()) return false;
        String reason = decide(shapeOf(method, path, authed));
        if (reason == null) return false;
        observe(method, path, authed, 403);
        byte[] out = ("{\"error\":\"blocked_by_nemesis_shield\",\"reason\":\"" + esc(reason) + "\"}").getBytes();
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(403, out.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(out); }
        return true;
    }
}
