// Nemesis Shield — Sentinel client for Java (JDK 11+, no dependencies).
//
//   NemesisShield nemesis = new NemesisShield(System.getenv("NEMESIS_TOKEN"));
//   // after each response, in a filter/interceptor:
//   nemesis.report(request.getMethod(), request.getRequestURI(), response.getStatus(), authed);
//
// Ships only privacy-preserving metadata (method, path shape, status, authenticated?). Never ships
// request bodies. Fire-and-forget; a Nemesis outage never affects your app.

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.regex.Pattern;

public class NemesisShield {
    private static final String OBSERVE_URL = "https://shield.nemesislabs.xyz/api/v1/observe";
    private static final Pattern INT = Pattern.compile("^\\d+$");
    private static final Pattern UUID = Pattern.compile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final Pattern HEX = Pattern.compile("(?i)^[0-9a-f]{16,}$");

    private final String token;
    private final String endpoint;
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();

    public NemesisShield(String token) { this(token, OBSERVE_URL); }
    public NemesisShield(String token, String endpoint) { this.token = token; this.endpoint = endpoint; }

    /** Collapse IDs so the baseline doesn't explode: /orders/123 -> /orders/{int} */
    public static String pathShape(String path) {
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

    private static String esc(String s) { return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\""); }

    /** Fire-and-forget report of a single request. Never throws. */
    public void report(String method, String path, int status, boolean authenticated) {
        if (token == null || token.isEmpty()) return;
        String body = String.format(
            "{\"events\":[{\"method\":\"%s\",\"path\":\"%s\",\"status\":%d,\"authenticated\":%b}]}",
            esc(method), esc(pathShape(path)), status, authenticated);
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(endpoint))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(2))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
            client.sendAsync(req, HttpResponse.BodyHandlers.discarding()); // async; ignore result
        } catch (Exception ignored) {
            // fail open
        }
    }
}
