// E2E live round-trip for the Java SDK. Computes the shape hash per fixed route via the SDK's own
// shapeOf/normalizePath, prints it, then POSTs the batch to the LIVE sketches endpoint.
import io.github.eobi.sentinel.NemesisShield;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class RoundTrip {
    public static void main(String[] args) throws Exception {
        String token = System.getenv("NEMESIS_TOKEN");
        if (token == null) token = "";
        NemesisShield s = new NemesisShield(token);
        String[][] routes = {
            {"GET", "/app/incidents/inc_ip_1_2_3_4_1786400000000"},
            {"GET", "/app/network/autogon.ai"},
            {"GET", "/app/applications/f47ac10b-58cc-4372-a567-0e02b2c3d479"},
        };
        StringBuilder arr = new StringBuilder("[");
        for (int i = 0; i < routes.length; i++) {
            String route = NemesisShield.normalizePath(routes[i][1]);
            String hash = s.shapeOf(routes[i][0], routes[i][1], false);
            System.out.println("SHAPE " + routes[i][1] + " route=" + route + " hash=" + hash);
            if (i > 0) arr.append(",");
            arr.append("{\"route\":\"").append(route).append("\",\"method\":\"").append(routes[i][0])
               .append("\",\"authenticated\":false,\"status\":200,\"params\":[],\"shape\":\"")
               .append(hash).append("\"}");
        }
        arr.append("]");
        String body = "{\"sketches\":" + arr + "}";
        HttpClient h = HttpClient.newHttpClient();
        HttpRequest req = HttpRequest.newBuilder(URI.create("https://shield.nemesislabs.xyz/api/v1/sketches"))
            .header("Authorization", "Bearer " + token)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
        HttpResponse<String> res = h.send(req, HttpResponse.BodyHandlers.ofString());
        System.out.println("POST_STATUS " + res.statusCode());
    }
}
