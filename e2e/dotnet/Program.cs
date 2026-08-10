// E2E live round-trip for the .NET SDK. Computes the shape hash per fixed route via the SDK's own
// ShapeOf/NormalizePath, prints it, then POSTs the batch to the LIVE sketches endpoint.
using System.Text;
using NemesisShield;

var token = Environment.GetEnvironmentVariable("NEMESIS_TOKEN") ?? "";
var client = new SentinelClient(token);
var routes = new[]
{
    ("GET", "/app/incidents/inc_ip_1_2_3_4_1786400000000"),
    ("GET", "/app/network/autogon.ai"),
    ("GET", "/app/applications/f47ac10b-58cc-4372-a567-0e02b2c3d479"),
};

var items = new List<string>();
foreach (var (method, path) in routes)
{
    var route = SentinelClient.NormalizePath(path);
    var hash = client.ShapeOf(method, path, false);
    Console.WriteLine($"SHAPE {path} route={route} hash={hash}");
    items.Add($"{{\"route\":\"{route}\",\"method\":\"{method}\",\"authenticated\":false,\"status\":200,\"params\":[],\"shape\":\"{hash}\"}}");
}

var body = "{\"sketches\":[" + string.Join(",", items) + "]}";
using var http = new HttpClient();
using var req = new HttpRequestMessage(HttpMethod.Post, "https://shield.nemesislabs.xyz/api/v1/sketches")
{
    Content = new StringContent(body, Encoding.UTF8, "application/json")
};
req.Headers.Add("Authorization", "Bearer " + token);
var res = await http.SendAsync(req);
Console.WriteLine($"POST_STATUS {(int)res.StatusCode}");
