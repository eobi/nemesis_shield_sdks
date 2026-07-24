// Nemesis Shield — Sentinel SDK for .NET / C# (native: local shape + policy cache + inline blocking).
// Learns your app's normal behavior; in enforce mode blocks off-baseline requests (auth bypass, path
// traversal, scanners, unusual methods) before your endpoints run. Positive-security, fail-open.
//
//   // Program.cs (ASP.NET Core):
//   app.UseMiddleware<NemesisShield.SentinelMiddleware>();
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NemesisShield;

public sealed class SentinelClient
{
    private const string Endpoint = "https://shield.nemesislabs.xyz/api/v1/sketches";
    private static readonly Regex Int = new("^\\d+$", RegexOptions.Compiled);
    private static readonly Regex Uuid = new("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex Hex = new("^[0-9a-f]{16,}$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly string _token;
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(3) };
    private volatile string _mode = "observe";
    private volatile bool _baseline = false;
    private volatile ConcurrentDictionary<string, string> _shapes = new();
    private volatile ConcurrentDictionary<string, bool> _knownBad = new();

    public SentinelClient(string token)
    {
        _token = token ?? "";
        if (!string.IsNullOrEmpty(_token))
        {
            Refresh().GetAwaiter().GetResult();
            _ = Task.Run(async () => { while (true) { await Task.Delay(2000); await Refresh(); } });
        }
    }

    public bool Enforcing => _mode == "enforce";

    public static string NormalizePath(string path)
    {
        var q = path.IndexOf('?');
        if (q >= 0) path = path[..q];
        var segs = path.Split('/');
        for (var i = 0; i < segs.Length; i++)
        {
            if (Int.IsMatch(segs[i])) segs[i] = "{int}";
            else if (Uuid.IsMatch(segs[i])) segs[i] = "{uuid}";
            else if (Hex.IsMatch(segs[i])) segs[i] = "{hex}";
        }
        return string.Join("/", segs);
    }

    private static string Fnv1a(string s)
    {
        uint h = 0x811c9dc5;
        foreach (var c in s) { h ^= (byte)c; h *= 0x01000193; }
        return h.ToString("x8");
    }

    // Request signature: method + normalized route + auth (excludes status by design).
    public string ShapeOf(string method, string path, bool authed)
    {
        var route = NormalizePath(path);
        var canon = $"{{\"route\":\"{route}\",\"method\":\"{method.ToUpperInvariant()}\",\"params\":[],\"auth\":{(authed ? 1 : 0)}}}";
        return Fnv1a(canon);
    }

    // Positive-security verdict: returns the block reason, or null to allow.
    public string? Decide(string shape)
    {
        if (_shapes.TryGetValue(shape, out var per))
        {
            if (per == "allow") return null;
            if (per == "block") return "policy: blocked shape";
        }
        if (_knownBad.ContainsKey(shape)) return "global threat intelligence";
        if (_baseline) return "off-baseline: unapproved behavior";
        return null;
    }

    public void Observe(string method, string path, bool authed, int status)
    {
        var route = NormalizePath(path);
        var sk = $"{{\"route\":\"{route}\",\"method\":\"{method.ToUpperInvariant()}\",\"authenticated\":{authed.ToString().ToLowerInvariant()},\"status\":{status},\"params\":[],\"shape\":\"{ShapeOf(method, path, authed)}\"}}";
        _ = Send("[" + sk + "]");
    }

    private Task Refresh() => Send("[]");

    private async Task Send(string sketchesJson)
    {
        if (string.IsNullOrEmpty(_token)) return;
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, Endpoint)
            { Content = new StringContent("{\"sketches\":" + sketchesJson + "}", Encoding.UTF8, "application/json") };
            req.Headers.Add("Authorization", "Bearer " + _token);
            var res = await _http.SendAsync(req);
            if (res.IsSuccessStatusCode) ApplyPolicy(await res.Content.ReadAsStringAsync());
        }
        catch { /* fail open */ }
    }

    private void ApplyPolicy(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (root.TryGetProperty("mode", out var m) && m.ValueKind == JsonValueKind.String) _mode = m.GetString()!;
            if (root.TryGetProperty("policy", out var pol))
            {
                if (pol.TryGetProperty("shapes", out var shapes) && shapes.ValueKind == JsonValueKind.Object)
                {
                    var next = new ConcurrentDictionary<string, string>();
                    foreach (var p in shapes.EnumerateObject()) next[p.Name] = p.Value.GetString() ?? "allow";
                    _shapes = next;
                    _baseline = !next.IsEmpty;
                }
                if (pol.TryGetProperty("knownBad", out var kb) && kb.ValueKind == JsonValueKind.Array)
                {
                    var next = new ConcurrentDictionary<string, bool>();
                    foreach (var s in kb.EnumerateArray()) next[s.GetString() ?? ""] = true;
                    _knownBad = next;
                }
            }
        }
        catch { /* ignore */ }
    }
}

// ASP.NET Core middleware. Register: app.UseMiddleware<NemesisShield.SentinelMiddleware>();
public sealed class SentinelMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SentinelClient _client;

    public SentinelMiddleware(RequestDelegate next)
    {
        _next = next;
        _client = new SentinelClient(Environment.GetEnvironmentVariable("NEMESIS_TOKEN") ?? "");
    }

    public async Task Invoke(HttpContext ctx)
    {
        var method = ctx.Request.Method;
        var path = ctx.Request.Path.HasValue ? ctx.Request.Path.Value! : "/";
        var authed = ctx.Request.Headers.ContainsKey("Authorization") || ctx.Request.Headers.ContainsKey("Cookie");
        if (_client.Enforcing)
        {
            var reason = _client.Decide(_client.ShapeOf(method, path, authed));
            if (reason != null)
            {
                _client.Observe(method, path, authed, 403);
                ctx.Response.StatusCode = 403;
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync(JsonSerializer.Serialize(new { error = "blocked_by_nemesis_shield", reason }));
                return;
            }
        }
        await _next(ctx);
        _client.Observe(method, path, authed, ctx.Response.StatusCode);
    }
}
