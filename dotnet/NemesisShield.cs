// Nemesis Shield — Sentinel SDK for .NET / C# (native: local shape + policy cache + inline blocking).
// Learns your app's normal behavior; in enforce mode blocks off-baseline requests (auth bypass, path
// traversal, scanners, unusual methods) before your endpoints run. Positive-security, fail-open.
//
//   // Program.cs (ASP.NET Core):
//   app.UseMiddleware<NemesisShield.SentinelMiddleware>();
using System.Collections.Concurrent;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;

namespace NemesisShield;

public sealed class SentinelClient
{
    // Sketches endpoint. Defaults to the Nemesis Shield cloud; override with the NEMESIS_ENDPOINT env
    // var to point at a self-hosted / on-prem Shield or a local mock (bank / air-gapped deployments).
    private static readonly string Endpoint =
        Environment.GetEnvironmentVariable("NEMESIS_ENDPOINT") is { Length: > 0 } e
            ? e : "https://shield.nemesislabs.xyz/api/v1/sketches";
    // Canonical value taxonomy — matches the shared engine (tokenize.ts) byte-for-byte.
    private static readonly Regex Int = new("^-?\\d+$", RegexOptions.Compiled);
    private static readonly Regex Float = new("^-?\\d*\\.\\d+$", RegexOptions.Compiled);
    private static readonly Regex Uuid = new("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex Email = new(@"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.Compiled);
    private static readonly Regex Url = new(@"^https?://\S+$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex Ipv4 = new(@"^(\d{1,3}\.){3}\d{1,3}$", RegexOptions.Compiled);
    private static readonly Regex Ipv6 = new("^[0-9a-f:]+:[0-9a-f:]+$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex DateRe = new(@"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?", RegexOptions.Compiled);
    private static readonly Regex Jwt = new(@"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", RegexOptions.Compiled);
    private static readonly Regex Hex = new("^[0-9a-f]+$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex B64 = new(@"^[A-Za-z0-9+/]+={0,2}$", RegexOptions.Compiled);
    private static readonly Regex Alpha = new("^[A-Za-z]+$", RegexOptions.Compiled);
    private static readonly Regex Alnum = new("^[A-Za-z0-9]+$", RegexOptions.Compiled);

    internal static string KindOf(string s)
    {
        if (string.IsNullOrEmpty(s)) return "empty";
        if (Uuid.IsMatch(s)) return "uuid";
        if (Email.IsMatch(s)) return "email";
        if (Url.IsMatch(s)) return "url";
        if (Ipv4.IsMatch(s)) return "ipv4";
        if (Ipv6.IsMatch(s)) return "ipv6";
        if (Jwt.IsMatch(s)) return "jwt";
        if (DateRe.IsMatch(s)) return "date";
        if (Int.IsMatch(s)) return "int";
        if (Float.IsMatch(s)) return "float";
        if (s.Length >= 16 && Hex.IsMatch(s)) return "hex";
        if (s.Length >= 16 && B64.IsMatch(s)) return "base64";
        if (Alpha.IsMatch(s)) return "alpha";
        if (Alnum.IsMatch(s)) return "alnum";
        return "string";
    }

    private static string Esc(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");

    // Parse a raw query string into the canonical params array [[name,kind,nested],...], sorted +
    // deduped by name (repeated key -> nested). Values are classified, never kept.
    private static string ParamsCanon(string? query)
    {
        if (string.IsNullOrEmpty(query)) return "[]";
        var first = new System.Collections.Generic.Dictionary<string, string>();
        var order = new System.Collections.Generic.List<string>();
        var multi = new System.Collections.Generic.HashSet<string>();
        foreach (var pair in query.Split('&'))
        {
            if (pair.Length == 0) continue;
            var eq = pair.IndexOf('=');
            var k = eq >= 0 ? pair.Substring(0, eq) : pair;
            var v = eq >= 0 ? pair.Substring(eq + 1) : "";
            k = System.Uri.UnescapeDataString(k);
            v = System.Uri.UnescapeDataString(v);
            if (first.ContainsKey(k)) multi.Add(k);
            else { first[k] = v; order.Add(k); }
        }
        order.Sort(System.StringComparer.Ordinal);
        var parts = new System.Collections.Generic.List<string>();
        foreach (var k in order)
            parts.Add("[\"" + Esc(k) + "\",\"" + KindOf(first[k]) + "\"," + (multi.Contains(k) ? 1 : 0) + "]");
        return "[" + string.Join(",", parts) + "]";
    }

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

    // Safe-unlock (break-glass): paths never blocked, so a still-learning baseline can't lock operators
    // out of the doors they need to fix it. Prefix-matched. Override with NEMESIS_SHIELD_BOOTSTRAP env.
    private static readonly string[] DefaultBootstrap =
        { "/login", "/signin", "/sign-in", "/auth", "/oauth", "/session", "/wp-login.php", "/wp-admin" };

    private static string[] Bootstrap()
    {
        var env = Environment.GetEnvironmentVariable("NEMESIS_SHIELD_BOOTSTRAP");
        if (!string.IsNullOrWhiteSpace(env))
            return env.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).ToArray();
        return DefaultBootstrap;
    }

    /// <summary>Break-glass: is this path on the never-block bootstrap allow-list? Prefix match.</summary>
    public static bool NeverBlock(string path)
    {
        var q = path.IndexOf('?'); if (q >= 0) path = path[..q];
        var h = path.IndexOf('#'); if (h >= 0) path = path[..h];
        var p = path.ToLowerInvariant();
        foreach (var b in Bootstrap())
            if (b.Length > 0 && p.StartsWith(b.ToLowerInvariant())) return true;
        return false;
    }

    public static string NormalizePath(string path)
    {
        var q = path.IndexOf('?');
        if (q >= 0) path = path[..q];
        var h = path.IndexOf('#');
        if (h >= 0) path = path[..h];
        var segs = path.Split('/');
        for (var i = 0; i < segs.Length; i++)
        {
            if (segs[i].Length == 0) continue;
            if (segs[i].Contains("..")) { segs[i] = "{traversal}"; continue; } // keeps ".." out of telemetry
            switch (KindOf(segs[i]))
            {
                case "int": case "float": segs[i] = "{int}"; break;
                case "uuid": segs[i] = "{uuid}"; break;
                case "hex": segs[i] = "{hex}"; break;
                case "base64": segs[i] = "{token}"; break;
                case "alnum": if (segs[i].Length >= 12) segs[i] = "{id}"; break;
            }
        }
        var outp = string.Join("/", segs);
        return outp.Length == 0 ? "/" : outp;
    }

    private static string Fnv1a(string s)
    {
        uint h = 0x811c9dc5;
        foreach (var c in s) { h ^= (byte)c; h *= 0x01000193; }
        return h.ToString("x8");
    }

    // Request signature: method + normalized route + auth (excludes status by design).
    public string ShapeOf(string method, string path, bool authed) => ShapeOf(method, path, null, authed);

    public string ShapeOf(string method, string path, string? query, bool authed)
    {
        var route = NormalizePath(path);
        // canonical shape input: keys SORTED (auth, method, params, route); status excluded by design.
        var canon = $"{{\"auth\":{(authed ? 1 : 0)},\"method\":\"{Esc(method.ToUpperInvariant())}\",\"params\":{ParamsCanon(query)},\"route\":\"{Esc(route)}\"}}";
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

    public void Observe(string method, string path, bool authed, int status) => Observe(method, path, null, authed, status);

    public void Observe(string method, string path, string? query, bool authed, int status)
    {
        var route = NormalizePath(path);
        var sk = $"{{\"route\":\"{Esc(route)}\",\"method\":\"{Esc(method.ToUpperInvariant())}\",\"authenticated\":{authed.ToString().ToLowerInvariant()},\"status\":{status},\"params\":{ParamsCanon(query)},\"shape\":\"{ShapeOf(method, path, query, authed)}\"}}";
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
        var query = ctx.Request.QueryString.HasValue ? ctx.Request.QueryString.Value!.TrimStart('?') : null;
        var authed = ctx.Request.Headers.ContainsKey("Authorization") || ctx.Request.Headers.ContainsKey("Cookie") || ctx.Request.Headers.ContainsKey("X-Api-Key");
        if (_client.Enforcing && !SentinelClient.NeverBlock(path))
        {
            var reason = _client.Decide(_client.ShapeOf(method, path, query, authed));
            if (reason != null)
            {
                _client.Observe(method, path, query, authed, 403);
                ctx.Response.StatusCode = 403;
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync(JsonSerializer.Serialize(new { error = "blocked_by_nemesis_shield", reason }));
                return;
            }
        }
        await _next(ctx);
        _client.Observe(method, path, query, authed, ctx.Response.StatusCode);
    }
}
