// Deep coverage test for the .NET SDK core - proves it SEES an attacker's request from ANY route and
// blocks it in enforce mode (unknown paths, injected/extra params, param-kind / method / auth
// anomalies, knownBad), plus the safe-unlock and fail-open. Mirrors the middleware's block logic.
// Run:  dotnet run --project deeptest
using System.Collections.Concurrent;
using System.Reflection;
using NemesisShield;

int pass = 0, fail = 0;
void Ok(bool c, string m)
{
    if (c) { pass++; Console.WriteLine("  [32m✓[0m " + m); }
    else { fail++; Console.WriteLine("  [31m✗ " + m + "[0m"); }
}

var T = typeof(SentinelClient);
SentinelClient Client(string mode, string[] allow, string[] knownBad)
{
    var c = new SentinelClient(""); // empty token -> no poller, no network
    T.GetField("_mode", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(c, mode);
    var shapes = (ConcurrentDictionary<string, string>)T.GetField("_shapes", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(c)!;
    foreach (var s in allow) shapes[s] = "allow";
    var kb = (ConcurrentDictionary<string, bool>)T.GetField("_knownBad", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(c)!;
    foreach (var s in knownBad) kb[s] = true;
    T.GetField("_baseline", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(c, allow.Length > 0 || knownBad.Length > 0);
    return c;
}

(string path, string? query) Split(string url)
{
    var i = url.IndexOf('?');
    return i < 0 ? (url, null) : (url[..i], url[(i + 1)..]);
}
string Shape(SentinelClient c, string method, string url, bool authed)
{
    var (p, q) = Split(url);
    return c.ShapeOf(method, p, q, authed);
}
// exactly the middleware's decision: enforce AND not a bootstrap path AND off-baseline
bool Blocked(SentinelClient c, string method, string url, bool authed)
{
    var (p, q) = Split(url);
    if (!c.Enforcing || SentinelClient.NeverBlock(p)) return false;
    return c.Decide(c.ShapeOf(method, p, q, authed)) != null;
}

var reff = new SentinelClient("");
string[] allow =
{
    Shape(reff, "GET", "/", false),
    Shape(reff, "GET", "/products/12345", false),
    Shape(reff, "GET", "/search?q=shoes", false),
    Shape(reff, "POST", "/api/orders", true),
};

Console.WriteLine("[1mNemesis Shield - .NET deep coverage test[0m");

Console.WriteLine("\n1 · query params change the shape");
Ok(Shape(reff, "GET", "/search?q=x", false) != Shape(reff, "GET", "/search?q=x&inject=1", false), "adding a param changes the shape");
Ok(Shape(reff, "GET", "/search?q=shoes", false) != Shape(reff, "GET", "/search?q=' OR 1=1", false), "param kind change changes the shape");

Console.WriteLine("\n2 · enforce - attacks from ANY route blocked, approved passes");
var c = Client("enforce", allow, Array.Empty<string>());
Ok(!Blocked(c, "GET", "/", false), "approved GET / passes");
Ok(!Blocked(c, "GET", "/products/999", false), "approved GET /products/{int} passes");
Ok(!Blocked(c, "GET", "/search?q=boots", false), "approved GET /search?q=<alnum> passes");
Ok(!Blocked(c, "POST", "/api/orders", true), "approved authed POST passes");
Ok(Blocked(c, "GET", "/.env", false), "scanner /.env blocked");
Ok(Blocked(c, "GET", "/wp-config.php.bak", false), "scanner /wp-config.php.bak blocked");
Ok(Blocked(c, "GET", "/search?q=x&cmd=id", false), "injected param blocked");
Ok(Blocked(c, "GET", "/search?q=' OR 1=1--", false), "SQLi-shaped param blocked");
Ok(Blocked(c, "POST", "/", false), "method anomaly POST / blocked");
Ok(Blocked(c, "GET", "/api/orders", false), "auth anomaly (unauth) blocked");
Ok(Blocked(c, "GET", "/admin/config", false), "unknown /admin/config blocked");

Console.WriteLine("\n3 · knownBad (global threat intel)");
var bad = Shape(reff, "POST", "/xmlrpc.php", false);
Ok(Blocked(Client("enforce", allow, new[] { bad }), "POST", "/xmlrpc.php", false), "knownBad shape blocked");

Console.WriteLine("\n4 · safe-unlock - auth path never blocked");
Ok(!Blocked(c, "POST", "/login?next=x", false), "/login never blocked");
Ok(!Blocked(c, "GET", "/wp-login.php", false), "/wp-login.php never blocked");
Ok(!Blocked(c, "GET", "/wp-admin/options.php", false), "/wp-admin never blocked");

Console.WriteLine("\n5 · fail-open + observe");
Ok(!Blocked(Client("enforce", Array.Empty<string>(), Array.Empty<string>()), "GET", "/.env", false), "fail-open with no baseline");
Ok(!Blocked(Client("observe", allow, Array.Empty<string>()), "GET", "/.env", false), "observe mode never blocks");

Console.WriteLine("\n" + new string('-', 52));
if (fail == 0) Console.WriteLine($"[32m[1mALL {pass} CHECKS PASSED[0m");
else { Console.WriteLine($"[31m[1m{fail} FAILED[0m, {pass} passed"); Environment.Exit(1); }
