// LLM Guard for .NET / C# - OWASP-LLM-Top-10 detection with the HashLR ML classifier shared across
// every Nemesis Shield SDK. Feature buckets are fnv1a(feature) % dim, identical to every other
// language; char n-grams over a canonicalized (de-leetspeaked, ASCII-alnum) form catch obfuscation
// the regex layer misses. Weights load from ml_weights.json (cwd or beside the assembly).
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NemesisShield;

public static class LlmGuard
{
    // Feature space (Dim) is fixed across versions; the rest is swappable so RefreshModel() can hot-swap
    // a newer published version in place.
    private static int Dim;
    private static double Bias, Block, Flag;
    private static int Version = 1;
    private static readonly Dictionary<int, double> Weights = new();
    // Ed25519 public key (hex) that signs published models. Cloud pulls MUST carry a valid signature
    // over the exact bytes; unsigned or tampered bundles are rejected and the embedded model is kept.
    private const string ModelPublicKeyHex = "79d81a3b41966b379a9ba719155b8713f70bb341c3e8fab09fd5563a59893d28";
    private static readonly Regex Word = new("[a-z0-9']+", RegexOptions.Compiled);
    private static readonly Regex[] Injection =
    {
        new("ignore\\s+(all\\s+)?(previous|prior|above)\\s+(instructions|prompts?|context)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new("disregard\\s+(the\\s+)?(above|previous|system)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new("(reveal|show|print|repeat)\\s+(your|the)\\s+(system\\s+)?(prompt|instructions)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new("\\bDAN\\b|do\\s+anything\\s+now|developer\\s+mode|jailbreak", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new("(bypass|ignore|disable)\\s+(your\\s+)?(safety|content\\s+policy|guardrails?)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
    };

    static LlmGuard()
    {
        ApplyModel(LoadWeights(), true);
    }

    // Parse a HashLR bundle and load it into the live model state. When init==true Dim is set (embedded
    // load); on a refresh Dim is fixed and enforced by the caller.
    private static void ApplyModel(string json, bool init)
    {
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        if (init) Dim = r.GetProperty("dim").GetInt32();
        Bias = r.GetProperty("bias").GetDouble();
        Block = r.TryGetProperty("blockThreshold", out var b) ? b.GetDouble() : 0.85;
        Flag = r.TryGetProperty("flagThreshold", out var f) ? f.GetDouble() : 0.45;
        Version = r.TryGetProperty("version", out var v) ? v.GetInt32() : Version;
        Weights.Clear();
        foreach (var w in r.GetProperty("weights").EnumerateObject())
            Weights[int.Parse(w.Name)] = w.Value.GetDouble();
    }

    public static int ModelVersion() => Version;

    private static bool VerifyModelSignature(byte[] raw, string? sigB64)
    {
        if (ModelPublicKeyHex.Length == 0) return true;          // no key pinned - version gate + HTTPS apply
        if (string.IsNullOrEmpty(sigB64)) return false;          // key pinned but bundle unsigned - reject
        try
        {
            byte[] key = FromHex(ModelPublicKeyHex);
            byte[] sig = Convert.FromBase64String(sigB64);
            var verifier = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
            verifier.Init(false, new Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters(key, 0));
            verifier.BlockUpdate(raw, 0, raw.Length);
            return verifier.VerifySignature(sig);
        }
        catch { return false; }
    }

    /// <summary>
    /// Hot-swap the HashLR model from a cloud URL if a newer signed version is published, so the model
    /// can be retrained and pushed centrally without redeploying the SDK. Returns the new version number
    /// if updated, else null. Fail-safe: on any error the current (embedded) model is kept.
    /// URL defaults to env NEMESIS_MODEL_URL.
    /// </summary>
    public static int? RefreshModel(string? url = null)
    {
        url ??= Environment.GetEnvironmentVariable("NEMESIS_MODEL_URL");
        if (string.IsNullOrEmpty(url)) return null;
        try
        {
            using var http = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            var resp = http.GetAsync(url).GetAwaiter().GetResult();
            if (!resp.IsSuccessStatusCode) return null;
            byte[] raw = resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
            resp.Headers.TryGetValues("X-Model-Signature", out var sigVals);
            string? sig = sigVals is null ? null : System.Linq.Enumerable.FirstOrDefault(sigVals);
            if (!VerifyModelSignature(raw, sig)) return null; // integrity gate
            string json = System.Text.Encoding.UTF8.GetString(raw);
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            int newVer = r.TryGetProperty("version", out var v) ? v.GetInt32() : 0;
            int newDim = r.TryGetProperty("dim", out var d) ? d.GetInt32() : Dim;
            if (newVer <= Version || newDim != Dim) return null; // version / dim gate
            ApplyModel(json, false);
            return Version;
        }
        catch { return null; }
    }

    private static string LoadWeights()
    {
        // 1) embedded resource - the trained model shipped inside the NuGet package (bank/air-gapped safe)
        try
        {
            var asm = typeof(LlmGuard).Assembly;
            foreach (var n in asm.GetManifestResourceNames())
                if (n.EndsWith("ml_weights.json", StringComparison.Ordinal))
                {
                    using var s = asm.GetManifestResourceStream(n);
                    if (s != null) { using var r = new StreamReader(s); return r.ReadToEnd(); }
                }
        }
        catch { /* fall through to disk */ }
        // 2) disk - dev / source-drop / hot-swap beside the assembly
        foreach (var p in new[] { "ml_weights.json", Path.Combine(AppContext.BaseDirectory, "ml_weights.json") })
            if (File.Exists(p)) return File.ReadAllText(p);
        return "{\"dim\":8192,\"bias\":0,\"weights\":{}}";
    }

    // portable hex decode (Convert.FromHexString is net5+; this keeps netstandard2.0 working)
    private static byte[] FromHex(string hex)
    {
        var b = new byte[hex.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = System.Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return b;
    }

    private static uint Fnv1a(string s)
    {
        uint h = 0x811c9dc5;
        foreach (char c in s) { h ^= (byte)c; h *= 0x01000193; }
        return h;
    }

    private static int Bucket(string s) => (int)(Fnv1a(s) % (uint)Dim);

    private static char Leet(char c) => c switch
    {
        '0' => 'o', '1' => 'i', '3' => 'e', '4' => 'a', '5' => 's',
        '7' => 't', '@' => 'a', '$' => 's', '8' => 'b', '|' => 'i', _ => c
    };

    private static string Canon(string text)
    {
        var sb = new StringBuilder();
        foreach (char raw in text.ToLowerInvariant())
        {
            char c = Leet(raw);
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) sb.Append(c);
        }
        return sb.ToString();
    }

    private static HashSet<int> Features(string text)
    {
        var b = new HashSet<int>();
        var ws = new List<string>();
        foreach (Match m in Word.Matches(text.ToLowerInvariant())) ws.Add(m.Value);
        foreach (var w in ws) b.Add(Bucket("w:" + w));
        for (int i = 0; i + 1 < ws.Count; i++) b.Add(Bucket("b:" + ws[i] + " " + ws[i + 1]));
        var c = Canon(text);
        foreach (var n in new[] { 3, 4, 5 })
            for (int i = 0; i + n <= c.Length; i++) b.Add(Bucket("c" + n + ":" + c.Substring(i, n)));
        if (text.Length > 2000) b.Add(Bucket("e:long"));
        int na = 0;
        foreach (char ch in text) if (ch > 127) na++;
        if (na > 3) b.Add(Bucket("e:nonascii"));
        return b;
    }

    /// <summary>Probability (0..1) that <paramref name="text"/> is a prompt-injection / jailbreak attempt.</summary>
    public static double MlInjectionScore(string text)
    {
        double z = Bias;
        foreach (int bk in Features(text)) if (Weights.TryGetValue(bk, out var w)) z += w;
        if (z < -30) return 0;
        if (z > 30) return 1;
        return 1.0 / (1.0 + Math.Exp(-z));
    }

    public sealed record Verdict(bool Blocked, string Severity, string Kind, double Score, string Owasp);

    /// <summary>Regex rules first, then HashLR ML for obfuscation. <paramref name="enforce"/> gates blocking.</summary>
    public static Verdict GuardLLM(string prompt, bool enforce = false)
    {
        foreach (var re in Injection)
            if (re.IsMatch(prompt))
                return new Verdict(enforce, "high", "prompt_injection", 1.0, "LLM01");
        double s = MlInjectionScore(prompt);
        if (s >= Block) return new Verdict(enforce, "high", "ml_prompt_injection", s, "LLM01");
        if (s >= Flag) return new Verdict(false, "medium", "ml_prompt_injection", s, "LLM01");
        return new Verdict(false, "none", "", s, "");
    }
}
