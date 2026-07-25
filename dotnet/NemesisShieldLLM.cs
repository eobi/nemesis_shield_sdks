// LLM Guard for .NET / C# — OWASP-LLM-Top-10 detection with the HashLR ML classifier shared across
// every Nemesis Shield SDK. Feature buckets are fnv1a(feature) % dim, identical to every other
// language; char n-grams over a canonicalized (de-leetspeaked, ASCII-alnum) form catch obfuscation
// the regex layer misses. Weights load from ml_weights.json (cwd or beside the assembly).
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NemesisShield;

public static class LlmGuard
{
    private static readonly int Dim;
    private static readonly double Bias, Block, Flag;
    private static readonly Dictionary<int, double> Weights = new();
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
        using var doc = JsonDocument.Parse(LoadWeights());
        var r = doc.RootElement;
        Dim = r.GetProperty("dim").GetInt32();
        Bias = r.GetProperty("bias").GetDouble();
        Block = r.TryGetProperty("blockThreshold", out var b) ? b.GetDouble() : 0.85;
        Flag = r.TryGetProperty("flagThreshold", out var f) ? f.GetDouble() : 0.45;
        foreach (var w in r.GetProperty("weights").EnumerateObject())
            Weights[int.Parse(w.Name)] = w.Value.GetDouble();
    }

    private static string LoadWeights()
    {
        foreach (var p in new[] { "ml_weights.json", Path.Combine(AppContext.BaseDirectory, "ml_weights.json") })
            if (File.Exists(p)) return File.ReadAllText(p);
        return "{\"dim\":8192,\"bias\":0,\"weights\":{}}";
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
