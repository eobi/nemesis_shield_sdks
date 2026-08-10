// Canonical path-tokenizer parity harness for the .NET SDK.
// Reads the cross-SDK source of truth (tokenize.vectors.json, key "normalizePath") and asserts
// NemesisShield.SentinelClient.NormalizePath(path) == expect for every vector. Byte-parity gate.
// Run:  dotnet run --project tokenizetest
using System.Text.Json;
using NemesisShield;

// Resolve the vectors file relative to this source directory, with an env override for CI.
string vectorsPath =
    Environment.GetEnvironmentVariable("NEMESIS_TOKENIZE_VECTORS")
    ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "tokenize.vectors.json"));

if (!File.Exists(vectorsPath))
{
    Console.Error.WriteLine($"vectors file not found: {vectorsPath}");
    Environment.Exit(2);
}

using var doc = JsonDocument.Parse(File.ReadAllText(vectorsPath));
var cases = doc.RootElement.GetProperty("normalizePath");

int pass = 0, fail = 0;
Console.WriteLine("[1mNemesis Shield - .NET tokenizer parity (normalizePath)[0m");
foreach (var t in cases.EnumerateArray())
{
    var path = t.GetProperty("path").GetString()!;
    var expect = t.GetProperty("expect").GetString()!;
    var got = SentinelClient.NormalizePath(path);
    if (got == expect)
    {
        pass++;
        Console.WriteLine($"  [32m✓[0m {path} -> {got}");
    }
    else
    {
        fail++;
        Console.WriteLine($"  [31m✗ {path}  expected [{expect}]  got [{got}][0m");
    }
}

Console.WriteLine(new string('-', 52));
int total = pass + fail;
if (fail == 0) Console.WriteLine($"[32m[1m{pass}/{total} PASSED[0m");
else { Console.WriteLine($"[31m[1m{fail} FAILED[0m, {pass}/{total} passed"); Environment.Exit(1); }
