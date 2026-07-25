<?php
// LLM Guard for PHP — OWASP-LLM-Top-10 detection with the HashLR ML classifier shared across every
// Nemesis Shield SDK. Feature buckets are fnv1a(feature) % dim, identical to every other language.
// Char n-grams over a canonicalized (de-leetspeaked, ASCII-alnum) form catch obfuscation the regex
// layer misses.

final class NemesisShieldLLM
{
    private static ?array $model = null;
    private const LEET = ['0' => 'o', '1' => 'i', '3' => 'e', '4' => 'a', '5' => 's', '7' => 't', '@' => 'a', '$' => 's', '8' => 'b', '|' => 'i'];
    private const INJECTION = [
        '/ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts?|context)/i',
        '/disregard\s+(the\s+)?(above|previous|system)/i',
        '/(reveal|show|print|repeat)\s+(your|the)\s+(system\s+)?(prompt|instructions)/i',
        '/\bDAN\b|do\s+anything\s+now|developer\s+mode|jailbreak/i',
        '/(bypass|ignore|disable)\s+(your\s+)?(safety|content\s+policy|guardrails?)/i',
    ];

    private static function model(): array
    {
        if (self::$model === null) {
            self::$model = json_decode(file_get_contents(__DIR__ . '/ml_weights.json'), true);
        }
        return self::$model;
    }

    private static function fnv1a(string $s): int
    {
        $h = 0x811c9dc5;
        for ($i = 0, $n = strlen($s); $i < $n; $i++) {
            $h ^= ord($s[$i]);
            $h = ($h * 0x01000193) & 0xffffffff;
        }
        return $h;
    }

    private static function bucket(string $s, int $dim): int
    {
        return self::fnv1a($s) % $dim;
    }

    private static function canon(string $text): string
    {
        $t = strtr(strtolower($text), self::LEET);
        $out = '';
        for ($i = 0, $n = strlen($t); $i < $n; $i++) {
            $c = $t[$i];
            if (($c >= 'a' && $c <= 'z') || ($c >= '0' && $c <= '9')) {
                $out .= $c;
            }
        }
        return $out;
    }

    private static function features(string $text, int $dim): array
    {
        $b = [];
        preg_match_all("/[a-z0-9']+/", strtolower($text), $m);
        $ws = $m[0];
        foreach ($ws as $w) {
            $b[self::bucket("w:" . $w, $dim)] = true;
        }
        for ($i = 0, $k = count($ws); $i + 1 < $k; $i++) {
            $b[self::bucket("b:" . $ws[$i] . " " . $ws[$i + 1], $dim)] = true;
        }
        $c = self::canon($text);
        foreach ([3, 4, 5] as $n) {
            for ($i = 0, $L = strlen($c); $i + $n <= $L; $i++) {
                $b[self::bucket("c" . $n . ":" . substr($c, $i, $n), $dim)] = true;
            }
        }
        if (strlen($text) > 2000) {
            $b[self::bucket("e:long", $dim)] = true;
        }
        $na = 0;
        for ($i = 0, $n = strlen($text); $i < $n; $i++) {
            if (ord($text[$i]) > 127) {
                $na++;
            }
        }
        if ($na > 3) {
            $b[self::bucket("e:nonascii", $dim)] = true;
        }
        return $b;
    }

    /** Probability (0..1) that $text is a prompt-injection / jailbreak attempt. */
    public static function mlInjectionScore(string $text): float
    {
        $m = self::model();
        $z = $m['bias'];
        $w = $m['weights'];
        foreach (self::features($text, $m['dim']) as $bk => $_) {
            if (isset($w[(string)$bk])) {
                $z += $w[(string)$bk];
            }
        }
        if ($z < -30) return 0.0;
        if ($z > 30) return 1.0;
        return 1.0 / (1.0 + exp(-$z));
    }

    /** Returns ['blocked'=>bool,'severity'=>,'kind'=>,'score'=>,'owasp'=>]. Regex first, then ML. */
    public static function guardLLM(string $prompt, bool $enforce = false): array
    {
        foreach (self::INJECTION as $re) {
            if (preg_match($re, $prompt)) {
                return ['blocked' => $enforce, 'severity' => 'high', 'kind' => 'prompt_injection', 'score' => 1.0, 'owasp' => 'LLM01'];
            }
        }
        $m = self::model();
        $s = self::mlInjectionScore($prompt);
        if ($s >= ($m['blockThreshold'] ?? 0.85)) {
            return ['blocked' => $enforce, 'severity' => 'high', 'kind' => 'ml_prompt_injection', 'score' => $s, 'owasp' => 'LLM01'];
        }
        if ($s >= ($m['flagThreshold'] ?? 0.45)) {
            return ['blocked' => false, 'severity' => 'medium', 'kind' => 'ml_prompt_injection', 'score' => $s, 'owasp' => 'LLM01'];
        }
        return ['blocked' => false, 'severity' => 'none', 'score' => $s];
    }
}
