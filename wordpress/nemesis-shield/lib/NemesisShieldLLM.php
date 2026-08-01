<?php
/**
 * Nemesis Shield: LLM Guard (WordPress-native).
 *
 * OWASP-LLM-Top-10 detection with the HashLR classifier shared across every Nemesis Shield SDK.
 * Feature buckets are fnv1a(feature) % dim, identical to every other language, so a prompt scores the
 * same everywhere. Char n-grams over a canonicalized (de-leetspeaked, ASCII-alnum) form catch
 * obfuscation the regex layer misses.
 *
 * The model is bundled with the plugin and read locally (via wp_json_file_decode). This build does not
 * fetch models or any other code from external sources.
 *
 * @package Nemesis_Shield
 */

if (!defined('ABSPATH')) {
    exit;
}

final class NemesisShieldLLM
{
    private static $model = null;

    private static $leet = array('0' => 'o', '1' => 'i', '3' => 'e', '4' => 'a', '5' => 's', '7' => 't', '@' => 'a', '$' => 's', '8' => 'b', '|' => 'i');

    private static $injection = array(
        '/ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts?|context)/i',
        '/disregard\s+(the\s+)?(above|previous|system)/i',
        '/(reveal|show|print|repeat)\s+(your|the)\s+(system\s+)?(prompt|instructions)/i',
        '/\bDAN\b|do\s+anything\s+now|developer\s+mode|jailbreak/i',
        '/(bypass|ignore|disable)\s+(your\s+)?(safety|content\s+policy|guardrails?)/i',
    );

    private static function model()
    {
        if (self::$model === null) {
            $m = wp_json_file_decode(__DIR__ . '/ml_weights.json', array('associative' => true));
            self::$model = is_array($m) ? $m : array('dim' => 1, 'bias' => 0, 'weights' => array(), 'version' => 1);
        }
        return self::$model;
    }

    public static function modelVersion()
    {
        return (int) (self::model()['version'] ?? 1);
    }

    private static function fnv1a($s)
    {
        $h = 0x811c9dc5;
        for ($i = 0, $n = strlen($s); $i < $n; $i++) {
            $h ^= ord($s[$i]);
            $h = ($h * 0x01000193) & 0xffffffff;
        }
        return $h;
    }

    private static function bucket($s, $dim)
    {
        return self::fnv1a($s) % $dim;
    }

    private static function canon($text)
    {
        $t = strtr(strtolower($text), self::$leet);
        $out = '';
        for ($i = 0, $n = strlen($t); $i < $n; $i++) {
            $c = $t[$i];
            if (($c >= 'a' && $c <= 'z') || ($c >= '0' && $c <= '9')) {
                $out .= $c;
            }
        }
        return $out;
    }

    private static function features($text, $dim)
    {
        $b = array();
        preg_match_all("/[a-z0-9']+/", strtolower($text), $m);
        $ws = $m[0];
        foreach ($ws as $w) {
            $b[self::bucket('w:' . $w, $dim)] = true;
        }
        for ($i = 0, $k = count($ws); $i + 1 < $k; $i++) {
            $b[self::bucket('b:' . $ws[$i] . ' ' . $ws[$i + 1], $dim)] = true;
        }
        $c = self::canon($text);
        foreach (array(3, 4, 5) as $n) {
            for ($i = 0, $l = strlen($c); $i + $n <= $l; $i++) {
                $b[self::bucket('c' . $n . ':' . substr($c, $i, $n), $dim)] = true;
            }
        }
        if (strlen($text) > 2000) {
            $b[self::bucket('e:long', $dim)] = true;
        }
        $na = 0;
        for ($i = 0, $n = strlen($text); $i < $n; $i++) {
            if (ord($text[$i]) > 127) {
                $na++;
            }
        }
        if ($na > 3) {
            $b[self::bucket('e:nonascii', $dim)] = true;
        }
        return $b;
    }

    /** Probability (0..1) that $text is a prompt-injection / jailbreak attempt. */
    public static function mlInjectionScore($text)
    {
        $m = self::model();
        $z = $m['bias'];
        $w = $m['weights'];
        foreach (self::features($text, $m['dim']) as $bk => $_) {
            if (isset($w[(string) $bk])) {
                $z += $w[(string) $bk];
            }
        }
        if ($z < -30) {
            return 0.0;
        }
        if ($z > 30) {
            return 1.0;
        }
        return 1.0 / (1.0 + exp(-$z));
    }

    /** Returns array('blocked'=>bool,'severity'=>,'kind'=>,'score'=>,'owasp'=>). Regex first, then ML. */
    public static function guardLLM($prompt, $enforce = false)
    {
        foreach (self::$injection as $re) {
            if (preg_match($re, $prompt)) {
                return array('blocked' => (bool) $enforce, 'severity' => 'high', 'kind' => 'prompt_injection', 'score' => 1.0, 'owasp' => 'LLM01');
            }
        }
        $m = self::model();
        $s = self::mlInjectionScore($prompt);
        if ($s >= ($m['blockThreshold'] ?? 0.85)) {
            return array('blocked' => (bool) $enforce, 'severity' => 'high', 'kind' => 'ml_prompt_injection', 'score' => $s, 'owasp' => 'LLM01');
        }
        if ($s >= ($m['flagThreshold'] ?? 0.45)) {
            return array('blocked' => false, 'severity' => 'medium', 'kind' => 'ml_prompt_injection', 'score' => $s, 'owasp' => 'LLM01');
        }
        return array('blocked' => false, 'severity' => 'none', 'score' => $s);
    }
}
