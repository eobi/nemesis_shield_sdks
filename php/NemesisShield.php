<?php
// Nemesis Shield — Sentinel SDK for PHP (native: local shape + cached policy + inline blocking).
// Learns your app's normal behavior; in enforce mode blocks off-baseline requests (auth bypass, path
// traversal, scanners, unusual methods) before your app runs. PHP is stateless per-request, so the
// compiled policy is cached to a temp file with a short TTL and refreshed on demand. Fail-open.
//
// Raw:      if (NemesisShield::guard($token)) return;  ... your app ...  NemesisShield::observe($token);
// Laravel/Symfony/PSR-15: see NemesisShieldMiddleware below.

class NemesisShield
{
    const ENDPOINT = 'https://shield.nemesislabs.xyz/api/v1/sketches';
    const TTL = 2; // seconds; refresh the cached policy at most this often

    private static function cacheFile(string $token): string
    {
        return sys_get_temp_dir() . '/nemesis_' . substr(sha1($token), 0, 16) . '.json';
    }

    public static function normalizePath(string $path): string
    {
        $path = explode('?', $path, 2)[0];
        $path = explode('#', $path, 2)[0];
        $segs = explode('/', $path);
        foreach ($segs as $i => $s) {
            if ($s === '') continue;
            switch (self::kindOf($s)) {
                case 'int': case 'float': $segs[$i] = '{int}'; break;
                case 'uuid': $segs[$i] = '{uuid}'; break;
                case 'hex': $segs[$i] = '{hex}'; break;
                case 'base64': $segs[$i] = '{token}'; break;
                case 'alnum': if (strlen($s) >= 12) $segs[$i] = '{id}'; break;
            }
        }
        $out = implode('/', $segs);
        return $out === '' ? '/' : $out;
    }

    // Canonical value taxonomy — must match the shared engine (tokenize.ts) byte-for-byte.
    private static function kindOf($v): string
    {
        if ($v === null || $v === '') return 'empty';
        if (is_bool($v)) return 'bool';
        $s = (string)$v;
        if ($s === '') return 'empty';
        if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $s)) return 'uuid';
        if (preg_match('/^[^@\s]+@[^@\s]+\.[^@\s]+$/', $s)) return 'email';
        if (preg_match('#^https?://\S+$#i', $s)) return 'url';
        if (preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $s)) return 'ipv4';
        if (preg_match('/^[0-9a-f:]+:[0-9a-f:]+$/i', $s)) return 'ipv6';
        if (preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $s)) return 'jwt';
        if (preg_match('/^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?/', $s)) return 'date';
        if (preg_match('/^-?\d+$/', $s)) return 'int';
        if (preg_match('/^-?\d*\.\d+$/', $s)) return 'float';
        if (strlen($s) >= 16 && preg_match('/^[0-9a-f]+$/i', $s)) return 'hex';
        if (strlen($s) >= 16 && preg_match('#^[A-Za-z0-9+/]+={0,2}$#', $s)) return 'base64';
        if (preg_match('/^[A-Za-z]+$/', $s)) return 'alpha';
        if (preg_match('/^[A-Za-z0-9]+$/', $s)) return 'alnum';
        return 'string';
    }

    private static function fnv1a(string $s): string
    {
        $h = 0x811c9dc5;
        for ($i = 0, $n = strlen($s); $i < $n; $i++) {
            $h ^= ord($s[$i]);
            $h = ($h * 0x01000193) & 0xffffffff;
        }
        return str_pad(dechex($h), 8, '0', STR_PAD_LEFT);
    }

    public static function buildSketch(string $method, string $path, array $query, bool $authed, int $status): array
    {
        $route = self::normalizePath($path);
        $names = array_keys($query);
        sort($names);
        $params = [];
        foreach ($names as $k) {
            $nested = is_array($query[$k]);
            $v = $nested ? ($query[$k][0] ?? '') : $query[$k];
            $params[] = ['name' => (string)$k, 'kind' => self::kindOf($v), 'nested' => $nested];
        }
        // canonical shape input: keys sorted (auth, method, params, route); params [name, kind, nested];
        // status excluded so enforcement decides BEFORE the response exists.
        $canonParams = array_map(fn($p) => [$p['name'], $p['kind'], !empty($p['nested']) ? 1 : 0], $params);
        $canon = json_encode(['auth' => $authed ? 1 : 0, 'method' => strtoupper($method), 'params' => $canonParams, 'route' => $route], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return ['route' => $route, 'method' => strtoupper($method), 'authenticated' => $authed, 'status' => $status, 'params' => $params, 'shape' => self::fnv1a($canon)];
    }

    private static function send(string $token, array $batch): ?array
    {
        if (!function_exists('curl_init')) return null;
        $ch = curl_init(self::ENDPOINT);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $token, 'Content-Type: application/json'],
            CURLOPT_POSTFIELDS => json_encode(['sketches' => $batch]),
            CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 3, CURLOPT_CONNECTTIMEOUT => 2,
        ]);
        $res = @curl_exec($ch);
        curl_close($ch);
        return $res ? (json_decode($res, true) ?: null) : null;
    }

    private static function savePolicy(string $token, array $res): array
    {
        $p = [
            'mode' => $res['mode'] ?? 'observe',
            'shapes' => $res['policy']['shapes'] ?? [],
            'knownBad' => $res['policy']['knownBad'] ?? [],
        ];
        @file_put_contents(self::cacheFile($token), json_encode($p));
        return $p;
    }

    /** Load the cached policy, refreshing from the server if the cache is missing or stale. */
    private static function policy(string $token): array
    {
        $f = self::cacheFile($token);
        if (is_file($f) && (time() - filemtime($f)) < self::TTL) {
            $d = json_decode(file_get_contents($f), true);
            if (is_array($d)) return $d;
        }
        $res = self::send($token, []); // refresh
        return $res ? self::savePolicy($token, $res) : (['mode' => 'observe', 'shapes' => [], 'knownBad' => []]);
    }

    private static function decide(array $policy, string $shape): array
    {
        $per = $policy['shapes'][$shape] ?? null;
        if ($per === 'allow') return [false, null];
        if ($per === 'block') return [true, 'policy: blocked shape'];
        if (in_array($shape, $policy['knownBad'] ?? [], true)) return [true, 'global threat intelligence'];
        if (!empty($policy['shapes'])) return [true, 'off-baseline: unapproved behavior'];
        return [false, null];
    }

    /**
     * Non-echoing decision for framework middleware (Laravel/Symfony): returns [block(bool),
     * reason(?string)]. Records the blocked attempt when it blocks.
     */
    public static function verdict(string $token, string $method, string $path, array $query, bool $authed): array
    {
        $policy = self::policy($token);
        if (($policy['mode'] ?? 'observe') === 'enforce') {
            $sk = self::buildSketch($method, $path, $query, $authed, 0);
            [$block, $reason] = self::decide($policy, $sk['shape']);
            if ($block) {
                self::send($token, [self::buildSketch($method, $path, $query, $authed, 403)]);
                return [true, $reason];
            }
        }
        return [false, null];
    }

    /** Call at the START of a request (raw PHP). Returns true (and emits a 403) if blocked. */
    public static function guard(string $token, ?string $method = null, ?string $path = null, ?array $query = null, ?bool $authed = null): bool
    {
        $method = $method ?? ($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $path = $path ?? strtok($_SERVER['REQUEST_URI'] ?? '/', '?');
        $query = $query ?? ($_GET ?? []);
        $authed = $authed ?? (isset($_SERVER['HTTP_AUTHORIZATION']) || isset($_SESSION['user']) || isset($_COOKIE['session']));
        [$block, $reason] = self::verdict($token, $method, $path, $query, $authed);
        if ($block) {
            http_response_code(403);
            header('content-type: application/json');
            echo json_encode(['error' => 'blocked_by_nemesis_shield', 'reason' => $reason]);
            return true;
        }
        return false;
    }

    /** Call at the END of a request to record the observed behavior. */
    public static function observe(string $token, ?string $method = null, ?string $path = null, ?array $query = null, ?bool $authed = null, ?int $status = null): void
    {
        $method = $method ?? ($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $path = $path ?? strtok($_SERVER['REQUEST_URI'] ?? '/', '?');
        $query = $query ?? ($_GET ?? []);
        $authed = $authed ?? (isset($_SERVER['HTTP_AUTHORIZATION']) || isset($_SESSION['user']) || isset($_COOKIE['session']));
        $status = $status ?? (http_response_code() ?: 200);
        $res = self::send($token, [self::buildSketch($method, $path, $query, $authed, $status)]);
        if ($res) self::savePolicy($token, $res);
    }
}
