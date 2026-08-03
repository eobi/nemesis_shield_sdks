<?php
/**
 * Nemesis Shield: WordPress-native client for the Nemesis Shield service.
 *
 * The learning, the approval console, the enforcement mode, and the global threat intelligence all
 * live in the external Nemesis Shield service (shield.nemesislabs.xyz). This class is the connector:
 * it computes a privacy-preserving *shape* of each request locally, sends those shapes to the service,
 * caches the compiled policy the service returns, and applies the service's decision. It performs all
 * network I/O through the WordPress HTTP API and caches through the Transients API.
 *
 * The shape/decision math here is byte-for-byte identical to every other Nemesis Shield SDK, so the
 * service treats a WordPress site exactly like any other integration. Fail-open: if the service is
 * unreachable, requests are forwarded untouched.
 *
 * @package Nemesis_Shield
 */

if (!defined('ABSPATH')) {
    exit;
}

class NemesisShieldWP
{
    const ENDPOINT = 'https://shield.nemesislabs.xyz/api/v1/sketches';
    const TTL = 2; // seconds; refresh the cached policy at most this often

    /**
     * The service endpoint. Defaults to the Nemesis Shield cloud; override with the
     * NEMESIS_SHIELD_ENDPOINT constant (set from the plugin settings) or the NEMESIS_ENDPOINT
     * environment variable to point at a self-hosted service.
     */
    private static function endpoint()
    {
        if (defined('NEMESIS_SHIELD_ENDPOINT') && NEMESIS_SHIELD_ENDPOINT) {
            return NEMESIS_SHIELD_ENDPOINT;
        }
        $env = getenv('NEMESIS_ENDPOINT');
        return ($env !== false && $env !== '') ? $env : self::ENDPOINT;
    }

    // Safe-unlock (break-glass): paths the service never blocks, so a still-learning baseline can't
    // lock operators out of the doors they need to fix it. Prefix-matched on the pathname. Extend with
    // the NEMESIS_SHIELD_BOOTSTRAP environment variable (comma-separated).
    //
    // Note: /wp-admin is deliberately NOT here. Lockout safety for the dashboard is handled more
    // precisely in the plugin's enforceable() gate (regular wp-admin page loads are always observe-only;
    // only the admin-ajax / admin-post APIs are enforceable, and only when "Protect wp-admin" is on).
    // A blanket /wp-admin never-block here would make admin-ajax unblockable, which is a WordPress
    // attack surface we do want to be able to enforce. The login path stays fully break-glass.
    const DEFAULT_BOOTSTRAP = array('/login', '/signin', '/sign-in', '/auth', '/oauth', '/session', '/wp-login.php');

    private static function bootstrap()
    {
        $env = getenv('NEMESIS_SHIELD_BOOTSTRAP');
        if ($env !== false && trim($env) !== '') {
            return array_values(array_filter(array_map('trim', explode(',', $env))));
        }
        return self::DEFAULT_BOOTSTRAP;
    }

    /** Break-glass: is this path on the never-block bootstrap allow-list? Prefix match. */
    public static function neverBlock($path)
    {
        $p = strtolower(explode('#', explode('?', $path, 2)[0], 2)[0]);
        foreach (self::bootstrap() as $b) {
            if ($b !== '' && strpos($p, strtolower($b)) === 0) {
                return true;
            }
        }
        return false;
    }

    // ── Shape computation (parity-critical: identical to every Nemesis Shield SDK) ────────────────

    public static function normalizePath($path)
    {
        $path = explode('?', $path, 2)[0];
        $path = explode('#', $path, 2)[0];
        $segs = explode('/', $path);
        foreach ($segs as $i => $s) {
            if ($s === '') {
                continue;
            }
            if (strpos($s, '..') !== false) {
                $segs[$i] = '{traversal}';
                continue;
            }
            switch (self::kindOf($s)) {
                case 'int':
                case 'float':
                    $segs[$i] = '{int}';
                    break;
                case 'uuid':
                    $segs[$i] = '{uuid}';
                    break;
                case 'hex':
                    $segs[$i] = '{hex}';
                    break;
                case 'base64':
                    $segs[$i] = '{token}';
                    break;
                case 'alnum':
                    if (strlen($s) >= 12 && !preg_match('/[A-Za-z]{7,}/', $s)) {
                        $segs[$i] = '{id}';
                    }
                    break;
            }
        }
        $out = implode('/', $segs);
        return $out === '' ? '/' : $out;
    }

    // Canonical value taxonomy, must match the shared engine byte-for-byte.
    private static function kindOf($v)
    {
        if ($v === null || $v === '') {
            return 'empty';
        }
        if (is_bool($v)) {
            return 'bool';
        }
        $s = (string) $v;
        if ($s === '') {
            return 'empty';
        }
        if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $s)) {
            return 'uuid';
        }
        if (preg_match('/^[^@\s]+@[^@\s]+\.[^@\s]+$/', $s)) {
            return 'email';
        }
        if (preg_match('#^https?://\S+$#i', $s)) {
            return 'url';
        }
        if (preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $s)) {
            return 'ipv4';
        }
        if (preg_match('/^[0-9a-f:]+:[0-9a-f:]+$/i', $s)) {
            return 'ipv6';
        }
        if (preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $s)) {
            return 'jwt';
        }
        if (preg_match('/^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?/', $s)) {
            return 'date';
        }
        if (preg_match('/^-?\d+$/', $s)) {
            return 'int';
        }
        if (preg_match('/^-?\d*\.\d+$/', $s)) {
            return 'float';
        }
        if (strlen($s) >= 16 && preg_match('/^[0-9a-f]+$/i', $s)) {
            return 'hex';
        }
        if (strlen($s) >= 16 && preg_match('#^[A-Za-z0-9+/]+={0,2}$#', $s) && !preg_match('/[A-Za-z]{7,}/', $s)) {
            return 'base64';
        }
        if (preg_match('/^[A-Za-z]+$/', $s)) {
            return 'alpha';
        }
        if (preg_match('/^[A-Za-z0-9]+$/', $s)) {
            return 'alnum';
        }
        return 'string';
    }

    private static function fnv1a($s)
    {
        $h = 0x811c9dc5;
        for ($i = 0, $n = strlen($s); $i < $n; $i++) {
            $h ^= ord($s[$i]);
            $h = ($h * 0x01000193) & 0xffffffff;
        }
        return str_pad(dechex($h), 8, '0', STR_PAD_LEFT);
    }

    // Analytics / click-tracking query params carry no application logic and are the main cause of
    // shape explosion (every ad/campaign link adds different ones). Stripped from the signature so a
    // UTM'd request matches the bare route, while real params (and any attack in them) stay modeled.
    // Shared, identical across every Nemesis Shield SDK so the shape hash matches everywhere.
    private static function isTrackingParam($name)
    {
        $n = strtolower((string) $name);
        foreach (array('utm_', 'mtm_', 'pk_', 'hsa_', 'matomo_', 'piwik_', 'ga_') as $p) {
            if (strpos($n, $p) === 0) {
                return true;
            }
        }
        return in_array($n, array('gclid', 'gbraid', 'wbraid', 'dclid', 'gclsrc', 'fbclid', 'msclkid', 'twclid', 'ttclid', 'yclid', 'igshid', 'scid', 'wickedid', '_ga', '_gl', '_hsenc', '_hsmi', 'mc_cid', 'mc_eid', 'vero_id', 'vero_conv', 'oly_anon_id', 'oly_enc_id', '_openstat', 'rb_clickid', 's_cid', 'epik', 'sccid'), true);
    }

    public static function buildSketch($method, $path, array $query, $authed, $status)
    {
        $route = self::normalizePath($path);
        $names = array_filter(array_keys($query), function ($k) { return !self::isTrackingParam($k); });
        sort($names);
        $params = array();
        foreach ($names as $k) {
            $nested = is_array($query[$k]);
            $v = $nested ? ($query[$k][0] ?? '') : $query[$k];
            $params[] = array('name' => (string) $k, 'kind' => self::kindOf($v), 'nested' => $nested);
        }
        // Canonical shape input: keys sorted (auth, method, params, route); params [name, kind, nested];
        // status excluded so enforcement decides BEFORE the response exists.
        $canonParams = array_map(function ($p) {
            return array($p['name'], $p['kind'], !empty($p['nested']) ? 1 : 0);
        }, $params);
        $canon = wp_json_encode(array(
            'auth' => $authed ? 1 : 0,
            'method' => strtoupper($method),
            'params' => $canonParams,
            'route' => $route,
        ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return array(
            'route' => $route,
            'method' => strtoupper($method),
            'authenticated' => (bool) $authed,
            'status' => $status,
            'params' => $params,
            'shape' => self::fnv1a($canon),
        );
    }

    // ── Service I/O (WordPress HTTP API + Transients) ────────────────────────────────────────────

    /** POST a batch of sketches to the service; returns the decoded policy body, or null on any error. */
    private static function send($token, array $batch)
    {
        $res = wp_remote_post(self::endpoint(), array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $token,
                'Content-Type' => 'application/json',
            ),
            'body' => wp_json_encode(array('sketches' => $batch)),
            'timeout' => 3,
            'blocking' => true,
        ));
        if (is_wp_error($res)) {
            return null;
        }
        $code = (int) wp_remote_retrieve_response_code($res);
        if ($code < 200 || $code >= 300) {
            return null;
        }
        $body = wp_remote_retrieve_body($res);
        $d = json_decode($body, true);
        return is_array($d) ? $d : null;
    }

    private static function cacheKey($token)
    {
        return 'nemesis_shield_' . substr(sha1($token), 0, 16);
    }

    private static function normalizePolicy(array $res)
    {
        return array(
            'mode' => $res['mode'] ?? 'observe',
            'shapes' => $res['policy']['shapes'] ?? array(),
            'knownBad' => $res['policy']['knownBad'] ?? array(),
        );
    }

    /** Load the cached policy from a transient, refreshing from the service if missing or expired. */
    private static function policy($token)
    {
        $cached = get_transient(self::cacheKey($token));
        if (is_array($cached)) {
            return $cached;
        }
        $res = self::send($token, array()); // refresh
        if ($res) {
            $p = self::normalizePolicy($res);
            set_transient(self::cacheKey($token), $p, self::TTL);
            return $p;
        }
        return array('mode' => 'observe', 'shapes' => array(), 'knownBad' => array());
    }

    private static function decide(array $policy, $shape)
    {
        $per = $policy['shapes'][$shape] ?? null;
        if ($per === 'allow') {
            return array(false, null);
        }
        if ($per === 'block') {
            return array(true, 'policy: blocked shape');
        }
        if (in_array($shape, $policy['knownBad'] ?? array(), true)) {
            return array(true, 'global threat intelligence');
        }
        if (!empty($policy['shapes'])) {
            return array(true, 'off-baseline: unapproved behavior');
        }
        return array(false, null);
    }

    /**
     * Positive-security verdict for a request. Returns array(block(bool), reason(?string)).
     * All request values are passed in already sanitized by the caller (never read from superglobals
     * here). Records the blocked attempt with the service when it blocks.
     */
    public static function verdict($token, $method, $path, array $query, $authed)
    {
        if (self::neverBlock($path)) {
            return array(false, null); // break-glass: never block the auth path
        }
        $policy = self::policy($token);
        if (($policy['mode'] ?? 'observe') === 'enforce') {
            $sk = self::buildSketch($method, $path, $query, $authed, 0);
            list($block, $reason) = self::decide($policy, $sk['shape']);
            if ($block) {
                self::send($token, array(self::buildSketch($method, $path, $query, $authed, 403)));
                return array(true, $reason);
            }
        }
        return array(false, null);
    }

    /** Record an observed behavior with the service (builds the baseline). */
    public static function observe($token, $method, $path, array $query, $authed, $status)
    {
        $res = self::send($token, array(self::buildSketch($method, $path, $query, $authed, $status)));
        if ($res) {
            set_transient(self::cacheKey($token), self::normalizePolicy($res), self::TTL);
        }
    }
}
