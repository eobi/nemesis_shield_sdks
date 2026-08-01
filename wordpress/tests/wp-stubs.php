<?php
// Minimal WordPress function/constant stubs — just enough to load the plugin and
// fire its `init` / `shutdown` / `rest_pre_dispatch` hooks in isolation, so the
// gating logic can be exercised without a full WordPress install. The Docker e2e
// covers the real WordPress path; this proves the behaviour deterministically.

if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/');
}

$GLOBALS['ns_hooks']     = array();
$GLOBALS['ns_status']    = null;
$GLOBALS['ns_options']   = array();
$GLOBALS['ns_is_admin']  = false;
$GLOBALS['ns_logged_in'] = false;

function add_action($hook, $cb, $prio = 10, $args = 1) { $GLOBALS['ns_hooks'][$hook][] = $cb; }
function add_filter($hook, $cb, $prio = 10, $args = 1) { $GLOBALS['ns_hooks'][$hook][] = $cb; }

// Test-side dispatchers (a real WP core fires these; here we fire them by hand).
function ns_do_action($hook, ...$a) {
    foreach ($GLOBALS['ns_hooks'][$hook] ?? array() as $cb) { call_user_func_array($cb, $a); }
}
function ns_apply_filters($hook, $value, ...$a) {
    foreach ($GLOBALS['ns_hooks'][$hook] ?? array() as $cb) {
        $value = call_user_func_array($cb, array_merge(array($value), $a));
    }
    return $value;
}
function apply_filters($hook, $value, ...$a) { return ns_apply_filters($hook, $value, ...$a); }
function do_action($hook, ...$a) { return ns_do_action($hook, ...$a); }

function is_admin()          { return !empty($GLOBALS['ns_is_admin']); }
function is_user_logged_in() { return !empty($GLOBALS['ns_logged_in']); }

function get_option($k, $d = false)  { return $GLOBALS['ns_options'][$k] ?? $d; }
function update_option($k, $v)       { $GLOBALS['ns_options'][$k] = $v; return true; }

function wp_json_encode($d, $o = 0, $depth = 512) { return json_encode($d, $o, $depth); }
function status_header($code)        { $GLOBALS['ns_status'] = (int) $code; }
function nocache_headers()           {}

// UI helpers referenced only by the (unexercised) settings screen — stubbed so the
// file parses/loads cleanly if ever included in an admin context.
function esc_attr($s)        { return htmlspecialchars((string) $s, ENT_QUOTES); }
function esc_url_raw($s)     { return (string) $s; }
function sanitize_text_field($s) { return trim((string) $s); }
function sanitize_key($s) { $s = strtolower((string) $s); return preg_replace('/[^a-z0-9_\-]/', '', $s); }

// Input unslashing (real WP strips one level of magic-quotes slashes). Tests pass clean data.
function wp_unslash($v) { return is_array($v) ? array_map('wp_unslash', $v) : (is_string($v) ? stripslashes($v) : $v); }

// i18n + escaping helpers (settings screen only; not exercised by the gate tests).
function __($s, $d = 'default') { return (string) $s; }
function esc_html__($s, $d = 'default') { return htmlspecialchars((string) $s, ENT_QUOTES); }
function esc_html($s) { return htmlspecialchars((string) $s, ENT_QUOTES); }
function wp_kses($s, $allowed = array()) { return (string) $s; }

// ── WordPress HTTP API (real request to the mock endpoint; test-only transport) ──────────────────
function wp_remote_post($url, $args = array()) {
    if (!function_exists('curl_init')) {
        return new WP_Error('http', 'curl unavailable');
    }
    $ch = curl_init($url);
    $headers = array();
    foreach (($args['headers'] ?? array()) as $k => $v) { $headers[] = $k . ': ' . $v; }
    curl_setopt_array($ch, array(
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_POSTFIELDS => $args['body'] ?? '',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => (int) ($args['timeout'] ?? 5),
        CURLOPT_CONNECTTIMEOUT => 2,
    ));
    $body = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);
    if ($body === false || $code === 0) {
        return new WP_Error('http_request_failed', $err ?: 'request failed');
    }
    return array('body' => $body, 'response' => array('code' => $code));
}
function is_wp_error($t) { return $t instanceof WP_Error; }
function wp_remote_retrieve_response_code($r) { return is_array($r) ? ($r['response']['code'] ?? 0) : 0; }
function wp_remote_retrieve_body($r) { return is_array($r) ? ($r['body'] ?? '') : ''; }

// ── Transients (in-process; each test child starts empty, which is fine — it just refetches policy) ─
$GLOBALS['ns_transients'] = array();
function get_transient($k) { return $GLOBALS['ns_transients'][$k] ?? false; }
function set_transient($k, $v, $ttl = 0) { $GLOBALS['ns_transients'][$k] = $v; return true; }
function delete_transient($k) { unset($GLOBALS['ns_transients'][$k]); return true; }

function wp_json_file_decode($file, $opts = array()) {
    $raw = @file_get_contents($file);
    return $raw === false ? null : json_decode($raw, !empty($opts['associative']));
}

class WP_Error {
    public $code;
    public $message;
    public $data;
    public function __construct($code = '', $message = '', $data = '') {
        $this->code = $code; $this->message = $message; $this->data = $data;
    }
}
