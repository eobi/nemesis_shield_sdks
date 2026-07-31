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

class WP_Error {
    public $code;
    public $message;
    public $data;
    public function __construct($code = '', $message = '', $data = '') {
        $this->code = $code; $this->message = $message; $this->data = $data;
    }
}
