<?php
// Simulate ONE WordPress request through the plugin. Configured via NS_* env vars;
// prints a `RESULT:{...}` line reporting whether the request was blocked and with
// what status. Run by run.php as a child process so a block's exit() is contained.

error_reporting(E_ALL & ~E_DEPRECATED);
require __DIR__ . '/wp-stubs.php';

$_SERVER['REQUEST_METHOD'] = getenv('NS_METHOD') ?: 'GET';
$_SERVER['REQUEST_URI']    = getenv('NS_URI') ?: '/';
$_SERVER['SCRIPT_NAME']    = getenv('NS_SCRIPT') ?: '/index.php';
$GLOBALS['ns_is_admin']    = getenv('NS_ADMIN') === '1';
$GLOBALS['ns_logged_in']   = getenv('NS_AUTHED') === '1';

$_GET = array();
$qs = parse_url($_SERVER['REQUEST_URI'], PHP_URL_QUERY);
if ($qs) { parse_str($qs, $_GET); }
if (getenv('NS_AUTH_HEADER') === '1') { $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer test'; }

// Always emit a RESULT line, even when the plugin blocks (exit still runs PHP
// shutdown callbacks). Status 403 == blocked.
register_shutdown_function(function () {
    $status  = $GLOBALS['ns_status'];
    $blocked = ($status === 403);
    echo "\nRESULT:" . json_encode(array('blocked' => $blocked, 'status' => $status ?? 200)) . "\n";
});

require dirname(__DIR__) . '/nemesis-shield/nemesis-shield.php';

if (getenv('NS_REST') === '1') {
    if (!defined('REST_REQUEST')) { define('REST_REQUEST', true); }
    $route = getenv('NS_ROUTE') ?: '/wp/v2/posts';
    $req = new class($route, $_SERVER['REQUEST_METHOD'], $_GET) {
        private $r, $m, $q;
        public function __construct($r, $m, $q) { $this->r = $r; $this->m = $m; $this->q = $q; }
        public function get_route()        { return $this->r; }
        public function get_method()       { return $this->m; }
        public function get_query_params() { return $this->q; }
    };
    $res = ns_apply_filters('rest_pre_dispatch', null, null, $req);
    if ($res instanceof WP_Error) {
        $GLOBALS['ns_status'] = 403;
    }
    return; // REST path: don't also run the non-REST init gate
}

ns_do_action('init');      // pre-dispatch gate (may block + exit)
ns_do_action('shutdown');  // observe (only reached when not blocked)
