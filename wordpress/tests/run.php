<?php
// Deterministic proof that the WordPress plugin (a) UNDERSTANDS — reports the
// correct privacy-preserving shape for each request, matching the SDK byte-for-
// byte, and (b) GATES — blocks off-baseline requests in enforce mode while
// approved ones pass, and (c) FAILS OPEN when Shield is unreachable.
//
// Requires a running mock (see run-tests.sh) and these env vars:
//   NEMESIS_ENDPOINT, NEMESIS_MOCK_POLICY, NEMESIS_MOCK_RECORD, NEMESIS_TOKEN

// Parity oracle = the canonical PHP SDK. We assert the WordPress-native class produces byte-identical
// shapes to it, so a WP site is treated exactly like every other Nemesis Shield integration.
require dirname(dirname(__DIR__)) . '/php/NemesisShield.php';

$TOKEN      = getenv('NEMESIS_TOKEN');
$ENDPOINT   = getenv('NEMESIS_ENDPOINT');
$POLICYFILE = getenv('NEMESIS_MOCK_POLICY');
$RECORDFILE = getenv('NEMESIS_MOCK_RECORD');

$pass = 0; $fail = 0;
function ok($cond, $msg) {
    global $pass, $fail;
    if ($cond) { $pass++; echo "  \033[32m✓\033[0m $msg\n"; }
    else       { $fail++; echo "  \033[31m✗ $msg\033[0m\n"; }
}
function section($t) { echo "\n\033[1m$t\033[0m\n"; }

function cacheFile($token) { return sys_get_temp_dir() . '/nemesis_' . substr(sha1($token), 0, 16) . '.json'; }
function clearCache($token) { @unlink(cacheFile($token)); }
function setPolicy($file, $mode, $shapes = array(), $knownBad = array()) {
    file_put_contents($file, json_encode(array(
        'mode' => $mode,
        'policy' => array('shapes' => (object) $shapes, 'knownBad' => array_values($knownBad)),
    )));
}
function clearRecord($file) { file_put_contents($file, ''); }
function records($file) {
    $out = array();
    foreach (explode("\n", trim((string) @file_get_contents($file))) as $l) {
        if ($l !== '') { $out[] = json_decode($l, true); }
    }
    return $out;
}
function recordedShapes($file) {
    return array_map(function ($r) { return $r['shape'] ?? null; }, records($file));
}

// Compute the canonical sketch exactly as the SDK/plugin will — this is the
// oracle we assert the plugin's reported shape against.
function sketch($method, $path, $query, $authed) {
    return NemesisShield::buildSketch($method, $path, $query, $authed, 0);
}

// Run one simulated request in a child process.
function req($opts) {
    $env = array(
        'NS_METHOD'       => $opts['method']  ?? 'GET',
        'NS_URI'          => $opts['uri']     ?? '/',
        'NS_SCRIPT'       => $opts['script']  ?? '/index.php',
        'NS_ADMIN'        => !empty($opts['admin'])      ? '1' : '0',
        'NS_AUTHED'       => !empty($opts['authed'])     ? '1' : '0',
        'NS_AUTH_HEADER'  => !empty($opts['authHeader']) ? '1' : '0',
        'NS_REST'         => !empty($opts['rest'])       ? '1' : '0',
        'NS_ROUTE'        => $opts['route'] ?? '',
        'NS_POST'         => $opts['post'] ?? '',
        'NS_REST_BODY'    => $opts['body'] ?? '',
        'NS_PROTECT_ADMIN'=> !empty($opts['protectAdmin']) ? '1' : '0',
        'NEMESIS_TOKEN'   => getenv('NEMESIS_TOKEN'),
        'NEMESIS_ENDPOINT'=> $opts['endpoint'] ?? getenv('NEMESIS_ENDPOINT'),
        'TMPDIR'          => sys_get_temp_dir(),
    );
    $prefix = '';
    foreach ($env as $k => $v) { $prefix .= $k . '=' . escapeshellarg((string) $v) . ' '; }
    $out = shell_exec($prefix . 'php ' . escapeshellarg(__DIR__ . '/request.php') . ' 2>&1');
    if (preg_match('/RESULT:(\{.*\})/', (string) $out, $m)) {
        return json_decode($m[1], true);
    }
    return array('blocked' => false, 'status' => 0, 'raw' => $out);
}

echo "\033[1mNemesis Shield — WordPress plugin behaviour test\033[0m\n";
echo "endpoint: $ENDPOINT\n";

// The site's "normal" behaviour (three legit routes) + one authed route.
$G_home    = array('method' => 'GET', 'uri' => '/',                    'query' => array(),               'authed' => false);
$G_paged   = array('method' => 'GET', 'uri' => '/?page_id=2',          'query' => array('page_id' => '2'), 'authed' => false);
$G_product = array('method' => 'GET', 'uri' => '/shop/product/123',    'query' => array(),               'authed' => false);
$GOOD = array($G_home, $G_paged, $G_product);

// ---------------------------------------------------------------------------
section('1 · Understands — observe mode learns the correct, normalized shapes');
setPolicy($POLICYFILE, 'observe');
clearRecord($RECORDFILE);
clearCache($TOKEN);

foreach ($GOOD as $g) { req($g); }
usleep(150000); // let the mock finish appending

$recShapes = recordedShapes($RECORDFILE);
$recs = records($RECORDFILE);
foreach ($GOOD as $g) {
    $sk = sketch($g['method'], $g['uri'], $g['query'], $g['authed']);
    ok(in_array($sk['shape'], $recShapes, true),
        "reported shape for {$g['method']} {$g['uri']}  (shape {$sk['shape']}, route {$sk['route']})");
}
// Normalization proof: the product id became {int}, not the raw 123.
$prodRoutes = array_map(function ($r) { return $r['route'] ?? ''; }, $recs);
ok(in_array('/shop/product/{int}', $prodRoutes, true) && !in_array('/shop/product/123', $prodRoutes, true),
    'path id normalized: /shop/product/123 → /shop/product/{int} (raw id never sent)');
ok(count($recs) >= 3, 'every request was observed (' . count($recs) . ' sketches recorded)');

// ---------------------------------------------------------------------------
section('2 · Gates — enforce mode blocks off-baseline, approved passes');
$approved = array();
foreach (array($G_home, $G_product) as $g) {
    $approved[ sketch($g['method'], $g['uri'], $g['query'], $g['authed'])['shape'] ] = 'allow';
}
setPolicy($POLICYFILE, 'enforce', $approved);
clearCache($TOKEN);

$r = req($G_home);
ok(empty($r['blocked']), 'approved route GET / passes (not blocked)');

$r = req($G_product);
ok(empty($r['blocked']), 'approved route GET /shop/product/{int} passes');

$r = req(array('method' => 'GET', 'uri' => '/wp-config.php.bak')); // scanner probe
ok(!empty($r['blocked']) && $r['status'] === 403, 'scanner probe /wp-config.php.bak blocked (403)');

$r = req(array('method' => 'GET', 'uri' => '/index.php?id=1%20OR%201=1')); // never-approved shape
ok(!empty($r['blocked']), 'off-baseline query shape blocked');

$r = req(array('method' => 'DELETE', 'uri' => '/')); // unusual method on an approved path
ok(!empty($r['blocked']), 'unusual method DELETE / blocked (method is part of the shape)');

// ---------------------------------------------------------------------------
section('3 · Gates — global threat intelligence (knownBad)');
$badPath = '/xmlrpc.php';
$badShape = sketch('POST', $badPath, array(), false)['shape'];
setPolicy($POLICYFILE, 'enforce', $approved, array($badShape));
clearCache($TOKEN);
$r = req(array('method' => 'POST', 'uri' => $badPath));
ok(!empty($r['blocked']), 'knownBad shape (POST /xmlrpc.php) blocked by global intel');

// ---------------------------------------------------------------------------
section('4 · Gates the REST API (rest_pre_dispatch)');
$restOkShape = sketch('GET', '/wp-json/wp/v2/posts', array(), false)['shape'];
setPolicy($POLICYFILE, 'enforce', array($restOkShape => 'allow'));
clearCache($TOKEN);
$r = req(array('rest' => true, 'method' => 'GET', 'route' => '/wp/v2/posts'));
ok(empty($r['blocked']), 'approved REST route GET /wp-json/wp/v2/posts passes');
$r = req(array('rest' => true, 'method' => 'GET', 'route' => '/wp/v2/users'));
ok(!empty($r['blocked']) && $r['status'] === 403, 'off-baseline REST route /wp-json/wp/v2/users blocked (403)');

// ---------------------------------------------------------------------------
section('5 · Never locks the admin out (admin observe-only by default)');
setPolicy($POLICYFILE, 'enforce', $approved); // some baseline, admin route not in it
clearCache($TOKEN);
$r = req(array('method' => 'GET', 'uri' => '/wp-admin/options-general.php',
               'script' => '/wp-admin/options-general.php', 'admin' => true, 'authed' => true));
ok(empty($r['blocked']), 'wp-admin request NOT blocked while protect_admin is off (default)');

// ---------------------------------------------------------------------------
section('5b · Safe-unlock — the login/auth path is never blocked');
setPolicy($POLICYFILE, 'enforce', $approved); // baseline present, /login not in it
clearCache($TOKEN);
$r = req(array('method' => 'POST', 'uri' => '/login?next=x'));
ok(empty($r['blocked']), '/login never blocked (default bootstrap break-glass)');
$r = req(array('method' => 'GET', 'uri' => '/wp-login.php'));
ok(empty($r['blocked']), '/wp-login.php never blocked');

// ---------------------------------------------------------------------------
section('6 · Fails open — Shield unreachable never breaks the site');
clearCache($TOKEN);
$r = req(array('method' => 'GET', 'uri' => '/wp-config.php.bak',
               'endpoint' => 'http://127.0.0.1:1/api/v1/sketches')); // dead endpoint
ok(empty($r['blocked']), 'off-baseline request passes (fail-open) when Shield is unreachable');

// ---------------------------------------------------------------------------
section('7 · Depth — POST body structure is part of the shape');
setPolicy($POLICYFILE, 'observe'); clearRecord($RECORDFILE); clearCache($TOKEN);
req(array('method' => 'POST', 'uri' => '/contact', 'post' => 'name=Ada&email=ada@example.com'));
req(array('method' => 'POST', 'uri' => '/contact', 'post' => 'api_key=zzzz'));
usleep(150000);
$depthShapes = recordedShapes($RECORDFILE);
$skBodyA = sketch('POST', '/contact', array('name' => 'Ada', 'email' => 'ada@example.com'), false)['shape'];
$skBodyB = sketch('POST', '/contact', array('api_key' => 'zzzz'), false)['shape'];
ok(in_array($skBodyA, $depthShapes, true), 'POST body {name,email} is shaped + recorded (not just the path)');
ok($skBodyA !== $skBodyB, 'different POST bodies produce different shapes (body structure matters)');

// ---------------------------------------------------------------------------
section('7b · Depth — admin-ajax action distinguishes shapes');
setPolicy($POLICYFILE, 'observe'); clearRecord($RECORDFILE); clearCache($TOKEN);
$ajax = array('method' => 'POST', 'uri' => '/wp-admin/admin-ajax.php', 'script' => '/wp-admin/admin-ajax.php', 'admin' => true);
req(array_merge($ajax, array('post' => 'action=heartbeat')));
req(array_merge($ajax, array('post' => 'action=delete_user')));
usleep(150000);
$ajaxShapes = recordedShapes($RECORDFILE);
$skHeartbeat = sketch('POST', '/wp-admin/admin-ajax.php/heartbeat', array('action' => 'heartbeat'), false)['shape'];
$skDeleteUser = sketch('POST', '/wp-admin/admin-ajax.php/delete_user', array('action' => 'delete_user'), false)['shape'];
ok(in_array($skHeartbeat, $ajaxShapes, true) && in_array($skDeleteUser, $ajaxShapes, true), 'both admin-ajax actions observed (learned) even while observe-only');
ok($skHeartbeat !== $skDeleteUser, 'action=heartbeat and action=delete_user are DISTINCT shapes');

// ---------------------------------------------------------------------------
section('7c · Depth — admin-ajax enforce (Protect wp-admin) blocks off-baseline actions');
setPolicy($POLICYFILE, 'enforce', array($skHeartbeat => 'allow')); clearCache($TOKEN);
$r = req(array_merge($ajax, array('protectAdmin' => true, 'post' => 'action=heartbeat')));
ok(empty($r['blocked']), 'approved admin-ajax action=heartbeat passes');
$r = req(array_merge($ajax, array('protectAdmin' => true, 'post' => 'action=delete_user')));
ok(!empty($r['blocked']) && $r['status'] === 403, 'off-baseline admin-ajax action=delete_user blocked (403)');

// ---------------------------------------------------------------------------
section('7d · Safety — a wp-admin PAGE load is never blocked, even with Protect wp-admin on');
setPolicy($POLICYFILE, 'enforce', array($skHeartbeat => 'allow')); clearCache($TOKEN);
$r = req(array('method' => 'GET', 'uri' => '/wp-admin/options-general.php?page=nemesis-shield',
               'script' => '/wp-admin/options-general.php', 'admin' => true, 'authed' => true, 'protectAdmin' => true));
ok(empty($r['blocked']), 'settings/dashboard page not blocked, so you can always recover');

// ---------------------------------------------------------------------------
section('7e · Depth — REST body parameters are part of the shape');
$skRestOk = sketch('POST', '/wp-json/wp/v2/posts', array('title' => 'Hello'), false)['shape'];
setPolicy($POLICYFILE, 'enforce', array($skRestOk => 'allow')); clearCache($TOKEN);
$r = req(array('rest' => true, 'method' => 'POST', 'route' => '/wp/v2/posts', 'body' => 'title=Hello'));
ok(empty($r['blocked']), 'approved REST write (body {title}) passes');
$r = req(array('rest' => true, 'method' => 'POST', 'route' => '/wp/v2/posts', 'body' => 'title=Hello&inject=1'));
ok(!empty($r['blocked']) && $r['status'] === 403, 'REST write with an off-baseline body param blocked (403)');

// ---------------------------------------------------------------------------
echo "\n" . str_repeat('─', 52) . "\n";
if ($fail === 0) {
    echo "\033[32m\033[1mALL $pass CHECKS PASSED\033[0m\n";
    exit(0);
}
echo "\033[31m\033[1m$fail FAILED\033[0m, $pass passed\n";
exit(1);
