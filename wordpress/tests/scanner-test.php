<?php
// In-process test for the malware scanner's pattern engine (scan_string). Pure detection logic, no
// filesystem needed. Asserts it catches high-signal backdoors and does NOT flag ordinary code.

error_reporting(E_ALL & ~E_DEPRECATED);
require __DIR__ . '/wp-stubs.php';
require dirname(__DIR__) . '/nemesis-shield/lib/class-scanner.php';

$pass = 0; $fail = 0;
function ok($cond, $msg) {
    global $pass, $fail;
    if ($cond) { $pass++; echo "  \033[32m✓\033[0m $msg\n"; }
    else       { $fail++; echo "  \033[31m✗ $msg\033[0m\n"; }
}
function section($t) { echo "\n\033[1m$t\033[0m\n"; }
function hits($code) { return Nemesis_Shield_Scanner::scan_string($code); }

echo "\033[1mNemesis Shield — malware scanner patterns\033[0m\n";

section('1 · Catches high-signal backdoors');
$malware = array(
    'eval(base64_decode)'     => '<?php eval(base64_decode($_POST["x"]));',
    'assert(superglobal)'     => '<?php assert($_REQUEST["c"]);',
    'system(superglobal)'     => '<?php system($_GET["cmd"]);',
    'preg_replace /e'         => '<?php preg_replace("/.*/e", $evil, $s);',
    'gzinflate(base64)'       => '<?php $x = gzinflate(base64_decode($p));',
    'create_function'         => '<?php $f = create_function("", $code);',
    'variable superglobal fn' => '<?php $_GET["f"]("whoami");',
    'known shell name'        => '<?php /* c99shell v.1 */ $a=1;',
    'call_user_func super'    => '<?php call_user_func($_POST["cb"], $arg);',
);
foreach ($malware as $label => $code) {
    ok(count(hits($code)) > 0, "flags: $label");
}

section('2 · Does NOT flag ordinary WordPress code (no false positives)');
$clean = array(
    'sanitized GET'      => '<?php $id = (int) $_GET["id"]; echo esc_html($id);',
    'base64_encode use'  => '<?php function tok() { return base64_encode("hi"); }',
    'normal preg_replace' => '<?php $s = preg_replace("/foo/i", "bar", $s);',
    'add_action closure'  => '<?php add_action("init", function () { do_stuff(); });',
    'wpdb prepare'        => '<?php $wpdb->get_row($wpdb->prepare("SELECT * FROM t WHERE id=%d", $id));',
    'json + escaping'     => '<?php echo wp_json_encode(array("ok" => true));',
);
foreach ($clean as $label => $code) {
    $h = hits($code);
    ok(count($h) === 0, "clean: $label" . (count($h) ? " (WRONGLY flagged: " . implode(',', $h) . ")" : ""));
}

echo "\n" . str_repeat('─', 52) . "\n";
if ($fail === 0) { echo "\033[32m\033[1mALL $pass SCANNER CHECKS PASSED\033[0m\n"; exit(0); }
echo "\033[31m\033[1m$fail FAILED\033[0m, $pass passed\n";
exit(1);
