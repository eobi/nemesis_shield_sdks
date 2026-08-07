<?php
// In-process test for vulnerability awareness: local inventory + outdated detection, and parsing of
// cached service advisories. No network needed.

error_reporting(E_ALL & ~E_DEPRECATED);
require __DIR__ . '/wp-stubs.php';
require dirname(__DIR__) . '/nemesis-shield/lib/class-vulns.php';

$pass = 0; $fail = 0;
function ok($cond, $msg) {
    global $pass, $fail;
    if ($cond) { $pass++; echo "  \033[32m✓\033[0m $msg\n"; }
    else       { $fail++; echo "  \033[31m✗ $msg\033[0m\n"; }
}
function section($t) { echo "\n\033[1m$t\033[0m\n"; }

echo "\033[1mNemesis Shield - vulnerability awareness\033[0m\n";

section('1 · Inventory of installed plugins + themes');
$GLOBALS['ns_plugins'] = array(
    'akismet/akismet.php' => array('Name' => 'Akismet', 'Version' => '5.3'),
    'hello.php'           => array('Name' => 'Hello Dolly', 'Version' => '1.7.2'),
);
$theme = new class { public function get($k) { return $k === 'Name' ? 'Twenty Twenty-Four' : '1.0'; } };
$GLOBALS['ns_themes'] = array('twentytwentyfour' => $theme);
$inv = Nemesis_Shield_Vulns::inventory();
ok(count($inv) === 3, 'inventory lists 2 plugins + 1 theme (' . count($inv) . ')');
$names = array_map(function ($i) { return $i['name']; }, $inv);
ok(in_array('Akismet', $names, true) && in_array('Twenty Twenty-Four', $names, true), 'names captured');

section('2 · Locally-detected outdated components (no account needed)');
$upd = new stdClass();
$upd->Name = 'Akismet';
$upd->Version = '5.3';
$upd->update = (object) array('new_version' => '5.4');
$GLOBALS['ns_plugin_updates'] = array('akismet/akismet.php' => $upd);
$out = Nemesis_Shield_Vulns::outdated();
ok(count($out) === 1 && $out[0]['new'] === '5.4', 'flags Akismet 5.3 -> 5.4');

section('3 · Cached service advisories parse + risk count');
update_option('nemesis_shield_vulns', array('ts' => '2026-07-31 00:00:00', 'advisories' => array(
    array('name' => 'Some Plugin', 'severity' => 'high', 'title' => 'SQLi in v1.0', 'fixed_in' => '1.1', 'url' => 'https://example.com/cve'),
)));
$adv = Nemesis_Shield_Vulns::cached();
ok(count($adv) === 1 && $adv[0]['severity'] === 'high', 'cached advisory parsed');
ok(Nemesis_Shield_Vulns::cached_at() === '2026-07-31 00:00:00', 'cached_at returns the timestamp');
ok(Nemesis_Shield_Vulns::risk_count() === 2, 'risk_count = 1 advisory + 1 outdated');

section('4 · Degrades gracefully with nothing cached');
delete_option('nemesis_shield_vulns');
ok(Nemesis_Shield_Vulns::cached() === array(), 'no cache -> empty advisories, no error');

echo "\n" . str_repeat('─', 52) . "\n";
if ($fail === 0) { echo "\033[32m\033[1mALL $pass VULN CHECKS PASSED\033[0m\n"; exit(0); }
echo "\033[31m\033[1m$fail FAILED\033[0m, $pass passed\n";
exit(1);
