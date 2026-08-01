<?php
// In-process test for the brute-force login guard. The main harness spawns a child per request, so
// per-IP counters (transients) can't persist across it; this exercises the module in one process where
// the stubbed transient/option stores persist, which is what the lockout logic needs.

error_reporting(E_ALL & ~E_DEPRECATED);
require __DIR__ . '/wp-stubs.php';
require dirname(__DIR__) . '/nemesis-shield/lib/class-login-guard.php';

$pass = 0; $fail = 0;
function ok($cond, $msg) {
    global $pass, $fail;
    if ($cond) { $pass++; echo "  \033[32m✓\033[0m $msg\n"; }
    else       { $fail++; echo "  \033[31m✗ $msg\033[0m\n"; }
}
function section($t) { echo "\n\033[1m$t\033[0m\n"; }

echo "\033[1mNemesis Shield — brute-force login guard\033[0m\n";

// Defaults: 5 attempts, then lock. Enable explicitly (default is on anyway).
update_option('nemesis_shield_options', array('login_guard' => '1', 'lg_max' => 5, 'lg_window' => 900, 'lg_lockout' => 1800));
$_SERVER['REMOTE_ADDR'] = '203.0.113.5';
$ip = Nemesis_Shield_Login_Guard::client_ip();

section('1 · Counts failures and locks at the threshold');
ok(!Nemesis_Shield_Login_Guard::is_locked($ip), 'not locked initially');
for ($i = 1; $i <= 4; $i++) { Nemesis_Shield_Login_Guard::on_failed('admin'); }
ok(!Nemesis_Shield_Login_Guard::is_locked($ip), 'still not locked after 4 failures (< max)');
Nemesis_Shield_Login_Guard::on_failed('admin'); // 5th
ok(Nemesis_Shield_Login_Guard::is_locked($ip), 'locked after the 5th failure');

section('2 · A locked IP is refused at authenticate, before any credential check');
$r = Nemesis_Shield_Login_Guard::check_lock(null, 'admin', 'whatever');
ok(($r instanceof WP_Error) && $r->code === 'nemesis_shield_locked', 'authenticate returns a lockout WP_Error');

section('3 · Empty submit is not treated as an attempt');
$r2 = Nemesis_Shield_Login_Guard::check_lock('passthrough', '', '');
ok($r2 === 'passthrough', 'empty username+password passes through untouched');

section('4 · A successful login clears the lockout + counter');
Nemesis_Shield_Login_Guard::on_success('admin', null);
ok(!Nemesis_Shield_Login_Guard::is_locked($ip), 'unlocked after a real login');

section('5 · A different IP is unaffected by another IP\'s failures');
$_SERVER['REMOTE_ADDR'] = '198.51.100.9';
$ip2 = Nemesis_Shield_Login_Guard::client_ip();
for ($i = 1; $i <= 5; $i++) { Nemesis_Shield_Login_Guard::on_failed('admin'); }
ok(Nemesis_Shield_Login_Guard::is_locked($ip2), 'second IP locks on its own failures');
$_SERVER['REMOTE_ADDR'] = '203.0.113.5';
ok(!Nemesis_Shield_Login_Guard::is_locked(Nemesis_Shield_Login_Guard::client_ip()), 'first IP still clear (per-IP isolation)');

section('6 · Admin unlock clears a lockout');
Nemesis_Shield_Login_Guard::admin_unlock($ip2);
ok(!Nemesis_Shield_Login_Guard::is_locked($ip2), 'admin unlock releases the IP');

echo "\n" . str_repeat('─', 52) . "\n";
if ($fail === 0) { echo "\033[32m\033[1mALL $pass LOGIN-GUARD CHECKS PASSED\033[0m\n"; exit(0); }
echo "\033[31m\033[1m$fail FAILED\033[0m, $pass passed\n";
exit(1);
