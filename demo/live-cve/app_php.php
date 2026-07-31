<?php
// Live demo app — php -S router guarded by the raw PHP SDK. guard() blocks off-baseline before the
// app runs; observe() records at shutdown. Run: php -S 127.0.0.1:8802 app_php.php
require __DIR__ . '/../../php/NemesisShield.php';
$token = getenv('NEMESIS_TOKEN');
register_shutdown_function(function () use ($token) { NemesisShield::observe($token); });
if (NemesisShield::guard($token)) return true; // guard emitted a 403
header('Content-Type: text/plain');
echo 'ok';
return true;
