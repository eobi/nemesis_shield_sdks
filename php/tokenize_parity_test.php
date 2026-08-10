<?php
// Parity test: asserts NemesisShield::normalizePath() matches the canonical vectors.
require __DIR__ . '/NemesisShield.php';

$vectorsFile = __DIR__ . '/../tokenize.vectors.json';
$data = json_decode(file_get_contents($vectorsFile), true);
$cases = $data['normalizePath'];

$pass = 0;
$fail = 0;
$failures = [];
foreach ($cases as $c) {
    $got = NemesisShield::normalizePath($c['path']);
    if ($got === $c['expect']) {
        $pass++;
    } else {
        $fail++;
        $failures[] = sprintf("  FAIL  %-55s expected=%-30s got=%s", $c['path'], $c['expect'], $got);
    }
}

$total = count($cases);
echo "normalizePath parity: $pass/$total\n";
if ($fail > 0) {
    echo implode("\n", $failures) . "\n";
    exit(1);
}
echo "ALL PASS\n";
exit(0);
