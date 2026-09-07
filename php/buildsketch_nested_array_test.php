<?php
// Regression test for the "Array to string conversion" crash: a doubly-nested query
// param (e.g. ?filters[0][field]=x) makes $query[$k][0] itself an array, not a scalar.
// buildSketch() must not throw when that happens -- see kindOf()'s is_array($v) guard.
//
// Plain PHP CLI only *warns* on Array-to-string, it doesn't throw -- so without this
// handler the bug wouldn't actually fail this test. Laravel's own error handler
// (Illuminate\Foundation\Bootstrap\HandleExceptions::handleError) is what turns that
// warning into the fatal ErrorException seen in production; mimic it here so this test
// fails against the original code and passes against the fix.
set_error_handler(function ($severity, $message, $file, $line) {
    throw new \ErrorException($message, 0, $severity, $file, $line);
});

require __DIR__ . '/NemesisShield.php';

$cases = [
    'doubly-nested array param' => ['filters' => [['field' => 'name', 'op' => 'eq']]],
    'simple nested (PHP bracket) array param' => ['tags' => ['a', 'b']],
    'flat scalar param' => ['q' => 'shoes'],
    'empty array param' => ['empty' => []],
];

$pass = 0;
$fail = 0;
foreach ($cases as $label => $query) {
    try {
        $sketch = NemesisShield::buildSketch('GET', '/search', $query, false, 200);
        if (!is_array($sketch) || !isset($sketch['shape'])) {
            $fail++;
            echo "  FAIL  $label: buildSketch() returned an unexpected shape\n";
            continue;
        }
        $pass++;
    } catch (\Throwable $e) {
        $fail++;
        echo "  FAIL  $label: threw " . get_class($e) . ": " . $e->getMessage() . "\n";
    }
}

$total = count($cases);
echo "buildSketch nested-array regression: $pass/$total\n";
if ($fail > 0) {
    exit(1);
}
echo "ALL PASS\n";
exit(0);
