<?php
// Mock Nemesis Shield sketches endpoint for the WordPress plugin tests. Records
// every posted sketch (ndjson) and serves a policy the test controls (a JSON file
// it rewrites between phases). Run:  php -S 127.0.0.1:PORT tests/mock-shield.php
//
// Env:
//   NEMESIS_MOCK_POLICY  path to the policy JSON the mock returns
//   NEMESIS_MOCK_RECORD  path to append received sketches to (one JSON per line)

$policyFile = getenv('NEMESIS_MOCK_POLICY') ?: (sys_get_temp_dir() . '/ns_policy.json');
$recordFile = getenv('NEMESIS_MOCK_RECORD') ?: (sys_get_temp_dir() . '/ns_record.ndjson');

$in = json_decode(file_get_contents('php://input'), true);
$sketches = (is_array($in) && isset($in['sketches']) && is_array($in['sketches'])) ? $in['sketches'] : array();
foreach ($sketches as $s) {
    if (!empty($s)) {
        file_put_contents($recordFile, json_encode($s) . "\n", FILE_APPEND | LOCK_EX);
    }
}

$policy = array('mode' => 'observe', 'policy' => array('shapes' => new stdClass(), 'knownBad' => array()));
if (is_file($policyFile)) {
    $p = json_decode(file_get_contents($policyFile), true);
    if (is_array($p)) {
        $policy = $p;
    }
}

header('Content-Type: application/json');
echo json_encode($policy);
