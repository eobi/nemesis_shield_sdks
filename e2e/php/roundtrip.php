<?php
// E2E live round-trip for the PHP SDK. Builds a real sketch per fixed route via the SDK's own
// buildSketch, prints the shape hash, then POSTs the batch to the LIVE sketches endpoint.
require __DIR__ . '/NemesisShield.php';

$token = getenv('NEMESIS_TOKEN') ?: '';
$endpoint = 'https://shield.nemesislabs.xyz/api/v1/sketches';
$routes = [
    ['GET', '/app/incidents/inc_ip_1_2_3_4_1786400000000'],
    ['GET', '/app/network/autogon.ai'],
    ['GET', '/app/applications/f47ac10b-58cc-4372-a567-0e02b2c3d479'],
];

$sketches = [];
foreach ($routes as $r) {
    $s = NemesisShield::buildSketch($r[0], $r[1], [], false, 200);
    echo "SHAPE {$r[1]} route={$s['route']} hash={$s['shape']}\n";
    $sketches[] = $s;
}

$body = json_encode(['sketches' => $sketches]);
$ctx = stream_context_create([
    'http' => [
        'method' => 'POST',
        'header' => "Authorization: Bearer {$token}\r\nContent-Type: application/json\r\n",
        'content' => $body,
        'ignore_errors' => true,
        'timeout' => 15,
    ],
]);
$resp = @file_get_contents($endpoint, false, $ctx);
$code = 0;
if (isset($http_response_header) && preg_match('/\s(\d{3})\s/', $http_response_header[0], $m)) {
    $code = (int) $m[1];
}
echo "POST_STATUS {$code}\n";
