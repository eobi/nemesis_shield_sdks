<?php
// Nemesis Shield — Sentinel client for PHP.
//
// Call once after you've sent the response (e.g. via register_shutdown_function):
//
//   register_shutdown_function(function () {
//     NemesisShield::observe(getenv('NEMESIS_TOKEN'));
//   });
//
// Ships only privacy-preserving metadata (method, path shape, status, authenticated?). Never ships
// request bodies. Fail-open — a Nemesis outage never affects your app.

class NemesisShield
{
    const OBSERVE_URL = 'https://shield.nemesislabs.xyz/api/v1/observe';

    // Collapse IDs so the baseline doesn't explode: /orders/123 -> /orders/{int}
    public static function pathShape(string $path): string
    {
        $path = strtok($path, '?');
        $segs = explode('/', $path);
        foreach ($segs as $i => $s) {
            if (preg_match('/^\d+$/', $s)) {
                $segs[$i] = '{int}';
            } elseif (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $s)) {
                $segs[$i] = '{uuid}';
            } elseif (preg_match('/^[0-9a-f]{16,}$/i', $s)) {
                $segs[$i] = '{hex}';
            }
        }
        return implode('/', $segs);
    }

    // Report one or more events. Fire-and-forget; swallows all errors.
    public static function report(string $token, array $events, string $endpoint = self::OBSERVE_URL): void
    {
        if ($token === '' || count($events) === 0 || !function_exists('curl_init')) {
            return;
        }
        $ch = curl_init($endpoint);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $token, 'Content-Type: application/json'],
            CURLOPT_POSTFIELDS => json_encode(['events' => $events]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 2,
            CURLOPT_CONNECTTIMEOUT => 2,
        ]);
        @curl_exec($ch);
        curl_close($ch);
    }

    // Convenience: observe the current request from PHP superglobals.
    public static function observe(string $token, string $endpoint = self::OBSERVE_URL): void
    {
        $authed = isset($_SESSION['user']) || isset($_SERVER['HTTP_AUTHORIZATION']) || isset($_COOKIE['session']);
        self::report($token, [[
            'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
            'path' => self::pathShape($_SERVER['REQUEST_URI'] ?? '/'),
            'status' => http_response_code() ?: 200,
            'authenticated' => (bool) $authed,
        ]], $endpoint);
    }
}
