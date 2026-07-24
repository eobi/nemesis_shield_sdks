<?php
// Laravel middleware. Register in app/Http/Kernel.php (or bootstrap/app.php middleware) and set
// NEMESIS_TOKEN. Blocks off-baseline requests in enforce mode; records every request.
require_once __DIR__ . '/NemesisShield.php';

class NemesisShieldMiddleware
{
    public function handle($request, \Closure $next)
    {
        $token = getenv('NEMESIS_TOKEN') ?: '';
        if ($token === '') return $next($request);
        $method = $request->method();
        $path = '/' . ltrim($request->path(), '/');
        $query = $request->query();
        $authed = (bool)($request->header('Authorization') || $request->header('Cookie'));
        // pre-dispatch block
        if (NemesisShield::guard($token, $method, $path, $query, $authed)) {
            return response()->json(['error' => 'blocked_by_nemesis_shield'], 403);
        }
        $response = $next($request);
        NemesisShield::observe($token, $method, $path, $query, $authed, $response->getStatusCode());
        return $response;
    }
}
