<?php
// Manual registration (Option B) — only needed if you did NOT install via Composer auto-discovery.
// In app/Http/Kernel.php, require the file and add the middleware to the GLOBAL $middleware array so
// it runs on every request. Put it FIRST so it can guard before your app's middleware in enforce mode.

require_once app_path('Nemesis/NemesisShieldMiddleware.php'); // wherever you dropped the files

class Kernel extends HttpKernel
{
    protected $middleware = [
        \NemesisShieldMiddleware::class,           // <-- add this line, first
        \App\Http\Middleware\TrustProxies::class,
        \Illuminate\Foundation\Http\Middleware\CheckForMaintenanceMode::class,
        // ... the rest of your existing global middleware ...
    ];

    // ... $middlewareGroups, $routeMiddleware unchanged ...
}

// Then set the token in .env:   NEMESIS_TOKEN=nsk_your_app_token
// It starts in observe (learn-only); flip the app to enforce in the console when the baseline is approved.
