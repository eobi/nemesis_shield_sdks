<?php
// Laravel service provider - auto-registered via package discovery (extra.laravel.providers in
// composer.json). It prepends the Sentinel middleware to the global HTTP stack so protection is on
// after `composer require` with no Kernel.php edit. Set NEMESIS_TOKEN in .env; the middleware is a
// no-op until a token is present, and fail-open throughout.
namespace NemesisShield;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Support\ServiceProvider;

class NemesisShieldServiceProvider extends ServiceProvider
{
    public function boot(Kernel $kernel)
    {
        // Guard early - before the app's own middleware run (matters in enforce mode).
        $kernel->prependMiddleware(\NemesisShieldMiddleware::class);
    }
}
