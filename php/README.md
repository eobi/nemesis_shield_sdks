# Nemesis Shield — PHP

```php
require "NemesisShield.php";
register_shutdown_function(fn() => NemesisShield::observe(getenv('NEMESIS_TOKEN')));
```
Or `NemesisShield::report($token, [[ 'method'=>..., 'path'=>..., 'status'=>..., 'authenticated'=>... ]])`.
Fail-open; needs ext-curl. Token: https://shield.nemesislabs.xyz.
