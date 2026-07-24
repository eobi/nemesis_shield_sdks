# Nemesis Shield — Ruby

```ruby
require_relative "nemesis_shield"
use NemesisShield::Middleware, token: ENV["NEMESIS_TOKEN"]   # Rack (Rails/Sinatra)
```
Or `NemesisShield.report(token, [{ method:, path:, status:, authenticated: }])`. Fail-open.
Token: https://shield.nemesislabs.xyz.
