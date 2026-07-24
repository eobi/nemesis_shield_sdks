# Nemesis Shield — Ruby

Native Ruby SDK for [Nemesis Shield](https://shield.nemesislabs.xyz). Learns your app's normal
behavior; in **enforce mode BLOCKS off-baseline requests** (auth bypass, path traversal, scanners,
unusual methods) before your app runs. One Rack middleware works with **Rails, Sinatra and any Rack
app**. Positive-security, fail-open, privacy-preserving.

**Rails** — `config/application.rb`:
```ruby
require "nemesis_shield"
config.middleware.use NemesisShield::Middleware, token: ENV["NEMESIS_TOKEN"]
```

**Sinatra**:
```ruby
require "nemesis_shield"
use NemesisShield::Middleware, token: ENV["NEMESIS_TOKEN"]
```

**Rack** (`config.ru`):
```ruby
require "nemesis_shield"
use NemesisShield::Middleware, token: ENV["NEMESIS_TOKEN"]
run MyApp
```

Observe (default) → learn & approve behaviors in the console → flip to **enforce** (the SDK polls the
policy in the background, no redeploy) → off-baseline requests get `403 blocked_by_nemesis_shield`.
Verified end-to-end (learn → enforce → attack) on Rails, Sinatra and Rack: legit passes (200);
attacks blocked (403).
