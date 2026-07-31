# Publishing Checklist — names + status

Live tracker for pushing every SDK to its registry. See `PLAN.md` for the full how-to.
Legend: `[x]` done · `[ ]` not yet.

## npm account (done)
- [x] npm org **`nemesis-shield-autogon`** created (owner account: **obiebukadavid**)
- [x] scope decided: **`@nemesis-shield-autogon`** (the org name IS the scope; `@nemesis-shield` was taken)
- [x] repo-wide rename `@nemesis-shield/*` → `@nemesis-shield-autogon/*` (manifests, READMEs, imports, PLAN)
- [x] `.npmrc` added to `.gitignore` (never commit a token)

---

## Packages — exact name + status

| # | SDK | Registry | Package name (final) | Install | Published? | Pull-tested? |
|---|-----|----------|----------------------|---------|-----------|--------------|
| 1 | node | npm | **`@nemesis-shield-autogon/sentinel`** | `npm i @nemesis-shield-autogon/sentinel` | ✅ 0.2.0 + 0.2.1 | ✅ works |
| 2 | browser | npm | **`@nemesis-shield-autogon/browser`** | `npm i @nemesis-shield-autogon/browser` | ✅ 0.1.0 | ✅ works |
| 3 | edge | npm + JSR | **`@nemesis-shield-autogon/edge`** | `npm i @nemesis-shield-autogon/edge` | [ ] | [ ] |
| 4 | python | PyPI | **`nemesis-shield`** (v0.1.0) | `pip install nemesis-shield` | ✅ 0.1.0 | ✅ works |
| 5 | go | Go modules | **`github.com/eobi/nemesis_shield_sdks/go`** (tag `go/v0.1.0`) | `go get github.com/eobi/nemesis_shield_sdks/go` | ✅ go/v0.1.0 | ✅ works |
| 6 | ruby | RubyGems | **`nemesis-shield`** (v0.1.0) | `gem install nemesis-shield` | ✅ 0.1.0 | ✅ works |
| 7 | php | Packagist | **`nemesislabs/sentinel`** (v0.1.0) | `composer require nemesislabs/sentinel` | ✅ 0.1.0 | ✅ works |
| 8 | java | Maven Central | **`io.github.eobi:sentinel`** (v0.1.1) | Maven/Gradle coord | ✅ 0.1.1 (canonical) | ✅ works |
| 9 | dotnet | NuGet | **`NemesisShield`** (v0.1.1) | `dotnet add package NemesisShield` | ✅ pushed (validating) | ⏳ |
| 10 | rust | crates.io | **`nemesis-shield`** | `cargo add nemesis-shield` | [ ] | [ ] |
| 11 | wordpress | WordPress.org | slug **`nemesis-shield`** | Plugins → search | [ ] | [ ] |
| — | cloudflare-supabase-proxy | (deploy template) | `nemesis-supabase-proxy` | `wrangler deploy` | n/a | n/a |

> Note (#1): node was accidentally published twice (0.2.0 then a premature 0.2.1 during a read-propagation
> lag). Both are identical code; `0.2.1` is `latest`. Not an error, just untidy.

---

## Per-registry accounts + tokens (do before publishing that package)

- [x] **npm** — org + `nmptoken` in `~/Documents/nemesis-shield/.env` (used locally, never committed)
- [x] **PyPI** — project `nemesis-shield` published with `__token__` API token (`pypi_*` in `~/Documents/nemesis-shield/.env`, used locally)
- [ ] **crates.io** — login (GitHub); `CARGO_REGISTRY_TOKEN`
- [x] **RubyGems** — published with `rubygems` API key in `~/Documents/nemesis-shield/.env` (used locally); MFA lowered to UI-only for the push
- [x] **Packagist** — split repo github.com/eobi/nemesis-shield-php submitted; auto-updates on tag
- [ ] **NuGet** — nuget.org account; `NUGET_API_KEY`
- [x] **Maven Central** — io.github.eobi verified (GitHub), GPG key on keyserver.ubuntu.com, published via Central Portal token (`maven_java_*` in .env)
- [ ] **JSR** — scope `@nemesis-shield-autogon` (for edge); OIDC
- [ ] **WordPress.org** — submit plugin for review; then SVN access
- [x] **Go** — no account/token; `go/v0.1.0` tag pushed, proxy indexed, `go get` verified

---

## Manifests to CREATE before those can publish

- [ ] `edge/package.json` + `edge/jsr.json` (name `@nemesis-shield-autogon/edge`) → then repoint the CF proxy import
- [x] `ruby/nemesis-shield.gemspec` (done; flat layout, ships ml_weights.json)
- [ ] `dotnet/NemesisShield.csproj` (+ BouncyCastle dep, embed ml_weights.json)
- [ ] `wordpress/nemesis-shield/readme.txt` (WP format) + `assets/` (icon/banner/screenshots)
- [x] `java/pom.xml` (Maven module, groupId io.github.eobi, GPG + Central Portal release profile) — built+tested
- [ ] polish READY manifests: bump `python` off 0.0.0; confirm `rust`/`php` ship `ml_weights.json`

---

## Release hygiene (every coordinated release)

- [ ] all language test suites green
- [ ] **parity gate**: identical `ml_weights.json` sha256 (`e206c66c…ec0b0c`) + shape vectors across all SDKs
- [ ] every manifest on the SAME version; tag `vX.Y.Z` (+ `go/vX.Y.Z`)
- [ ] `CHANGELOG.md` updated
- [ ] verify AFTER publish (never query a package's read URL before publishing — it caches a 404 at the CDN)

---

## Next up (fastest developer payoff)
- [x] PyPI (`python`) — published `nemesis-shield` 0.1.0, pull-verified (parity + ml_weights sha256 match)
- [ ] crates.io (`rust`) — polish Cargo.toml, `cargo publish`
- [x] Packagist (`php`) — published nemesislabs/sentinel 0.1.0 via split repo, pull-verified (parity + allow-list)
- [x] Go — `go/v0.1.0` tag pushed + proxy-verified (`go get` works, embedded ML model matches parity vectors)
- [x] RubyGems (`ruby`) — published nemesis-shield 0.1.0, pull-verified (parity + ML guard)
- [ ] then: NuGet, edge (npm+JSR), Maven Central, WordPress.org
