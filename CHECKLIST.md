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
| 4 | python | PyPI | **`nemesis-shield`** | `pip install nemesis-shield` | [ ] | [ ] |
| 5 | go | Go modules | **`github.com/eobi/nemesis_shield_sdks/go`** | `go get github.com/eobi/nemesis_shield_sdks/go` | [ ] | [ ] |
| 6 | ruby | RubyGems | **`nemesis-shield`** | `gem install nemesis-shield` | [ ] | [ ] |
| 7 | php | Packagist | **`nemesislabs/sentinel`** | `composer require nemesislabs/sentinel` | [ ] | [ ] |
| 8 | java | Maven Central | **`xyz.nemesislabs:sentinel`** | Maven/Gradle coord | [ ] | [ ] |
| 9 | dotnet | NuGet | **`NemesisShield`** | `dotnet add package NemesisShield` | [ ] | [ ] |
| 10 | rust | crates.io | **`nemesis-shield`** | `cargo add nemesis-shield` | [ ] | [ ] |
| 11 | wordpress | WordPress.org | slug **`nemesis-shield`** | Plugins → search | [ ] | [ ] |
| — | cloudflare-supabase-proxy | (deploy template) | `nemesis-supabase-proxy` | `wrangler deploy` | n/a | n/a |

> Note (#1): node was accidentally published twice (0.2.0 then a premature 0.2.1 during a read-propagation
> lag). Both are identical code; `0.2.1` is `latest`. Not an error, just untidy.

---

## Per-registry accounts + tokens (do before publishing that package)

- [x] **npm** — org + `nmptoken` in `~/Documents/nemesis-shield/.env` (used locally, never committed)
- [ ] **PyPI** — project `nemesis-shield`; set up **Trusted Publishing (OIDC)** (no token) or an API token
- [ ] **crates.io** — login (GitHub); `CARGO_REGISTRY_TOKEN`
- [ ] **RubyGems** — account; `RUBYGEMS_API_KEY`
- [ ] **Packagist** — submit repo URL once (auto-updates on tag)
- [ ] **NuGet** — nuget.org account; `NUGET_API_KEY`
- [ ] **Maven Central** — Central Portal namespace `xyz.nemesislabs` (DNS TXT verify) + GPG key; `CENTRAL_TOKEN`
- [ ] **JSR** — scope `@nemesis-shield-autogon` (for edge); OIDC
- [ ] **WordPress.org** — submit plugin for review; then SVN access
- [ ] **Go** — nothing (proxy indexes the tag)

---

## Manifests to CREATE before those can publish

- [ ] `edge/package.json` + `edge/jsr.json` (name `@nemesis-shield-autogon/edge`) → then repoint the CF proxy import
- [ ] `ruby/nemesis-shield.gemspec`
- [ ] `dotnet/NemesisShield.csproj` (+ BouncyCastle dep, embed ml_weights.json)
- [ ] `wordpress/nemesis-shield/readme.txt` (WP format) + `assets/` (icon/banner/screenshots)
- [ ] `java/pom.xml` (groupId `xyz.nemesislabs`, GPG signing, Central Portal deploy) ← long pole
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
- [ ] PyPI (`python`) — set up Trusted Publishing, bump version, publish
- [ ] crates.io (`rust`) — polish Cargo.toml, `cargo publish`
- [ ] Packagist (`php`) — submit repo URL, tag
- [ ] Go — push `go/vX.Y.Z` tag, verify `go get`
- [ ] then: RubyGems, NuGet, edge (npm+JSR), Maven Central, WordPress.org
