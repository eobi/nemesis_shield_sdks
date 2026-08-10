# Publishing Checklist - names + status

Live tracker for pushing every SDK to its registry. See `PLAN.md` for the full how-to.
Legend: `[x]` done · `[ ]` not yet.

## npm account (done)
- [x] npm org **`nemesis-shield-autogon`** created (owner account: **obiebukadavid**)
- [x] scope decided: **`@nemesis-shield-autogon`** (the org name IS the scope; `@nemesis-shield` was taken)
- [x] repo-wide rename `@nemesis-shield/*` → `@nemesis-shield-autogon/*` (manifests, READMEs, imports, PLAN)
- [x] `.npmrc` added to `.gitignore` (never commit a token)

---

## Packages - exact name + status

| # | SDK | Registry | Package name (final) | Install | Published? | Pull-tested? |
|---|-----|----------|----------------------|---------|-----------|--------------|
| 1 | node | npm | **`@nemesis-shield-autogon/sentinel`** | `npm i @nemesis-shield-autogon/sentinel` | ✅ 0.2.6 | ✅ works |
| 2 | browser | npm | **`@nemesis-shield-autogon/browser`** | `npm i @nemesis-shield-autogon/browser` | ✅ 0.1.1 | ✅ works |
| 3 | edge | npm + JSR | **`@nemesis-shield-autogon/edge`** | `npm i @nemesis-shield-autogon/edge` | ✅ 0.1.3 (npm) | ✅ works · JSR [ ] |
| 4 | python | PyPI | **`nemesis-shield`** (v0.1.4) | `pip install nemesis-shield` | ✅ 0.1.4 | ✅ works |
| 5 | go | Go modules | **`github.com/eobi/nemesis_shield_sdks/go`** (tag `go/v0.1.3`) | `go get github.com/eobi/nemesis_shield_sdks/go` | ✅ go/v0.1.3 | ✅ works |
| 6 | ruby | RubyGems | **`nemesis-shield`** (v0.1.3) | `gem install nemesis-shield` | ✅ 0.1.3 | ✅ works |
| 7 | php | Packagist | **`nemesislabs/sentinel`** (v0.1.3) | `composer require nemesislabs/sentinel` | ✅ 0.1.3 | ✅ works |
| 8 | java | Maven Central | **`io.github.eobi:sentinel`** (v0.1.4) | Maven/Gradle coord | ✅ 0.1.4 | ✅ works |
| 9 | dotnet | NuGet | **`NemesisShield`** (v0.1.4) | `dotnet add package NemesisShield` | ✅ 0.1.4 | ✅ works |
| 10 | rust | crates.io | **`nemesis-shield`** (v0.1.3) | `cargo add nemesis-shield` | ✅ 0.1.3 | ✅ works |
| 11 | wordpress | WordPress.org | slug **`nemesis-shield`** | Plugins → search | [ ] | [ ] |
| - | cloudflare-supabase-proxy | (deploy template) | `nemesis-supabase-proxy` | `wrangler deploy` | n/a | n/a |

> Note (#1): the `{domain}/{id}/{traversal}` tokenizer parity fix (commit `59af7cd`, 2026-08-10) was released
> across the whole fleet. The prior cohort (0.1.2/0.1.3, cut 2026-08-03) predated the fix, so each SDK was
> bumped to a version strictly above its live one and republished: node 0.2.6, rust/php/go/ruby 0.1.3,
> python/java/dotnet 0.1.4, edge 0.1.3. `browser` stayed 0.1.1 (page-shield, no path tokenizer). Registries
> had diverged (npm ahead, others at 0.1.2/0.1.3), so versions are NOT globally locked — each is correct for
> its own registry. All ship an identical `ml_weights.json` (sha256 `e206c66c…ec0b0c`) and pass 36/36 parity.

---

## Per-registry accounts + tokens (do before publishing that package)

- [x] **npm** - org + `nmptoken` in `~/Documents/nemesis-shield/.env` (used locally, never committed)
- [x] **PyPI** - project `nemesis-shield` published with `__token__` API token (`pypi_*` in `~/Documents/nemesis-shield/.env`, used locally)
- [x] **crates.io** - published with `createsio_api_token` in .env (email verified); name nemesis-shield reserved
- [x] **RubyGems** - published with `rubygems` API key in `~/Documents/nemesis-shield/.env` (used locally); MFA lowered to UI-only for the push
- [x] **Packagist** - split repo github.com/eobi/nemesis-shield-php submitted; auto-updates on tag
- [x] **NuGet** - Trusted Publishing (OIDC, keyless) policy on nuget.org (owner nemesislabs) -> .github/workflows/publish-nuget.yml; no stored key
- [x] **Maven Central** - io.github.eobi verified (GitHub), GPG key on keyserver.ubuntu.com, published via Central Portal token (`maven_java_*` in .env)
- [ ] **JSR** - scope `@nemesis-shield-autogon` (for edge); OIDC
- [ ] **WordPress.org** - submit plugin for review; then SVN access
- [x] **Go** - no account/token; `go/v0.1.0` tag pushed, proxy indexed, `go get` verified

---

## Manifests to CREATE before those can publish

- [ ] `edge/package.json` + `edge/jsr.json` (name `@nemesis-shield-autogon/edge`) → then repoint the CF proxy import
- [x] `ruby/nemesis-shield.gemspec` (done; flat layout, ships ml_weights.json)
- [ ] `dotnet/NemesisShield.csproj` (+ BouncyCastle dep, embed ml_weights.json)
- [x] `wordpress/nemesis-shield/readme.txt` (WP format) + `assets/` (icon/banner/screenshots) - built; `build-zip.sh` + `SUBMIT.md` ready. Blocked only on manual review + SVN.
- [x] `java/pom.xml` (Maven module, groupId io.github.eobi, GPG + Central Portal release profile) - built+tested
- [ ] polish READY manifests: bump `python` off 0.0.0; confirm `rust`/`php` ship `ml_weights.json`

---

## Release hygiene (every coordinated release)

- [ ] all language test suites green
- [ ] **parity gate**: identical `ml_weights.json` sha256 (`e206c66c…ec0b0c`) + shape vectors across all SDKs
- [ ] every manifest on the SAME version; tag `vX.Y.Z` (+ `go/vX.Y.Z`)
- [ ] `CHANGELOG.md` updated
- [ ] verify AFTER publish (never query a package's read URL before publishing - it caches a 404 at the CDN)

---

## Published (all live on their registries)
- [x] npm (`node`) - 0.2.6 · tokenizer parity fix
- [x] npm (`browser`) - 0.1.1 · unaffected (page-shield, no path tokenizer)
- [x] npm (`edge`) - 0.1.3 · reference tokenizer ({domain}/{id})
- [x] PyPI (`python`) - 0.1.4
- [x] crates.io (`rust`) - 0.1.3
- [x] Packagist (`php`) - 0.1.3 via split repo
- [x] Go - tag `go/v0.1.3` (resolves v0.1.3), proxy-verified
- [x] RubyGems (`ruby`) - 0.1.3
- [x] NuGet (`dotnet`) - 0.1.4 · keyless OIDC (workflow_dispatch, version input)
- [x] Maven Central (`java`) - 0.1.4 · signed, published via Central Portal

## Still open
- [ ] JSR (`edge`) - scope `@nemesis-shield-autogon` + OIDC
- [ ] WordPress.org - submit for review; then SVN
- [ ] (nice-to-have) bump `central-publishing-maven-plugin` past 0.5.0 so a successful Maven deploy stops
      exiting non-zero on the new `warnings` API field
