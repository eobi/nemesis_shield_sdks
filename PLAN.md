# Nemesis Shield SDKs — Publishing Plan

Goal: every SDK live on its native registry so a developer just runs `npm i` / `pip install` / `go get` /
`gem install` / `composer require` / `dotnet add package` / `cargo add` / a Maven coordinate / a WordPress
plugin search, and picks it up with zero manual steps.

There are **11 publishable units** across **8 registries** (plus one deploy-template and one CDN pass-through).
All share ONE behavioral contract (identical `ml_weights.json` + FNV-1a shape hash), so releases must be
**version-locked and parity-gated** (Section 3).

---

## 1. Target registries + package identity

| SDK dir | Registry | Package id / coordinate | Install command | Status (live) |
|---|---|---|---|---|
| `node` | **npm** | `@nemesis-shield-autogon/sentinel` | `npm i @nemesis-shield-autogon/sentinel` | ✅ **PUBLISHED** v0.2.2 · pull-verified |
| `browser` | **npm** (+ CDN) | `@nemesis-shield-autogon/browser` | `npm i @nemesis-shield-autogon/browser` / unpkg | ✅ **PUBLISHED** v0.1.1 · pull-verified |
| `edge` | **npm** + **JSR** | `@nemesis-shield-autogon/edge` | `npm i @nemesis-shield-autogon/edge` / `jsr add @nemesis-shield-autogon/edge` | ⏳ pending — needs package.json (+ jsr.json) |
| `python` | **PyPI** | `nemesis-shield` | `pip install nemesis-shield` | ✅ **PUBLISHED** v0.1.1 · pull-verified |
| `go` | **Go modules** (proxy) | `github.com/eobi/nemesis_shield_sdks/go` | `go get github.com/eobi/nemesis_shield_sdks/go` | ✅ **PUBLISHED** tag `go/v0.1.0` · proxy-verified |
| `ruby` | **RubyGems** | `nemesis-shield` | `gem install nemesis-shield` | ✅ **PUBLISHED** v0.1.0 · gemspec + pull-verified |
| `php` | **Packagist** | `nemesislabs/sentinel` | `composer require nemesislabs/sentinel` | ✅ **PUBLISHED** v0.1.0 · split repo (eobi/nemesis-shield-php) · pull-verified |
| `java` | **Maven Central** | `io.github.eobi:sentinel` | Maven/Gradle coordinate | ✅ **PUBLISHED** v0.1.0 · Central-pull-verified · live-tested Raw HttpServer + Spring Boot |
| `dotnet` | **NuGet** | `NemesisShield` | `dotnet add package NemesisShield` | ✅ **PUBLISHED** v0.1.1 via Trusted Publishing (OIDC, keyless) — validating/indexing; multi-target net8.0+netstandard2.0, deep ASP.NET Core tested |
| `rust` | **crates.io** | `nemesis-shield` | `cargo add nemesis-shield` | ⏳ Cargo.toml ready (v0.1.0) — not yet pushed to crates.io |
| `wordpress` | **WordPress.org** | slug `nemesis-shield` | Plugins → search "Nemesis Shield" | ⏳ pending — needs `readme.txt` (WP format) + assets + SVN |
| `cloudflare-supabase-proxy` | not a package | deploy template | `wrangler deploy` (see note) | template only (ships via GitHub) |

Note on the CF proxy: it `import`s `../../edge/nemesis-shield.ts` relatively, so it is a **deploy template**,
not a registry artifact. Ship it via GitHub (a `degit`/template repo or the `examples`), and once `@nemesis-shield-autogon/edge`
is on npm/JSR, change its import to the published package so it stands alone. The browser SDK needs no separate
CDN publish: once on npm it is automatically served by unpkg/jsdelivr (`https://unpkg.com/@nemesis-shield-autogon/browser`).

---

## 2. One-time accounts, namespaces + org setup (do these first)

Reserve every name up front so nobody squats them, even before the code is 100% polished.

| Registry | Account / namespace to create | Auth artifact for CI |
|---|---|---|
| npm | Org **`nemesis-shield-autogon`** (npmjs.com, created ✓) → owns `@nemesis-shield-autogon/*` | `NPM_TOKEN` (Automation token) |
| JSR (jsr.io) | Scope **`@nemesis-shield-autogon`** (GitHub-linked, for the edge SDK) | OIDC (GitHub Actions, no token) |
| PyPI | Project **`nemesis-shield`** | **Trusted Publisher (OIDC)** — no token needed |
| crates.io | Login (GitHub), reserve `nemesis-shield` on first publish | `CARGO_REGISTRY_TOKEN` |
| Packagist | Submit repo URL once; auto-updates on tag via webhook | none (GitHub App) |
| Go | nothing — `proxy.golang.org` indexes any public tag | none |
| RubyGems | Account, reserve `nemesis-shield` | `RUBYGEMS_API_KEY` |
| Maven Central | **Central Portal** (central.sonatype.com) namespace `io.github.eobi` (verify via a public GitHub repo, no DNS) + a **GPG key** published to keyservers | `CENTRAL_TOKEN` + `GPG_PRIVATE_KEY` + `GPG_PASSPHRASE` |
| NuGet | nuget.org account, reserve `NemesisShield` (ID prefix optional) | `NUGET_API_KEY` |
| WordPress.org | Submit plugin at wordpress.org/plugins/developers for **manual review** (can take days–weeks); then SVN commit access | SVN user/pass (`SVN_USER`, `SVN_PASS`) |

Store every token as a **GitHub Actions repo secret** (Settings → Secrets → Actions) so the release workflow
in Section 4 can publish unattended.

---

## 3. Versioning + the parity gate (critical, because the SDKs must stay identical)

- **Single version across all SDKs.** A published version = a specific wire/parity contract. Cut a release by
  bumping every manifest to the same `X.Y.Z` and tagging `vX.Y.Z`. Recommend starting the first coordinated
  release at **`0.3.0`** (node is already ahead at 0.2.0) so every package lands on the same number.
- **Parity gate — must pass before ANY publish.** Every language pins the same reference digests
  (`fnv1a("abc")=="1a47e90b"`, shape `"809cc854"`, LLM shape `"b7b2bb5b"`, etc.) and ships a byte-identical
  `ml_weights.json` (sha256 `e206c66c…ec0b0c`). The release workflow runs all language test suites +
  `sha256sum */**/ml_weights.json | uniq` and **aborts if any digest or hash diverges**. Never publish a
  package whose `ml_weights.json` or shape hash differs from the others.
- Keep a `CHANGELOG.md` at the root; one entry per coordinated release.

---

## 4. Automated release: one tag → all registries

Add `.github/workflows/release.yml`, triggered on `push: tags: ['v*']`, with one job per registry (they run in
parallel; a failure in one does not block the others). Sketch:

```yaml
name: release
on: { push: { tags: ['v*'] } }
jobs:
  parity:            # GATE — runs first, others `needs: parity`
    runs-on: ubuntu-latest
    steps: [ checkout, run all language test suites, verify identical ml_weights.json sha256 + shape vectors ]

  npm-node:          needs: parity; publish node + browser (+ edge once packaged) with `npm publish --access public`
  jsr-edge:          needs: parity; `npx jsr publish` (OIDC)
  pypi:              needs: parity; `python -m build && twine upload` OR PyPI Trusted Publishing (OIDC)
  crates:            needs: parity; `cargo publish -p nemesis-shield`
  rubygems:          needs: parity; `gem build *.gemspec && gem push`
  nuget:             needs: parity; `dotnet pack -c Release && dotnet nuget push`
  maven:             needs: parity; `mvn -B deploy` (signed) to the Central Portal
  go:                needs: parity; no publish — the `vX.Y.Z` tag is the release (proxy picks it up)
  packagist:         no job — Packagist auto-ingests the new tag via its GitHub webhook
```

Per-registry publish specifics:
- **npm (scoped):** `--access public` is REQUIRED for a free `@nemesis-shield-autogon/*` package. Set
  `registry-url` in `actions/setup-node` and `NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}`.
- **PyPI:** prefer **Trusted Publishing** (configure the GitHub repo/workflow as a publisher on PyPI) so no
  long-lived token is stored. Build with `python -m build`, publish with `pypa/gh-action-pypi-publish`.
- **crates.io:** `cargo publish` needs `CARGO_REGISTRY_TOKEN`; the name is claimed on first successful publish.
- **Maven Central:** the heaviest. Sign artifacts with GPG (`maven-gpg-plugin`), publish to the Central Portal
  (`central-publishing-maven-plugin`), namespace `io.github.eobi` verified via a
  public GitHub repo named the verification key. Budget extra setup time here.
- **NuGet:** `dotnet nuget push bin/Release/*.nupkg -k $NUGET_API_KEY -s https://api.nuget.org/v3/index.json`.
- **Go:** the module is already `github.com/eobi/nemesis_shield_sdks/go`; a subdir module is released by a
  **path-prefixed tag** `go/vX.Y.Z` (in addition to the top-level `vX.Y.Z`). Then
  `go get github.com/eobi/nemesis_shield_sdks/go@vX.Y.Z`.
- **Packagist:** one-time submit of the repo URL; thereafter every git tag is auto-published. Ensure
  `composer.json` has `"version"` omitted (Packagist derives it from tags) and correct `autoload`.

---

## 5. What must be CREATED before first publish (the gaps)

Ordered easiest → hardest:

1. **`edge/package.json`** (npm) + **`edge/jsr.json`** (JSR) — name `@nemesis-shield-autogon/edge`, `type: module`,
   `exports` → `nemesis-shield.ts` (ship TS + a compiled `.js`+`.d.ts`). Then repoint the CF proxy import.
2. **`ruby/nemesis-shield.gemspec`** — name `nemesis-shield`, summary, license MIT, `files` = the `.rb` +
   `ml_weights.json`, homepage, source_code_uri. `ruby/lib/` layout is optional but cleaner.
3. **`dotnet/NemesisShield.csproj`** — `PackageId=NemesisShield`, `TargetFramework=net8.0` (+ net6.0),
   `PackageLicenseExpression=MIT`, repo URL, embed `ml_weights.json` as content/EmbeddedResource, add the
   BouncyCastle dependency. `dotnet pack` → `.nupkg`.
4. **`wordpress/nemesis-shield/readme.txt`** — WordPress.org format (Contributors, Tags, Requires at least,
   Tested up to, Stable tag, GPLv2+ license, changelog). Add `assets/` (icon-128, banner-772x250, screenshots).
   Submit for review; publish via SVN `trunk` + `tags/X.Y.Z`.
5. **`java/pom.xml`** (Maven) — `groupId=xyz.nemesislabs`, `artifactId=sentinel`, MIT license block, `scm`,
   `developers`, sources+javadoc jars, GPG signing, Central Portal deploy plugin. (Most involved; do last.)

Also polish the READY ones:
- `python/pyproject.toml`: bump `version` off `0.0.0`, confirm `license = "MIT"`, `readme`, `urls`, and that
  `ml_weights.json` is included as package data (`[tool.setuptools.package-data]` / MANIFEST.in).
- `node/package.json`: confirm `files` includes `lib/**` + `ml_weights.json`, `exports` map for
  express/fastify/koa, `repository`, `license`, `keywords` (waf, rasp, api-security, prompt-injection).
- `browser/package.json`: confirm UMD `main` + `module` + `types` + `unpkg` fields.
- `rust/Cargo.toml`: add `description`, `license = "MIT"`, `repository`, `keywords`, `categories`, `readme`;
  ensure `ml_weights.json` is embedded (`include_bytes!` / `include_str!`) and `include = [...]` ships it.
- `php/composer.json`: confirm `license`, `autoload` (PSR-4 or classmap), `keywords`, `require` (php >=8.0,
  ext-sodium suggested), and that `ml_weights.json` ships in the package.

---

## 6. Pre-publish checklist (run per release)

- [ ] All language test suites green; **parity gate passes** (identical `ml_weights.json` sha256 + shape vectors).
- [ ] Every manifest bumped to the SAME version; `vX.Y.Z` tag created; `go/vX.Y.Z` tag created.
- [ ] Each package has: MIT license, a README that renders on the registry, `repository`/homepage links,
      keywords, and ships `ml_weights.json` in the published artifact.
- [ ] Names reserved on every registry (Section 2); tokens in GitHub secrets.
- [ ] `CHANGELOG.md` updated.
- [ ] Dry-run where supported (`npm publish --dry-run`, `cargo publish --dry-run`, `python -m build` + `twine check`).

---

## 7. Suggested first-release order (fastest developer payoff first)

1. **npm** (node + browser) — biggest audience, already packaged. Reserve `@nemesis-shield` org, publish.
2. **PyPI** (python) — set up Trusted Publishing, bump version, publish `nemesis-shield`.
3. **crates.io** (rust) — polish Cargo.toml, `cargo publish`.
4. **Packagist** (php) — submit repo URL once; tag.
5. **Go** — push the `go/vX.Y.Z` tag; verify `go get`.
6. **RubyGems** — write the gemspec, publish.
7. **NuGet** — write the csproj, `dotnet pack`/push.
8. **JSR + npm** (edge) — package it, repoint the CF proxy.
9. **Maven Central** (java) — the long pole (namespace verification + GPG); start the account setup early,
   publish when ready.
10. **WordPress.org** — submit for review early (approval is slow); ship the zip via GitHub releases +
    the website in the meantime so it is installable before the directory listing lands.

Once 1–5 are live, the majority of developers (`npm`, `pip`, `cargo`, `composer`, `go get`) can already
`install` and pick it up — which is the goal. The rest follow as their manifests land.
