# Publishing Nemesis Shield to WordPress.org

WordPress.org is a **two-step, manual-review** channel: submit a zip → a human reviews it (days to weeks) → you get SVN commit access → you publish via SVN. There is no API/token push like npm or crates.io.

Everything needed is already built:

- `nemesis-shield/` — the plugin (main file + vendored `lib/` + `readme.txt`)
- `assets/` — WordPress.org listing images (icon, banner, screenshots)
- `build-zip.sh` — produces `nemesis-shield.zip` (plugin only; no tests/dev files)

## One-time prerequisite

A **WordPress.org account** whose username becomes the `Contributors:` value in `readme.txt`.
`readme.txt` currently lists `nemesislabs`. If the real account username differs, update the
`Contributors:` line before submitting (it must be an existing wordpress.org login, not a display name).

## Step 1 — Build the zip

```bash
./build-zip.sh          # writes nemesis-shield.zip (re-syncs the vendored PHP SDK first)
```

Sanity-check before uploading (optional but recommended):

```bash
./run-tests.sh          # 17 checks, no Docker
```

## Step 2 — Submit for review

1. Sign in at https://wordpress.org/plugins/developers/add/
2. Upload `nemesis-shield.zip`.
3. The automated checker runs immediately; then a human reviewer follows up **by email** (reply from the same account). Typical wait: a few days to a few weeks.
4. Address any reviewer feedback by replying to that email thread (no re-upload form — you send a corrected zip in reply if asked).

The requested slug is **`nemesis-shield`** → the listing will live at
`https://wordpress.org/plugins/nemesis-shield/`.

## Step 3 — Publish via SVN (after approval only)

On approval you receive SVN commit access to `https://plugins.svn.wordpress.org/nemesis-shield/`.
The SVN layout is **not** the same as the zip: code goes in `trunk/` + `tags/X.Y.Z/`, and the
listing images go in a **separate top-level `assets/`** (never inside the plugin).

```bash
svn co https://plugins.svn.wordpress.org/nemesis-shield/ svn-nemesis-shield
cd svn-nemesis-shield

# 1. code → trunk
rsync -a --delete --exclude tests/ \
  ../nemesis_shield_sdks/wordpress/nemesis-shield/ trunk/

# 2. listing images → /assets (icon-*.png, banner-*.png, screenshot-*.png)
mkdir -p assets
cp ../nemesis_shield_sdks/wordpress/assets/icon-128x128.png \
   ../nemesis_shield_sdks/wordpress/assets/icon-256x256.png \
   ../nemesis_shield_sdks/wordpress/assets/banner-772x250.png \
   ../nemesis_shield_sdks/wordpress/assets/banner-1544x500.png \
   ../nemesis_shield_sdks/wordpress/assets/screenshot-1.png \
   ../nemesis_shield_sdks/wordpress/assets/screenshot-2.png \
   assets/

# 3. tag this release (must equal Stable tag in readme.txt = 1.0.0)
svn cp trunk tags/1.0.0

svn add --force trunk assets tags
svn ci -m "Nemesis Shield 1.0.0" --username <wporg-user>
```

The live listing updates within a few minutes of the commit. `Stable tag: 1.0.0` in
`trunk/readme.txt` is what tells WordPress.org which tag to serve, so bump it in lockstep with
each `tags/X.Y.Z`.

## Releasing a new version later

1. Bump `Version:` in `nemesis-shield/nemesis-shield.php` **and** `Stable tag:` in `readme.txt`, add a `== Changelog ==` entry.
2. `./build-zip.sh` (optional local check).
3. `rsync` code into `trunk/`, `svn cp trunk tags/X.Y.Z`, `svn ci`.

## Notes

- **License.** The plugin is MIT (GPL-compatible), declared in both the plugin header and `readme.txt`.
- **Assets are self-contained.** Icon/banner render from `assets/src/*.svg` via `rsvg-convert`; screenshots via `assets/src/*.html` + Playwright. Re-run those if you restyle.
- **ML parity.** `build-zip.sh` re-syncs `lib/` from `../php`; the vendored `ml_weights.json` must keep sha256 `e206c66c…ec0b0c` so the WordPress verdict matches every other Nemesis Shield SDK.
