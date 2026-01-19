# Changelog

## v0.2.1

- Published package to PyPI as `repoclean-cli`
- Added secret scanning and git hook support

## v0.3.0

- Added .repoclean.toml configuration support
- Added ignore rules for scan/secrets/fix
- Added allowlist paths for secrets scan
- Added repoclean config init command

## v0.4.0

- Added scan gating via `--fail-on` (junk/sensitive/large)
- Added `repoclean ci` command for CI pipelines with correct exit codes

## v0.5.0

- Improved pre-commit hook with strict/warn modes
- Hook now runs `repoclean ci --json`
- Added `repoclean hook status` and `repoclean hook print`
- Hook metadata stored in `.git/repoclean_hook.toml`

## v0.5.1

- Fixed pre-commit hook execution on Windows by using a shell wrapper that invokes Python

## v0.5.2

- Fixed missing tomli dependency on Python 3.10 (GitHub Actions install issue)

## v0.6.0

* Added severity levels (`low/medium/high/critical`)
* Added entropy detection for suspicious high-randomness tokens
* Added support for more real-world token patterns (GitHub, Slack, Stripe, Telegram, JWT, etc.)
* Added `--min-severity` and `--fail-on` flags for CI/hook workflows

## v0.7.0


* Added `--staged-only` mode for repo scanning/cleanup (only checks files staged for commit)
* Added `repoclean fix --staged-only` to safely remove junk artifacts from the staged set
* **Auto-unstage behavior:** when `fix --staged-only` deletes a staged junk file, repoclean now:
  * removes it from git index (`git rm --cached …` fallback)
  * stages deletion updates correctly (`git add -u`)
  * prevents “commit contains deleted blob” / mismatch issues
* Pre-commit hook now runs **staged-only CI checks** for speed + relevance
* Strict mode hook blocks commits on:
  * secrets
  * junk artifacts
  * sensitive files
  * large files
* Warn mode hook blocks only on secrets (allows commit otherwise)
* Improved junk rules coverage (`.log/.tmp/.swp`, caches, build artifacts etc.)
