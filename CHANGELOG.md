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
