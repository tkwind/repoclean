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
