# Repoclean (CLI) v0.8.0

![PyPI](https://img.shields.io/pypi/v/repoclean-cli)
![License](https://img.shields.io/github/license/tkwind/repoclean)
![CI](https://github.com/tkwind/repoclean/actions/workflows/repoclean.yml/badge.svg)

repoclean — Git repo hygiene scanner + secrets detector + pre-commit gatekeeper.

It prevents:

- accidental API key/token leaks
- committing junk artifacts (`__pycache__/`, `.log`, `.tmp`, etc.)
- committing sensitive files (`.env`, keys)
- bloating git history with large files
- tracked junk already inside git history

It can also act as a **gatekeeper**:

- prints a health score (0–100)
- blocks risky commits (optional git pre-commit hook)
- CI-friendly JSON output

## Why repoclean exists

Most leaks don’t happen because people are careless — they happen because shipping is fast and repo hygiene is manual.

repoclean is a small CLI tool that acts like a repo bodyguard:

- fast hygiene scan
- scary-good secrets detection (real-world token patterns + entropy detection)
- optional git hook that blocks commits automatically
- staged-only mode so checks stay fast and relevant

## Demo

![repoclean demo](assets/demo.gif)

## Install

```bash
pip install repoclean-cli
```

## Quick Start

```bash
repoclean scan
repoclean secrets
repoclean gate
```



```md
## Secrets scanner (v0.6.0)

repoclean detects:
- Private key markers (`BEGIN PRIVATE KEY`)
- GitHub tokens (`ghp_`, `github_pat_`, `gho_`)
- Slack tokens (`xoxb-...`)
- Stripe live keys (`sk_live_...`)
- Telegram bot tokens (`123456:ABC...`)
- JWT tokens
- High entropy secret candidates in assignment contexts
```

## Recommended: Install commit hook (strict blocks commit on issues):

```bash
repoclean install-hook --mode strict

```

## CI usage

```bash
repoclean ci
repoclean scan --fail-on sensitive,large
repoclean secrets --fail
```

## Typical workflow

```bash
repoclean scan
repoclean secrets --fail
repoclean fix --yes
repoclean install-hook --mode strict
```

# Secrets severity + CI

```bash
repoclean secrets --min-severity high
repoclean secrets --fail-on critical
repoclean ci --json
```

#### The CI command supports `--fail-on` categories:

* secrets
* junk
* sensitive
* large
* tracked-junk
* gitignore
* env

# Command

##### Scan repo hygiene issues

```bash
repoclean scan
```

##### Create a default .gitignore

```bash
repoclean init
```

##### Config

Create a .repoclean.toml config file:

```bash
repoclean config init
```

##### Safely clean junk files/folders

Preview:

```bash
repoclean fix --dry-run --verbose
```

Apply cleanup:

```bash
repoclean fix --yes
```



```md
### Unstage instead of delete

```bash
repoclean fix --staged-only --unstage --yes
```


##### Scan for secrets/tokens

```bash
repoclean secrets
```

Fail mode (useful for CI and hooks):

```bash
repoclean secrets --fail
```

#### repoclean detects:

* GitHub tokens (`ghp_`, `github_pat_`, `gho_`)
* Slack tokens (`xoxb-...`)
* Stripe live keys (`sk_live_...`)
* Telegram bot tokens (`123456:ABC...`)
* JWT tokens
* OpenAI keys
* AWS secret access keys
* Google API keys
* high-entropy tokens in assignment contexts

## Install git pre-commit hook

##### Install (strict mode blocks commit on issues):

```bash
repoclean install-hook --mode strict
```

Strict mode blocks commits on:

* secrets
* junk artifacts
* sensitive files
* large files

##### Install (warn mode prints warnings but allows commit):

```bash
repoclean install-hook --mode warn
```

Warn mode blocks only secrets

##### Uninstall:

```bash
repoclean uninstall-hook
```

##### Hook utilities:

```bash
repoclean hook status
repoclean hook print --mode warn
repoclean hook print --mode strict
```

## Notes

* repoclean is the command name.
* The PyPI package name is repoclean-cli.
