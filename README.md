![PyPI](https://img.shields.io/pypi/v/repoclean-cli)
![License](https://img.shields.io/github/license/tkwind/repoclean)
![CI](https://github.com/tkwind/repoclean/actions/workflows/repoclean.yml/badge.svg)


## Demo

![repoclean demo](assets/demo.gif)

# repoclean

A repo hygiene CLI tool to scan repositories for common junk artifacts, detect secret/token patterns, and optionally install a Git pre-commit hook to prevent leaks.

## Why repoclean exists

`repoclean` is a small CLI tool meant to be run before pushing to GitHub. It helps you quickly:

- spot repo hygiene issues
- detect secret/token patterns
- block accidental leaks via an optional Git pre-commit hook

## Install

```bash
pip install repoclean-cli
```

## Quick Start

```bash
repoclean scan
repoclean secrets
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

##### Scan for secrets/tokens

```bash
repoclean secrets
```

Fail mode (useful for CI and hooks):

```bash
repoclean secrets --fail
```

## Install git pre-commit hook

##### Install (strict mode blocks commit on issues):

```bash
repoclean install-hook --mode strict
```

##### Install (warn mode prints warnings but allows commit):

```bash
repoclean install-hook --mode warn
```

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
