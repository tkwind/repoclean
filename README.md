

![PyPI](https://img.shields.io/pypi/v/repoclean-cli)
![License](https://img.shields.io/github/license/tkwind/repoclean)
![CI](https://github.com/tkwind/repoclean/actions/workflows/repoclean.yml/badge.svg)

# repoclean

A repo hygiene CLI tool to scan repositories for common junk artifacts, detect secret/token patterns, and optionally install a git pre-commit hook to prevent leaks.

## Why repoclean exists

Most developers (especially students) accidentally commit junk and sensitive files at least once:

- `__pycache__/`, `*.pyc`, `venv/`, `node_modules/`
- `.env` files
- API keys/tokens and private keys

These mistakes are common, embarrassing, and sometimes expensive.

`repoclean` is a small CLI tool meant to be run before pushing to GitHub. It helps you quickly:

- spot repo hygiene issues
- detect secret/token patterns
- block accidental leaks via an optional git pre-commit hook

## Install

```bash
pip install repoclean-cli
```

## Quick Start

<pre class="overflow-visible! px-0!" data-start="761" data-end="805"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-[calc(--spacing(9)+var(--header-height))] @w-xl/main:top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>repoclean scan
repoclean secrets
</span></span></code></div></div></pre>

## CI usage

repoclean ci
repoclean scan --fail-on sensitive,large
repoclean secrets --fail

## Typical workflow

<pre class="overflow-visible! px-0!" data-start="828" data-end="922"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-[calc(--spacing(9)+var(--header-height))] @w-xl/main:top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>repoclean scan
repoclean secrets --fail
repoclean fix --</span><span>yes</span><span>
repoclean install-hook
</span></span></code></div></div></pre>

## Commands

### Scan repo hygiene issues

<pre class="overflow-visible! px-0!" data-start="966" data-end="992"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-[calc(--spacing(9)+var(--header-height))] @w-xl/main:top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>repoclean scan
</span></span></code></div></div></pre>

### Create a default .gitignore

<pre class="overflow-visible! px-0!" data-start="1026" data-end="1052"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-[calc(--spacing(9)+var(--header-height))] @w-xl/main:top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>repoclean init
</span></span></code></div></div></pre>

### Safely clean junk files/folders

Preview:

<pre class="overflow-visible! px-0!" data-start="1100" data-end="1145"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-[calc(--spacing(9)+var(--header-height))] @w-xl/main:top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>repoclean fix --dry-run --verbose
</span></span></code></div></div></pre>

Apply cleanup:

<pre class="overflow-visible! px-0!" data-start="1162" data-end="1193"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-[calc(--spacing(9)+var(--header-height))] @w-xl/main:top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>repoclean fix --</span><span>yes</span><span>
</span></span></code></div></div></pre>

### Scan for secrets/tokens

<pre class="overflow-visible! px-0!" data-start="1223" data-end="1252"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-[calc(--spacing(9)+var(--header-height))] @w-xl/main:top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>repoclean secrets
</span></span></code></div></div></pre>

Fail mode (useful for CI and hooks):

<pre class="overflow-visible! px-0!" data-start="1291" data-end="1327"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-[calc(--spacing(9)+var(--header-height))] @w-xl/main:top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>repoclean secrets --fail
</span></span></code></div></div></pre>

### Install git pre-commit hook

<pre class="overflow-visible! px-0!" data-start="1361" data-end="1395"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-[calc(--spacing(9)+var(--header-height))] @w-xl/main:top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>repoclean install-hook
</span></span></code></div></div></pre>

Uninstall:

<pre class="overflow-visible! px-0!" data-start="1408" data-end="1444"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-[calc(--spacing(9)+var(--header-height))] @w-xl/main:top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>repoclean uninstall-hook
</span></span></code></div></div></pre>

## Notes

* `repoclean` is the command name.
* The PyPI package name is `repoclean-cli`.
