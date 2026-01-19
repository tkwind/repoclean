from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


# --- Default junk rules (built-in) ---

JUNK_DIRS = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".coverage",
    "htmlcov",
    ".idea",
    ".tox",
    ".nox",
    ".vscode",
    "node_modules",
    "dist",
    "build",
    ".ipynb_checkpoints",
    ".venv",
    "venv",
    ".turbo",
    ".parcel-cache",
    ".next",
    ".nuxt",
}

JUNK_FILE_EXTS = {".pyc", ".log", ".tmp", ".swp"}

JUNK_FILES = {
    ".DS_Store",
    "Thumbs.db",
}

SENSITIVE_FILES = {
    ".env",
    "id_rsa",
    "id_dsa",
}

SENSITIVE_EXTENSIONS = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
}

DEFAULT_MAX_FILE_MB = 25


@dataclass(frozen=True)
class JunkRules:
    dirs: set[str]
    files: set[str]
    extensions: set[str]


def _normalize_ext(e: str) -> str:
    e = (e or "").strip()
    if not e:
        return ""
    if not e.startswith("."):
        e = "." + e
    return e.lower()


def _normalize_name(s: str) -> str:
    return (s or "").strip()


def get_effective_junk_rules(config=None) -> JunkRules:
    """
    Merge built-in junk rules with config overrides.
    Users ADD to the default sets; they don't replace them.

    This keeps behavior stable and avoids accidentally weakening repoclean
    just because user config is incomplete.
    """
    dirs = set(JUNK_DIRS)
    files = set(JUNK_FILES)
    exts = {x.lower() for x in JUNK_FILE_EXTS}

    if not config:
        return JunkRules(dirs=dirs, files=files, extensions=exts)

    cfg_dirs = getattr(config, "junk_dirs", None)
    cfg_files = getattr(config, "junk_files", None)
    cfg_exts = getattr(config, "junk_extensions", None)

    if cfg_dirs:
        for d in cfg_dirs:
            n = _normalize_name(d)
            if n:
                # users may put trailing slashes, normalize them away
                n = n.strip("/").strip("\\")
                if n:
                    dirs.add(n)

    if cfg_files:
        for f in cfg_files:
            n = _normalize_name(f)
            if n:
                files.add(n)

    if cfg_exts:
        for e in cfg_exts:
            n = _normalize_ext(e)
            if n:
                exts.add(n)

    return JunkRules(dirs=dirs, files=files, extensions=exts)
