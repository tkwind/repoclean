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
