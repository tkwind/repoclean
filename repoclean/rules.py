JUNK_DIRS = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".idea",
    ".vscode",
    "node_modules",
    "dist",
    "build",
    ".venv",
    "venv",
}

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
