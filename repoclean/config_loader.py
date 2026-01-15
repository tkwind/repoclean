from dataclasses import dataclass, field
from pathlib import Path

import tomli


@dataclass
class RepoCleanConfig:
    max_file_mb: int = 25
    max_secret_file_kb: int = 256

    ignore_dirs: list[str] = field(default_factory=list)
    ignore_files: list[str] = field(default_factory=list)
    ignore_extensions: list[str] = field(default_factory=list)

    allow_secrets_in: list[str] = field(default_factory=list)


DEFAULT_CONFIG = RepoCleanConfig()


def load_config(repo_path: str = ".") -> RepoCleanConfig:
    repo = Path(repo_path).resolve()
    cfg_path = repo / ".repoclean.toml"

    cfg = RepoCleanConfig(
        max_file_mb=DEFAULT_CONFIG.max_file_mb,
        max_secret_file_kb=DEFAULT_CONFIG.max_secret_file_kb,
        ignore_dirs=list(DEFAULT_CONFIG.ignore_dirs),
        ignore_files=list(DEFAULT_CONFIG.ignore_files),
        ignore_extensions=list(DEFAULT_CONFIG.ignore_extensions),
        allow_secrets_in=list(DEFAULT_CONFIG.allow_secrets_in),
    )

    if not cfg_path.exists():
        return cfg

    with cfg_path.open("rb") as f:
        raw = tomli.load(f)

    section = raw.get("repoclean", {})

    cfg.max_file_mb = int(section.get("max_file_mb", cfg.max_file_mb))
    cfg.max_secret_file_kb = int(section.get("max_secret_file_kb", cfg.max_secret_file_kb))

    cfg.ignore_dirs = list(section.get("ignore_dirs", cfg.ignore_dirs))
    cfg.ignore_files = list(section.get("ignore_files", cfg.ignore_files))
    cfg.ignore_extensions = list(section.get("ignore_extensions", cfg.ignore_extensions))

    cfg.allow_secrets_in = list(section.get("allow_secrets_in", cfg.allow_secrets_in))

    return cfg
