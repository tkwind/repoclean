from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib as tomli
except ModuleNotFoundError:
    import tomli


def _as_list(x: Any) -> list[str]:
    """
    Defensive parsing:
    - if TOML gives a string, wrap it into list
    - if TOML gives None, return empty
    - otherwise cast list elements to str
    """
    if x is None:
        return []
    if isinstance(x, str):
        return [x]
    if isinstance(x, (list, tuple)):
        return [str(i) for i in x]
    return [str(x)]


def _clean_path_list(items: list[str]) -> list[str]:
    """
    Normalize and clean config paths:
    - strip whitespace
    - convert backslashes to forward slashes
    - drop empty entries
    """
    out: list[str] = []
    seen = set()

    for raw in items:
        s = (raw or "").strip().replace("\\", "/")
        if not s:
            continue
        if s not in seen:
            seen.add(s)
            out.append(s)

    return out


@dataclass
class RepoCleanConfig:
    max_file_mb: int = 25
    max_secret_file_kb: int = 256

    ignore_dirs: list[str] = field(default_factory=list)
    ignore_files: list[str] = field(default_factory=list)
    ignore_extensions: list[str] = field(default_factory=list)

    allow_secrets_in: list[str] = field(default_factory=list)

    # new: allow user to customize junk detection rules
    junk_dirs: list[str] = field(default_factory=list)
    junk_files: list[str] = field(default_factory=list)
    junk_extensions: list[str] = field(default_factory=list)


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

        junk_dirs=list(DEFAULT_CONFIG.junk_dirs),
        junk_files=list(DEFAULT_CONFIG.junk_files),
        junk_extensions=list(DEFAULT_CONFIG.junk_extensions),
    )

    if not cfg_path.exists():
        return cfg

    with cfg_path.open("rb") as f:
        raw = tomli.load(f)

    section = raw.get("repoclean", {})

    # numeric settings
    cfg.max_file_mb = int(section.get("max_file_mb", cfg.max_file_mb))
    cfg.max_secret_file_kb = int(section.get("max_secret_file_kb", cfg.max_secret_file_kb))

    # ignore rules
    cfg.ignore_dirs = _clean_path_list(_as_list(section.get("ignore_dirs", cfg.ignore_dirs)))
    cfg.ignore_files = _clean_path_list(_as_list(section.get("ignore_files", cfg.ignore_files)))
    cfg.ignore_extensions = _clean_path_list(_as_list(section.get("ignore_extensions", cfg.ignore_extensions)))

    # allowlist for secrets scan
    cfg.allow_secrets_in = _clean_path_list(_as_list(section.get("allow_secrets_in", cfg.allow_secrets_in)))

    # junk rule overrides
    cfg.junk_dirs = _clean_path_list(_as_list(section.get("junk_dirs", cfg.junk_dirs)))
    cfg.junk_files = _clean_path_list(_as_list(section.get("junk_files", cfg.junk_files)))

    # allow alias
    junk_exts = section.get("junk_extensions", None)
    if junk_exts is None:
        junk_exts = section.get("junk_exts", None)

    cfg.junk_extensions = _clean_path_list(_as_list(junk_exts if junk_exts is not None else cfg.junk_extensions))

    return cfg
