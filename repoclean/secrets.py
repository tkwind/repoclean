import re
from dataclasses import dataclass
from pathlib import Path

SECRET_PATTERNS = [
    ("OpenAI API Key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("GitHub Token", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("GitHub PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Telegram Bot Token", re.compile(r"\b\d{6,10}:[A-Za-z0-9_-]{25,}\b")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA )?PRIVATE KEY-----")),
    ("Generic API Key Assignment", re.compile(r"(?i)\b(api_key|apikey|token|secret|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{12,})")),
]

TEXT_FILE_EXTS = {
    ".py", ".js", ".ts", ".json", ".env", ".txt", ".yaml", ".yml", ".toml", ".ini", ".md", ".sh"
}

SKIP_DIRS = {".git", "__pycache__", "node_modules", "dist", "build", ".venv", "venv"}

@dataclass
class SecretFinding:
    kind: str
    file: str
    line: int
    preview: str


def mask(s: str, keep_start: int = 4, keep_end: int = 4) -> str:
    if len(s) <= keep_start + keep_end:
        return "*" * len(s)
    return s[:keep_start] + "*" * (len(s) - keep_start - keep_end) + s[-keep_end:]


def looks_text_file(path: Path) -> bool:
    return path.suffix.lower() in TEXT_FILE_EXTS or path.name == ".env"


def scan_secrets(repo_path: str = ".", max_kb: int = 256, config=None) -> list[SecretFinding]:
    from repoclean.path_utils import rel_posix, should_ignore, is_allowlisted

    repo = Path(repo_path).resolve()
    findings: list[SecretFinding] = []

    for p in repo.rglob("*"):
        if not p.is_file():
            continue

        if any(part in SKIP_DIRS for part in p.parts):
            continue

        if not looks_text_file(p):
            continue

        rel = rel_posix(repo, p)

        if config and should_ignore(
            rel,
            ignore_dirs=config.ignore_dirs,
            ignore_files=config.ignore_files,
            ignore_extensions=config.ignore_extensions,
        ):
            continue

        try:
            if p.stat().st_size > max_kb * 1024:
                continue
        except Exception:
            continue

        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        allowlisted = bool(config) and is_allowlisted(rel, config.allow_secrets_in)

        lines = text.splitlines()

        for idx, line in enumerate(lines, start=1):
            for kind, rgx in SECRET_PATTERNS:
                m = rgx.search(line)
                if not m:
                    continue

                if allowlisted:
                    continue

                match_text = m.group(0)
                if kind == "Generic API Key Assignment" and m.lastindex and m.lastindex >= 2:
                    match_text = m.group(2)

                findings.append(
                    SecretFinding(
                        kind=kind,
                        file=rel,
                        line=idx,
                        preview=mask(match_text),
                    )
                )

    return findings
