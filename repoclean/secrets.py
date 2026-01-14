import re
from dataclasses import dataclass
from pathlib import Path

# (name, regex)
SECRET_PATTERNS = [
    ("OpenAI API Key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("GitHub Token", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("GitHub PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Telegram Bot Token", re.compile(r"\b\d{6,10}:[A-Za-z0-9_-]{25,}\b")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA )?PRIVATE KEY-----")),
    # generic token-ish assignments
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
    # scan only known text-ish types
    return path.suffix.lower() in TEXT_FILE_EXTS or path.name == ".env"


def scan_secrets(repo_path: str = ".", max_kb: int = 256) -> list[SecretFinding]:
    repo = Path(repo_path).resolve()
    findings: list[SecretFinding] = []

    for p in repo.rglob("*"):
        if not p.is_file():
            continue

        # skip dirs
        if any(part in SKIP_DIRS for part in p.parts):
            continue

        if not looks_text_file(p):
            continue

        # skip big files
        try:
            if p.stat().st_size > max_kb * 1024:
                continue
        except Exception:
            continue

        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        rel = str(p.relative_to(repo)).replace("\\", "/")
        lines = text.splitlines()

        for idx, line in enumerate(lines, start=1):
            for kind, rgx in SECRET_PATTERNS:
                m = rgx.search(line)
                if not m:
                    continue

                # prefer full match; fallback to group
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
