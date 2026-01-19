import base64
import math
import re
from dataclasses import dataclass
from pathlib import Path
import subprocess


TEXT_FILE_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".json", ".env", ".txt", ".yaml", ".yml",
    ".toml", ".ini", ".md", ".sh", ".bash",
    ".zsh", ".ps1", ".java", ".go", ".rb",
}

SKIP_DIRS = {".git", "__pycache__", "node_modules", "dist", "build", ".venv", "venv"}


SEVERITY_ORDER = {
    "low": 10,
    "medium": 20,
    "high": 30,
    "critical": 40,
}


@dataclass(frozen=True)
class SecretPattern:
    kind: str
    severity: str
    rgx: re.Pattern


@dataclass
class SecretFinding:
    kind: str
    severity: str
    file: str
    line: int
    preview: str


def _git(repo: Path, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
    )


def _get_staged_paths(repo: Path) -> list[str]:
    """
    Returns staged file paths relative to repo root (posix format).
    """
    try:
        p = _git(repo, ["diff", "--cached", "--name-only"])
    except Exception:
        return []

    if p.returncode != 0:
        return []

    out = (p.stdout or "").strip()
    if not out:
        return []

    staged: list[str] = []
    for line in out.splitlines():
        rel = line.strip().replace("\\", "/")
        if not rel:
            continue
        if rel.startswith(".git/"):
            continue
        staged.append(rel)

    return staged


def mask(s: str, keep_start: int = 4, keep_end: int = 4) -> str:
    if not s:
        return ""
    if len(s) <= keep_start + keep_end:
        return "*" * len(s)
    return s[:keep_start] + "*" * (len(s) - keep_start - keep_end) + s[-keep_end:]


def looks_text_file(path: Path) -> bool:
    if path.name == ".env":
        return True
    return path.suffix.lower() in TEXT_FILE_EXTS


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0

    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1

    ent = 0.0
    n = float(len(s))
    for count in freq.values():
        p = count / n
        ent -= p * math.log2(p)
    return ent


def _looks_like_assignment_context(line: str) -> bool:
    return bool(
        re.search(
            r"(?i)\b(key|token|secret|passwd|password|api_key|apikey|auth|bearer)\b\s*[:=]",
            line,
        )
    )


def _extract_candidate_strings(line: str) -> list[str]:
    candidates: list[str] = []

    # KEY="value" / KEY='value'
    m = re.search(r"[:=]\s*['\"]([^'\"]{12,})['\"]", line)
    if m:
        candidates.append(m.group(1).strip())

    # KEY=value
    m2 = re.search(r"[:=]\s*([A-Za-z0-9_\-\/\+=]{16,})", line)
    if m2:
        candidates.append(m2.group(1).strip())

    # raw tokens on same line
    for token in re.findall(r"[A-Za-z0-9_\-\/\+=]{20,}", line):
        candidates.append(token)

    out = []
    seen = set()
    for c in candidates:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _looks_like_high_entropy_secret(candidate: str) -> bool:
    if not candidate:
        return False

    if len(candidate) < 24:
        return False

    # avoid common non-secrets
    if "/" in candidate or "\\" in candidate:
        return False

    # too repetitive = probably junk
    if len(set(candidate)) < max(8, len(candidate) // 10):
        return False

    ent = _shannon_entropy(candidate)
    return ent >= 4.0


def _normalize_candidate_token(s: str) -> str:
    if not s:
        return ""
    return (
        s.strip()
        .strip("\"'")
        .replace("\\", "")
        .replace("\r", "")
        .replace("\n", "")
    )


def _looks_like_jwt(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 3:
        return False
    if any(len(p) < 8 for p in parts):
        return False

    # validate base64-ish
    for p in parts[:2]:
        p2 = p.replace("-", "+").replace("_", "/")
        pad = "=" * (-len(p2) % 4)
        try:
            raw = base64.b64decode(p2 + pad)
        except Exception:
            return False
        if not raw:
            return False
    return True


# High precision patterns first (low false positives)
SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        "Private Key Block",
        "critical",
        re.compile(r"-----BEGIN ([A-Z ]+)?PRIVATE KEY-----"),
    ),

    # OpenAI
    SecretPattern("OpenAI API Key", "critical", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),

    # GitHub
    SecretPattern("GitHub Classic Token", "high", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    SecretPattern("GitHub OAuth Token", "high", re.compile(r"\bgho_[A-Za-z0-9]{20,}\b")),
    SecretPattern("GitHub Fine-grained Token", "high", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),

    # GitLab
    SecretPattern("GitLab Token", "high", re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b")),

    # AWS
    SecretPattern("AWS Access Key ID", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    SecretPattern(
        "AWS Secret Access Key",
        "critical",
        re.compile(r"(?i)\baws_secret_access_key\b\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{32,}"),
    ),

    # Slack
    SecretPattern("Slack Token", "critical", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),

    # Stripe
    SecretPattern("Stripe Secret Key (live)", "critical", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    SecretPattern("Stripe Restricted Key (live)", "critical", re.compile(r"\brk_live_[A-Za-z0-9]{16,}\b")),

    # Telegram
    SecretPattern("Telegram Bot Token", "high", re.compile(r"\b\d{6,10}:[A-Za-z0-9_-]{25,}\b")),

    # Google
    SecretPattern("Google API Key", "high", re.compile(r"\bAIzaSy[A-Za-z0-9_\-]{20,}\b")),

    # Firebase Admin SDK key file marker
    SecretPattern(
        "Firebase Service Account JSON Marker",
        "high",
        re.compile(r'(?i)"type"\s*:\s*"service_account"'),
    ),

    # Heroku
    SecretPattern("Heroku API Key", "high", re.compile(r"\b[0-9a-f]{32}\b")),

    # Twilio
    SecretPattern("Twilio Account SID", "high", re.compile(r"\bAC[a-f0-9]{32}\b")),

    # SendGrid
    SecretPattern("SendGrid API Key", "high", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b")),

    # Discord (Bot token-like)
    SecretPattern("Discord Token", "high", re.compile(r"\b[Mm][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b")),
]

GENERIC_ASSIGNMENT_RGX = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|passwd|auth[_-]?token|bearer)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-\/\+=]{12,})"
)


def scan_secrets(
    repo_path: str = ".",
    max_kb: int = 256,
    config=None,
    min_severity: str = "low",
    staged_only: bool = False,
) -> list[SecretFinding]:
    """
    Security scanner:
    - High precision patterns (critical/high)
    - Conservative generic assignment checks
    - Optional entropy detection (guarded)
    - Deduped output
    """
    from repoclean.path_utils import rel_posix, should_ignore, is_allowlisted

    min_sev_val = SEVERITY_ORDER.get(min_severity, SEVERITY_ORDER["low"])

    repo = Path(repo_path).resolve()
    findings: list[SecretFinding] = []

    # IMPORTANT: dedupe should use normalized raw token, not masked preview
    already_reported_tokens = set()  # (kind, rel, normalized_token)

    def _iter_target_files() -> list[Path]:
    # staged-only mode: only check staged files
        if staged_only:
            staged_rel_paths = _get_staged_paths(repo)
            out: list[Path] = []
            for rel in staged_rel_paths:
                try:
                    fp = (repo / rel).resolve()
                except Exception:
                    continue
                if fp.exists() and fp.is_file():
                    out.append(fp)
            return out

        # full scan mode
        return [p for p in repo.rglob("*") if p.is_file()]


    for p in _iter_target_files():
        if not p.is_file():
            continue


        try:
            rel_parts = p.relative_to(repo).parts
        except Exception:
            rel_parts = ()

        if any(part in SKIP_DIRS for part in rel_parts):
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
        if allowlisted:
            continue

        for idx, line in enumerate(text.splitlines(), start=1):
            already_flagged_this_line = set()

            # 1) high precision patterns
            for pat in SECRET_PATTERNS:
                m = pat.rgx.search(line)
                if not m:
                    continue

                if SEVERITY_ORDER[pat.severity] < min_sev_val:
                    continue

                match_text = m.group(0)
                normalized = _normalize_candidate_token(match_text)
                already_flagged_this_line.add(normalized)

                sig = (pat.kind, rel, normalized)
                if sig in already_reported_tokens:
                    continue
                already_reported_tokens.add(sig)

                findings.append(
                    SecretFinding(
                        kind=pat.kind,
                        severity=pat.severity,
                        file=rel,
                        line=idx,
                        preview=mask(match_text),
                    )
                )

            # 2) jwt detection
            for token in re.findall(r"[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", line):
                if not _looks_like_jwt(token):
                    continue

                sev = "medium"
                if SEVERITY_ORDER[sev] < min_sev_val:
                    continue

                normalized = _normalize_candidate_token(token)
                already_flagged_this_line.add(normalized)

                sig = ("JWT Token", rel, normalized)
                if sig in already_reported_tokens:
                    continue
                already_reported_tokens.add(sig)

                findings.append(
                    SecretFinding(
                        kind="JWT Token",
                        severity=sev,
                        file=rel,
                        line=idx,
                        preview=mask(token),
                    )
                )

            # 3) generic assignment
            m2 = GENERIC_ASSIGNMENT_RGX.search(line)
            if m2:
                key_name = (m2.group(1) or "token").lower()
                raw_value = (m2.group(2) or "").strip()

                normalized = _normalize_candidate_token(raw_value)
                already_flagged_this_line.add(normalized)

                if raw_value.lower() in {"true", "false", "null", "none"}:
                    continue
                if raw_value.isdigit():
                    continue

                sev = "low"
                if len(raw_value) >= 24 and _looks_like_high_entropy_secret(raw_value):
                    sev = "high"

                if SEVERITY_ORDER[sev] >= min_sev_val:
                    sig = (f"Generic Secret Assignment ({key_name})", rel, normalized)
                    if sig not in already_reported_tokens:
                        already_reported_tokens.add(sig)
                        findings.append(
                            SecretFinding(
                                kind=f"Generic Secret Assignment ({key_name})",
                                severity=sev,
                                file=rel,
                                line=idx,
                                preview=mask(raw_value),
                            )
                        )

            # 4) entropy detection (guarded)
            if _looks_like_assignment_context(line):
                for cand in _extract_candidate_strings(line):
                    normalized = _normalize_candidate_token(cand)

                    if not normalized:
                        continue
                    if normalized in already_flagged_this_line:
                        continue

                    # don't report KEY=... (people love writing TOKEN=ABC... which becomes a cand)
                    if normalized.lower().startswith(("token", "apikey", "api_key", "secret", "password")):
                        continue

                    if not _looks_like_high_entropy_secret(normalized):
                        continue

                    sev = "medium"
                    if len(normalized) >= 40:
                        sev = "high"

                    if SEVERITY_ORDER[sev] < min_sev_val:
                        continue

                    sig = ("High Entropy Token", rel, normalized)
                    if sig in already_reported_tokens:
                        continue
                    already_reported_tokens.add(sig)

                    findings.append(
                        SecretFinding(
                            kind="High Entropy Token",
                            severity=sev,
                            file=rel,
                            line=idx,
                            preview=mask(normalized),
                        )
                    )

    return findings
