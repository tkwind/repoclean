import base64
import math
import re
from dataclasses import dataclass
from pathlib import Path


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
    # tiny utility, no need to overthink
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
    # avoids random-base64 spam
    return bool(re.search(r"(?i)\b(key|token|secret|passwd|password|api_key|apikey|auth)\b\s*[:=]", line))


def _extract_candidate_strings(line: str) -> list[str]:
    # Pull quoted strings / rhs values - keep it conservative
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

    # remove junk duplicates
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

    # avoid false positives (paths, ids, etc.)
    if len(candidate) < 24:
        return False

    # too many repeats => likely not a secret
    if len(set(candidate)) < max(8, len(candidate) // 10):
        return False

    ent = _shannon_entropy(candidate)
    # NOTE: this threshold is tuned to avoid spam
    return ent >= 4.0

def _normalize_candidate_token(s: str) -> str:
    # makes comparisons robust
    return (s or "").strip().strip("\"'").replace("\\", "")

def _looks_like_jwt(s: str) -> bool:
    # JWT = header.payload.signature
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
    SecretPattern("Private Key Block", "critical", re.compile(r"-----BEGIN ([A-Z ]+)?PRIVATE KEY-----")),
    SecretPattern("OpenAI API Key", "critical", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),

    # GitHub
    SecretPattern("GitHub Classic Token", "high", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    SecretPattern("GitHub OAuth Token", "high", re.compile(r"\bgho_[A-Za-z0-9]{20,}\b")),
    SecretPattern("GitHub Fine-grained Token", "high", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),

    # AWS
    SecretPattern("AWS Access Key ID", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    SecretPattern("AWS Secret Access Key", "critical", re.compile(r"(?i)\baws_secret_access_key\b\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{32,}")),

    # Slack
    SecretPattern("Slack Token", "critical", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),

    # Stripe
    SecretPattern("Stripe Secret Key (live)", "critical", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    SecretPattern("Stripe Restricted Key (live)", "critical", re.compile(r"\brk_live_[A-Za-z0-9]{16,}\b")),

    # Telegram
    SecretPattern("Telegram Bot Token", "high", re.compile(r"\b\d{6,10}:[A-Za-z0-9_-]{25,}\b")),

    # Google API Key (AIza...)
    SecretPattern("Google API Key", "high", re.compile(r"\bAIzaSy[A-Za-z0-9_\-]{20,}\b")),

    # Firebase Admin SDK key file (marker)
    SecretPattern("Firebase Service Account JSON Marker", "high", re.compile(r'(?i)"type"\s*:\s*"service_account"')),
]

# Generic assignment — but still guarded
GENERIC_ASSIGNMENT_RGX = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|passwd|auth[_-]?token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-\/\+=]{12,})"
)


def scan_secrets(
    repo_path: str = ".",
    max_kb: int = 256,
    config=None,
    min_severity: str = "low",
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

    already_reported_signatures = set()  # kind|file|masked_preview

    for p in repo.rglob("*"):
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
            already_flagged_candidates_this_line = set()
            for pat in SECRET_PATTERNS:
                m = pat.rgx.search(line)
                if not m:
                    continue

                if SEVERITY_ORDER[pat.severity] < min_sev_val:
                    continue

                match_text = m.group(0)
                masked = mask(match_text)
                already_flagged_candidates_this_line.add(_normalize_candidate_token(match_text))


                sig = f"{pat.kind}|{rel}|{masked}"
                if sig in already_reported_signatures:
                    continue
                already_reported_signatures.add(sig)

                findings.append(
                    SecretFinding(
                        kind=pat.kind,
                        severity=pat.severity,
                        file=rel,
                        line=idx,
                        preview=masked,
                    )
                )

            # 2) jwt detection (carefully)
            for token in re.findall(r"[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", line):
                if not _looks_like_jwt(token):
                    continue

                sev = "medium"
                if SEVERITY_ORDER[sev] < min_sev_val:
                    continue

                masked = mask(token)
                already_flagged_candidates_this_line.add(_normalize_candidate_token(token))
                sig = f"JWT|{rel}|{masked}"
                if sig in already_reported_signatures:
                    continue
                already_reported_signatures.add(sig)

                findings.append(
                    SecretFinding(
                        kind="JWT Token",
                        severity=sev,
                        file=rel,
                        line=idx,
                        preview=masked,
                    )
                )

            # 3) generic assignment (guarded)
            m2 = GENERIC_ASSIGNMENT_RGX.search(line)
            if m2:
                key_name = (m2.group(1) or "token").lower()
                raw_value = (m2.group(2) or "").strip()
                already_flagged_candidates_this_line.add(_normalize_candidate_token(raw_value))
                # ignore obvious non-secrets
                if raw_value.lower() in {"true", "false", "null", "none"}:
                    continue
                if raw_value.isdigit():
                    continue

                # severity depends on length + entropy
                sev = "low"
                if len(raw_value) >= 24 and _looks_like_high_entropy_secret(raw_value):
                    sev = "high"

                if SEVERITY_ORDER[sev] < min_sev_val:
                    continue

                masked = mask(raw_value)
                sig = f"Generic {key_name}|{rel}|{masked}"
                if sig in already_reported_signatures:
                    continue
                already_reported_signatures.add(sig)

                findings.append(
                    SecretFinding(
                        kind=f"Generic Secret Assignment ({key_name})",
                        severity=sev,
                        file=rel,
                        line=idx,
                        preview=masked,
                    )
                )

            # 4) entropy detection - only when assignment-ish to avoid spam
            if _looks_like_assignment_context(line):
                for cand in _extract_candidate_strings(line):
                    normalized_cand = _normalize_candidate_token(cand)
                    # if already detected confidently, don't spam entropy finding too
                    if normalized_cand in already_flagged_candidates_this_line:
                        continue
                    if not _looks_like_high_entropy_secret(normalized_cand):
                        continue
                    if normalized_cand.lower().startswith(("token", "apikey", "api_key", "secret")):
                        continue


                    sev = "medium"
                    if len(cand) >= 40:
                        sev = "high"

                    if SEVERITY_ORDER[sev] < min_sev_val:
                        continue

                    masked = mask(normalized_cand)
                    sig = f"High Entropy Token|{rel}|{masked}"
                    if sig in already_reported_signatures:
                        continue
                    already_reported_signatures.add(sig)

                    findings.append(
                        SecretFinding(
                            kind="High Entropy Token",
                            severity=sev,
                            file=rel,
                            line=idx,
                            preview=masked,
                        )
                    )

    return findings
