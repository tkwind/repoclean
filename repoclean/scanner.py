from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from repoclean.rules import DEFAULT_MAX_FILE_MB, get_effective_junk_rules
from repoclean.rules import SENSITIVE_FILES, SENSITIVE_EXTENSIONS


@dataclass
class ScanResult:
    repo_path: Path
    has_git: bool
    has_gitignore: bool

    junk_dirs: list
    junk_files: list
    sensitive_files: list
    large_files: list

    tracked_junk: list
    gitignore_missing: bool
    env_unignored: bool
    repo_health_score: int


def is_sensitive(path: Path) -> bool:
    if path.name in SENSITIVE_FILES:
        return True
    if path.suffix.lower() in SENSITIVE_EXTENSIONS:
        return True
    return False


def _git(repo: Path, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
    )


def _get_staged_paths(repo: Path) -> list[str]:
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
        line = line.strip().replace("\\", "/")
        if not line:
            continue
        if line.startswith(".git/"):
            continue
        staged.append(line)

    return staged


def _get_tracked_paths(repo: Path) -> list[str]:
    try:
        p = _git(repo, ["ls-files"])
    except Exception:
        return []

    if p.returncode != 0:
        return []

    out = (p.stdout or "").strip()
    if not out:
        return []

    tracked: list[str] = []
    for line in out.splitlines():
        rel = line.strip().replace("\\", "/")
        if not rel:
            continue
        if rel.startswith(".git/"):
            continue
        tracked.append(rel)

    return tracked


def _is_junk_rel_path(
    rel_path_posix: str,
    *,
    junk_dirs: set[str],
    junk_files: set[str],
    junk_exts: set[str],
) -> bool:
    """
    Generic junk detector using effective rules.
    Works for both tracked junk checks and scanner junk lists.
    """
    name = rel_path_posix.split("/")[-1]

    if name in junk_files:
        return True

    suffix = Path(name).suffix.lower()
    if suffix in junk_exts:
        return True

    parts = rel_path_posix.split("/")
    for part in parts[:-1]:
        if part in junk_dirs:
            return True

    return False


def _gitignore_ignores_env(repo: Path) -> bool:
    env_path = repo / ".env"
    if not env_path.exists():
        return True

    try:
        p = _git(repo, ["check-ignore", "-q", ".env"])
        return p.returncode == 0
    except Exception:
        try:
            gi = (repo / ".gitignore").read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return False
        return ".env" in gi


def _compute_health_score(
    *,
    has_gitignore: bool,
    env_unignored: bool,
    junk_count: int,
    sensitive_count: int,
    tracked_junk_count: int,
    large_count: int,
) -> int:
    score = 100

    if not has_gitignore:
        score -= 15

    if env_unignored:
        score -= 25

    if tracked_junk_count > 0:
        score -= 20

    if junk_count > 0:
        score -= 10

    if sensitive_count > 0:
        score -= 20

    if large_count > 0:
        score -= 10

    if score < 0:
        score = 0
    if score > 100:
        score = 100

    return score


def scan_repo(
    repo_path: str = ".",
    max_file_mb: int = DEFAULT_MAX_FILE_MB,
    config=None,
    staged_only: bool = False,
) -> ScanResult:
    from repoclean.path_utils import rel_posix, should_ignore, is_allowlisted

    repo = Path(repo_path).resolve()

    has_git = (repo / ".git").exists()
    has_gitignore = (repo / ".gitignore").exists()

    junk_dirs: list[str] = []
    junk_files: list[str] = []
    sensitive_files: list[str] = []
    large_files: list[tuple[str, int]] = []

    tracked_junk: list[str] = []
    gitignore_missing = False
    env_unignored = False

    max_bytes = max_file_mb * 1024 * 1024

    # effective merged junk rules (built-in + config)
    jr = get_effective_junk_rules(config)

    # Phase 5: missing gitignore
    if has_git and not has_gitignore:
        gitignore_missing = True

    # Phase 5: env exists but not ignored (unless allowlisted)
    env_path = repo / ".env"
    if has_git and env_path.exists():
        rel_env = ".env"
        allowlisted_env = bool(config) and is_allowlisted(rel_env, config.allow_secrets_in)

        if not allowlisted_env:
            if not has_gitignore:
                env_unignored = True
            else:
                env_unignored = not _gitignore_ignores_env(repo)

    # tracked junk should NOT pollute staged-only scans
    if has_git and not staged_only:
        tracked = _get_tracked_paths(repo)
        for rel in tracked:
            # apply config ignore
            if config and should_ignore(
                rel,
                ignore_dirs=config.ignore_dirs,
                ignore_files=config.ignore_files,
                ignore_extensions=config.ignore_extensions,
            ):
                continue

            if _is_junk_rel_path(
                rel,
                junk_dirs=jr.dirs,
                junk_files=jr.files,
                junk_exts=jr.extensions,
            ):
                tracked_junk.append(rel)

    # staged-only mode
    if staged_only:
        staged_rel_paths = _get_staged_paths(repo)

        for rel in staged_rel_paths:
            try:
                fp = (repo / rel).resolve()
            except Exception:
                continue

            if not fp.exists() or not fp.is_file():
                continue

            if config and should_ignore(
                rel,
                ignore_dirs=config.ignore_dirs,
                ignore_files=config.ignore_files,
                ignore_extensions=config.ignore_extensions,
            ):
                continue

            # junk file detection uses merged rules now
            if _is_junk_rel_path(
                rel,
                junk_dirs=jr.dirs,
                junk_files=jr.files,
                junk_exts=jr.extensions,
            ):
                junk_files.append(rel)

            if is_sensitive(fp):
                sensitive_files.append(rel)

            try:
                size = fp.stat().st_size
                if size > max_bytes:
                    large_files.append((rel, size))
            except Exception:
                pass

        score = _compute_health_score(
            has_gitignore=has_gitignore,
            env_unignored=env_unignored,
            junk_count=len(junk_files),
            sensitive_count=len(sensitive_files),
            tracked_junk_count=0,  # intentionally ignored in staged-only
            large_count=len(large_files),
        )

        return ScanResult(
            repo_path=repo,
            has_git=has_git,
            has_gitignore=has_gitignore,
            junk_dirs=[],
            junk_files=sorted(set(junk_files)),
            sensitive_files=sorted(set(sensitive_files)),
            large_files=sorted(set(large_files)),
            tracked_junk=[],
            gitignore_missing=gitignore_missing,
            env_unignored=env_unignored,
            repo_health_score=score,
        )

    # full scan
    for root, dirs, files in os.walk(repo):
        root_path = Path(root)

        if ".git" in dirs:
            dirs.remove(".git")

        # prune ignored dirs
        if config:
            pruned = []
            for d in dirs:
                rel_dir = rel_posix(repo, root_path / d)
                if should_ignore(
                    rel_dir,
                    ignore_dirs=config.ignore_dirs,
                    ignore_files=config.ignore_files,
                    ignore_extensions=config.ignore_extensions,
                ):
                    pruned.append(d)
            for d in pruned:
                dirs.remove(d)

        # junk folders
        for d in list(dirs):
            if d in jr.dirs:
                rel_dir = rel_posix(repo, root_path / d)

                if config and should_ignore(
                    rel_dir,
                    ignore_dirs=config.ignore_dirs,
                    ignore_files=config.ignore_files,
                    ignore_extensions=config.ignore_extensions,
                ):
                    continue

                junk_dirs.append(rel_dir)

        # junk/sensitive/large files
        for f in files:
            fp = root_path / f
            rel = rel_posix(repo, fp)

            if config and should_ignore(
                rel,
                ignore_dirs=config.ignore_dirs,
                ignore_files=config.ignore_files,
                ignore_extensions=config.ignore_extensions,
            ):
                continue

            if f in jr.files or fp.suffix.lower() in jr.extensions:
                junk_files.append(rel)

            if is_sensitive(fp):
                sensitive_files.append(rel)

            try:
                size = fp.stat().st_size
                if size > max_bytes:
                    large_files.append((rel, size))
            except Exception:
                pass

    score = _compute_health_score(
        has_gitignore=has_gitignore,
        env_unignored=env_unignored,
        junk_count=(len(junk_dirs) + len(junk_files)),
        sensitive_count=len(sensitive_files),
        tracked_junk_count=len(tracked_junk),
        large_count=len(large_files),
    )

    return ScanResult(
        repo_path=repo,
        has_git=has_git,
        has_gitignore=has_gitignore,
        junk_dirs=sorted(set(junk_dirs)),
        junk_files=sorted(set(junk_files)),
        sensitive_files=sorted(set(sensitive_files)),
        large_files=sorted(set(large_files)),
        tracked_junk=sorted(set(tracked_junk)),
        gitignore_missing=gitignore_missing,
        env_unignored=env_unignored,
        repo_health_score=score,
    )
