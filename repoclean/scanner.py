import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from repoclean.rules import (
    JUNK_DIRS,
    JUNK_FILES,
    JUNK_FILE_EXTS,
    SENSITIVE_FILES,
    SENSITIVE_EXTENSIONS,
    DEFAULT_MAX_FILE_MB,
)


@dataclass
class ScanResult:
    repo_path: Path
    has_git: bool
    has_gitignore: bool
    junk_dirs: list
    junk_files: list
    sensitive_files: list
    large_files: list


def is_sensitive(path: Path) -> bool:
    if path.name in SENSITIVE_FILES:
        return True
    if path.suffix.lower() in SENSITIVE_EXTENSIONS:
        return True
    return False


def _get_staged_paths(repo: Path) -> list[str]:
    try:
        p = subprocess.run(
            ["git", "-C", str(repo), "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
        )
    except Exception:
        return []

    if p.returncode != 0:
        return []

    out = (p.stdout or "").strip()
    if not out:
        return []

    staged = []
    for line in out.splitlines():
        line = line.strip().replace("\\", "/")
        if not line:
            continue
        if line.startswith(".git/"):
            continue
        staged.append(line)
    return staged


def _effective_junk_rules(config=None):
    junk_dirs = set(JUNK_DIRS)
    junk_files = set(JUNK_FILES)
    junk_exts = set(JUNK_FILE_EXTS)

    if config:
        # extend defaults
        for d in getattr(config, "junk_dirs", []) or []:
            junk_dirs.add(str(d))
        for f in getattr(config, "junk_files", []) or []:
            junk_files.add(str(f))
        for e in getattr(config, "junk_extensions", []) or []:
            if not str(e).startswith("."):
                junk_exts.add("." + str(e))
            else:
                junk_exts.add(str(e))

    return junk_dirs, junk_files, junk_exts


def scan_repo(
    repo_path: str = ".",
    max_file_mb: int = DEFAULT_MAX_FILE_MB,
    config=None,
    staged_only: bool = False,
) -> ScanResult:
    from repoclean.path_utils import rel_posix, should_ignore

    repo = Path(repo_path).resolve()

    has_git = (repo / ".git").exists()
    has_gitignore = (repo / ".gitignore").exists()

    junk_dirs: list[str] = []
    junk_files: list[str] = []
    sensitive_files: list[str] = []
    large_files: list[tuple[str, int]] = []

    max_bytes = max_file_mb * 1024 * 1024

    effective_junk_dirs, effective_junk_files, effective_junk_exts = _effective_junk_rules(config)

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

            name = fp.name
            suffix = fp.suffix.lower()

            if name in effective_junk_files or suffix in effective_junk_exts:
                junk_files.append(rel)

            if is_sensitive(fp):
                sensitive_files.append(rel)

            try:
                size = fp.stat().st_size
                if size > max_bytes:
                    large_files.append((rel, size))
            except Exception:
                pass

        return ScanResult(
            repo_path=repo,
            has_git=has_git,
            has_gitignore=has_gitignore,
            junk_dirs=[],
            junk_files=sorted(set(junk_files)),
            sensitive_files=sorted(set(sensitive_files)),
            large_files=sorted(set(large_files)),
        )

    # full scan mode
    for root, dirs, files in os.walk(repo):
        root_path = Path(root)

        if ".git" in dirs:
            dirs.remove(".git")

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

        for d in list(dirs):
            if d in effective_junk_dirs:
                rel_dir = rel_posix(repo, root_path / d)

                if config and should_ignore(
                    rel_dir,
                    ignore_dirs=config.ignore_dirs,
                    ignore_files=config.ignore_files,
                    ignore_extensions=config.ignore_extensions,
                ):
                    continue

                junk_dirs.append(rel_dir)

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

            if f in effective_junk_files or fp.suffix.lower() in effective_junk_exts:
                junk_files.append(rel)

            if is_sensitive(fp):
                sensitive_files.append(rel)

            try:
                size = fp.stat().st_size
                if size > max_bytes:
                    large_files.append((rel, size))
            except Exception:
                pass

    return ScanResult(
        repo_path=repo,
        has_git=has_git,
        has_gitignore=has_gitignore,
        junk_dirs=sorted(set(junk_dirs)),
        junk_files=sorted(set(junk_files)),
        sensitive_files=sorted(set(sensitive_files)),
        large_files=sorted(set(large_files)),
    )
