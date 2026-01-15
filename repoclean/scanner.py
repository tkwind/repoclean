import os
from dataclasses import dataclass
from pathlib import Path

from repoclean.rules import (
    JUNK_DIRS,
    JUNK_FILES,
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


def scan_repo(repo_path: str = ".", max_file_mb: int = DEFAULT_MAX_FILE_MB, config=None) -> ScanResult:
    from repoclean.path_utils import rel_posix, should_ignore

    repo = Path(repo_path).resolve()

    has_git = (repo / ".git").exists()
    has_gitignore = (repo / ".gitignore").exists()

    junk_dirs = []
    junk_files = []
    sensitive_files = []
    large_files = []

    max_bytes = max_file_mb * 1024 * 1024

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
            if d in JUNK_DIRS:
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

            if f in JUNK_FILES or fp.suffix.lower() == ".pyc":
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

