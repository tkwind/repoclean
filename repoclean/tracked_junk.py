# repoclean/tracked_junk.py
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from repoclean.rules import JUNK_DIRS, JUNK_FILES, JUNK_FILE_EXTS


@dataclass
class TrackedJunkResult:
    repo_path: Path
    tracked_junk: list[str]


def _git(repo: Path, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
    )


def _get_tracked_paths(repo: Path) -> list[str]:
    p = _git(repo, ["ls-files"])
    if p.returncode != 0:
        return []

    out = (p.stdout or "").strip()
    if not out:
        return []

    paths: list[str] = []
    for line in out.splitlines():
        rel = line.strip().replace("\\", "/")
        if not rel or rel.startswith(".git/"):
            continue
        paths.append(rel)
    return paths


def _is_junk_rel_path(rel_path_posix: str) -> bool:
    name = rel_path_posix.split("/")[-1]
    if name in JUNK_FILES:
        return True

    suffix = Path(name).suffix.lower()
    if suffix in JUNK_FILE_EXTS:
        return True

    parts = rel_path_posix.split("/")
    for part in parts[:-1]:
        if part in JUNK_DIRS:
            return True

    return False


def get_tracked_junk(repo_path: str = ".") -> TrackedJunkResult:
    repo = Path(repo_path).resolve()

    tracked = _get_tracked_paths(repo)
    junk = [p for p in tracked if _is_junk_rel_path(p)]

    return TrackedJunkResult(
        repo_path=repo,
        tracked_junk=sorted(set(junk)),
    )


def _ensure_gitignore_contains(repo: Path, lines: list[str]) -> None:
    """
    Minimal helper: appends patterns if missing.
    (we keep it conservative: don’t rewrite user file)
    """
    gi = repo / ".gitignore"
    if not gi.exists():
        existing = ""
    else:
        existing = gi.read_text(encoding="utf-8", errors="ignore")

    existing_lines = {x.strip() for x in existing.splitlines() if x.strip()}
    to_add = [x for x in lines if x.strip() and x.strip() not in existing_lines]
    if not to_add:
        return

    blob = existing.rstrip() + "\n\n# repoclean tracked junk\n" + "\n".join(to_add) + "\n"
    gi.write_text(blob, encoding="utf-8")


def fix_tracked_junk(repo_path: str = ".", tracked_junk: list[str] | None = None) -> tuple[int, list[str]]:
    """
    Removes tracked junk from git index while keeping files on disk.
    Equivalent to: git rm -r --cached <paths>
    """
    repo = Path(repo_path).resolve()

    if tracked_junk is None:
        tracked_junk = get_tracked_junk(str(repo)).tracked_junk

    if not tracked_junk:
        return 0, []

    removed: list[str] = []

    _ensure_gitignore_contains(
        repo,
        [
            "__pycache__/",
            "*.pyc",
            "*.log",
            "*.tmp",
            "*.swp",
            ".DS_Store",
            "Thumbs.db",
        ],
    )

    for rel in tracked_junk:
        p = _git(repo, ["rm", "-r", "--cached", "--quiet", "--", rel])
        if p.returncode == 0:
            removed.append(rel)

    _git(repo, ["add", ".gitignore"])

    return len(removed), removed
