from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from repoclean.rules import get_effective_junk_rules


def _git(repo: Path, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
    )


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


def _is_tracked_path_junk(rel_posix: str, *, junk_dirs: set[str], junk_files: set[str], junk_exts: set[str]) -> bool:
    # rel_posix example: "repoclean/__pycache__/abc.pyc"
    name = rel_posix.split("/")[-1]

    if name in junk_files:
        return True

    suffix = Path(name).suffix.lower()
    if suffix and suffix in junk_exts:
        return True

    # junk dirs anywhere in path
    parts = rel_posix.split("/")
    for part in parts[:-1]:
        if part in junk_dirs:
            return True

    return False


@dataclass
class TrackedJunkResult:
    repo_path: Path
    tracked_junk: list[str]


def get_tracked_junk(repo_path: str = ".", config=None) -> TrackedJunkResult:
    from repoclean.path_utils import should_ignore

    repo = Path(repo_path).resolve()
    rules = get_effective_junk_rules(config)

    tracked = _get_tracked_paths(repo)
    bad: list[str] = []

    for rel in tracked:
        # keep consistent with scanner: user ignore config wins
        if config and should_ignore(
            rel,
            ignore_dirs=config.ignore_dirs,
            ignore_files=config.ignore_files,
            ignore_extensions=config.ignore_extensions,
        ):
            continue

        if _is_tracked_path_junk(
            rel,
            junk_dirs=rules.dirs,
            junk_files=rules.files,
            junk_exts=rules.extensions,
        ):
            bad.append(rel)

    bad = sorted(set(bad))

    return TrackedJunkResult(
        repo_path=repo,
        tracked_junk=bad,
    )


def remove_tracked_paths(repo: Path, rel_paths: list[str]) -> tuple[int, list[str]]:
    """
    Removes files from git index but keeps them locally.
    Equivalent to: git rm --cached -- <paths>
    """
    repo = Path(repo).resolve()

    removed: list[str] = []
    for rel in rel_paths:
        rel = (rel or "").strip().replace("\\", "/")
        if not rel:
            continue

        p = _git(repo, ["rm", "--cached", "--quiet", "--", rel])
        if p.returncode == 0:
            removed.append(rel)

    # stage index updates (so commit reflects removal)
    if removed:
        _git(repo, ["add", "-u"])

    return len(removed), removed


def fix_tracked_junk(repo_path: str = ".", config=None) -> tuple[int, list[str]]:
    """
    Convenience wrapper:
    - detects tracked junk
    - removes it from index
    Returns: (removed_count, removed_paths)
    """
    repo = Path(repo_path).resolve()

    result = get_tracked_junk(repo_path=str(repo), config=config)
    if not result.tracked_junk:
        return 0, []

    return remove_tracked_paths(repo, result.tracked_junk)
