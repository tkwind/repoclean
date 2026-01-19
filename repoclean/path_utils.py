# repoclean/path_utils.py

from __future__ import annotations

from pathlib import Path
import subprocess


def rel_posix(repo: Path, path: Path) -> str:
    """
    Convert absolute path -> repo-relative POSIX path (forward slashes).
    """
    repo = repo.resolve()
    path = path.resolve()

    try:
        rel = path.relative_to(repo)
    except Exception:
        # fallback (should not happen, but don't crash)
        return path.as_posix()

    return rel.as_posix()


def _norm_rel_path(p: str) -> str:
    return (p or "").strip().replace("\\", "/").lstrip("./")


def _norm_dir_prefix(d: str) -> str:
    d = _norm_rel_path(d)
    return d.strip("/")


def _norm_ext(ext: str) -> str:
    ext = (ext or "").strip().lower()
    if not ext:
        return ""
    if not ext.startswith("."):
        ext = "." + ext
    return ext


def should_ignore(
    rel_path: str,
    *,
    ignore_dirs: list[str],
    ignore_files: list[str],
    ignore_extensions: list[str],
) -> bool:
    rel_path = _norm_rel_path(rel_path)
    name = rel_path.split("/")[-1]

    # 1) exact file ignores
    for f in ignore_files:
        if name == (f or "").strip():
            return True

    # 2) extension ignores
    lowered = name.lower()
    for ext in ignore_extensions:
        ext = _norm_ext(ext)
        if ext and lowered.endswith(ext):
            return True

    # 3) directory ignores (prefix match)
    for d in ignore_dirs:
        d = _norm_dir_prefix(d)
        if not d:
            continue

        if rel_path == d:
            return True

        # prefix match only on proper boundary
        if rel_path.startswith(d + "/"):
            return True

    return False


def is_allowlisted(rel_path: str, allowlist: list[str]) -> bool:
    rel_path = _norm_rel_path(rel_path)

    for prefix in allowlist:
        prefix = _norm_rel_path(prefix)
        if not prefix:
            continue

        if not prefix.endswith("/"):
            prefix += "/"

        if rel_path.startswith(prefix):
            return True

    return False


def get_staged_paths(repo_path: str = ".") -> set[str]:
    """
    Return repo-relative POSIX paths staged for commit.
    Used for staged-only scan/fix.
    """
    repo = Path(repo_path).resolve()

    try:
        p = subprocess.run(
            ["git", "-C", str(repo), "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
        )
    except Exception:
        return set()

    if p.returncode != 0:
        return set()

    staged = set()
    for line in (p.stdout or "").splitlines():
        line = _norm_rel_path(line)
        if line:
            staged.add(line)

    return staged
