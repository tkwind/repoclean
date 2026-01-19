import shutil
import subprocess
from pathlib import Path

from repoclean.scanner import scan_repo
from repoclean.rules import DEFAULT_MAX_FILE_MB


def _git(repo: Path, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
    )


def _unstage_path(repo: Path, rel_posix_path: str) -> None:
    # git restore --staged is newer; fallback to reset for older git
    p = _git(repo, ["restore", "--staged", "--", rel_posix_path])
    if p.returncode == 0:
        return
    _git(repo, ["reset", "HEAD", "--", rel_posix_path])


def _unstage_deleted_file(repo: Path, rel_posix_path: str) -> None:
    """
    If a staged file gets deleted by repoclean fix, we must update git index.
    """
    p = _git(repo, ["rm", "--cached", "--quiet", "--", rel_posix_path])
    if p.returncode == 0:
        return
    _git(repo, ["add", "-u", "--", rel_posix_path])


def get_fix_targets(repo: Path, config=None, staged_only: bool = False):
    repo = Path(repo).resolve()

    max_mb = DEFAULT_MAX_FILE_MB
    if config and getattr(config, "max_file_mb", None) is not None:
        max_mb = config.max_file_mb

    result = scan_repo(
        repo_path=str(repo),
        max_file_mb=max_mb,
        config=config,
        staged_only=staged_only,
    )

    junk_dirs = [repo / Path(p) for p in result.junk_dirs]
    junk_files = [repo / Path(p) for p in result.junk_files]

    # staged-only mode: DO NOT delete dirs (dangerous)
    if staged_only:
        junk_dirs = []

        # IMPORTANT: do not filter staged files by exists()
        # because the git index might have staged entries even if file
        # no longer exists in working tree.
        return [], junk_files

    # full mode safety filters
    junk_dirs = [p for p in junk_dirs if p.exists() and p.is_dir()]
    junk_files = [p for p in junk_files if p.exists() and p.is_file()]

    return junk_dirs, junk_files


def apply_fix(
    junk_dirs,
    junk_files,
    *,
    repo: Path | None = None,
    staged_only: bool = False,
    unstage: bool = False,
):
    removed_dirs = 0
    removed_files = 0

    repo_path = Path(repo).resolve() if repo else None

    # staged-only unstage mode: don't delete files, just remove from commit
    if staged_only and unstage:
        if not repo_path:
            # can't unstage without repo path
            return 0, 0

        for f in junk_files:
            try:
                rel = f.resolve().relative_to(repo_path).as_posix()
            except Exception:
                # if resolve/relative fails, fallback to best-effort
                rel = str(f).replace("\\", "/")
                if repo_path:
                    # strip absolute prefix if present
                    try:
                        rel = str(Path(rel).relative_to(repo_path)).replace("\\", "/")
                    except Exception:
                        pass

            _unstage_path(repo_path, rel)

        return 0, 0

    # normal deletion cleanup
    for f in junk_files:
        try:
            if f.exists():
                f.unlink()
                removed_files += 1
        except Exception:
            pass

        # if staged-only, always ensure git index matches result
        if staged_only and repo_path:
            try:
                rel = f.resolve().relative_to(repo_path).as_posix()
                _unstage_deleted_file(repo_path, rel)
            except Exception:
                pass

    for d in junk_dirs:
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
            removed_dirs += 1

    # just in case: stage deletions in staged-only mode
    if staged_only and repo_path:
        _git(repo_path, ["add", "-u"])

    return removed_dirs, removed_files
