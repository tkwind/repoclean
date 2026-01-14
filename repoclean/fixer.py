import shutil
from pathlib import Path

from repoclean.rules import JUNK_DIRS, JUNK_FILES


def get_fix_targets(repo_path: Path):
    """
    Return (junk_dirs_to_remove, junk_files_to_remove)
    """
    junk_dirs = []
    junk_files = []

    for p in repo_path.rglob("*"):
        # skip .git entirely
        if ".git" in p.parts:
            continue

        # junk folders
        if p.is_dir() and p.name in JUNK_DIRS:
            junk_dirs.append(p)

        # junk files
        if p.is_file():
            if p.name in JUNK_FILES or p.suffix == ".pyc":
                junk_files.append(p)

    # remove nested duplicates (if we delete a dir, don't list children)
    junk_dirs = sorted(set(junk_dirs), key=lambda x: len(str(x)))
    junk_files = sorted(set(junk_files))

    return junk_dirs, junk_files


def apply_fix(junk_dirs, junk_files):
    removed_dirs = 0
    removed_files = 0

    # 1) delete files first
    for f in junk_files:
        if f.exists():
            try:
                f.unlink()
                removed_files += 1
            except Exception:
                pass

    # 2) delete dirs after
    for d in junk_dirs:
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
            removed_dirs += 1

    return removed_dirs, removed_files

