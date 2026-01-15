import shutil
from pathlib import Path
from repoclean.path_utils import rel_posix, should_ignore
from repoclean.rules import JUNK_DIRS, JUNK_FILES


def get_fix_targets(repo: Path, config=None):
    junk_dirs = []
    junk_files = []

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

        for d in dirs:
            if d in JUNK_DIRS:
                rel_dir = rel_posix(repo, root_path / d)

                if config and should_ignore(
                    rel_dir,
                    ignore_dirs=config.ignore_dirs,
                    ignore_files=config.ignore_files,
                    ignore_extensions=config.ignore_extensions,
                ):
                    continue

                junk_dirs.append(root_path / d)

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
                junk_files.append(fp)

    return junk_dirs, junk_files



def apply_fix(junk_dirs, junk_files):
    removed_dirs = 0
    removed_files = 0

    for f in junk_files:
        if f.exists():
            try:
                f.unlink()
                removed_files += 1
            except Exception:
                pass

    for d in junk_dirs:
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
            removed_dirs += 1

    return removed_dirs, removed_files

