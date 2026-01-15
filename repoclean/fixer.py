import shutil
from pathlib import Path
from repoclean.scanner import scan_repo
from repoclean.rules import DEFAULT_MAX_FILE_MB



def get_fix_targets(repo: Path, config=None):
    repo = Path(repo).resolve()

    max_mb = DEFAULT_MAX_FILE_MB
    if config and getattr(config, "max_file_mb", None) is not None:
        max_mb = config.max_file_mb

    result = scan_repo(repo_path=str(repo), max_file_mb=max_mb, config=config)

    junk_dirs = [repo / Path(p) for p in result.junk_dirs]
    junk_files = [repo / Path(p) for p in result.junk_files]

    # keep it safe: filter only real targets
    junk_dirs = [p for p in junk_dirs if p.exists() and p.is_dir()]
    junk_files = [p for p in junk_files if p.exists() and p.is_file()]

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

