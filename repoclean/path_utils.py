from pathlib import Path


def rel_posix(repo: Path, path: Path) -> str:
    return path.resolve().relative_to(repo.resolve()).as_posix()


def should_ignore(rel_path: str, *, ignore_dirs: list[str], ignore_files: list[str], ignore_extensions: list[str]) -> bool:
    name = rel_path.split("/")[-1]

    if name in ignore_files:
        return True

    for ext in ignore_extensions:
        if name.lower().endswith(ext.lower()):
            return True

    for d in ignore_dirs:
        d = d.strip("/").strip("\\")
        if rel_path == d or rel_path.startswith(d + "/"):
            return True

    return False


def is_allowlisted(rel_path: str, allowlist: list[str]) -> bool:
    for prefix in allowlist:
        prefix = prefix.strip().replace("\\", "/")
        if not prefix.endswith("/"):
            prefix += "/"
        if rel_path.startswith(prefix):
            return True
    return False
