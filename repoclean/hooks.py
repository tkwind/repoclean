from pathlib import Path


HOOK_MARKER_BEGIN = "# repoclean hook begin"
HOOK_MARKER_END = "# repoclean hook end"


def find_git_dir(repo_path: Path) -> Path | None:
    p = repo_path.resolve()
    if (p / ".git").is_dir():
        return p / ".git"
    return None


def build_pre_commit_script() -> str:
    return f"""#!/bin/sh
{HOOK_MARKER_BEGIN}
repoclean secrets --fail
# Optional non-blocking scan summary:
repoclean scan > /dev/null 2>&1 || true
{HOOK_MARKER_END}
"""


def install_pre_commit_hook(repo_path: str = ".") -> tuple[bool, str]:
    repo = Path(repo_path).resolve()
    git_dir = find_git_dir(repo)
    if not git_dir:
        return False, "Not a git repository (.git not found)."

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    hook_path = hooks_dir / "pre-commit"

    content = build_pre_commit_script()

    if hook_path.exists():
        existing = hook_path.read_text(encoding="utf-8", errors="ignore")
        if HOOK_MARKER_BEGIN in existing and HOOK_MARKER_END in existing:
            return True, "repoclean pre-commit hook already installed."

        new_content = existing.rstrip() + "\n\n" + content
        hook_path.write_text(new_content, encoding="utf-8")
    else:
        hook_path.write_text(content, encoding="utf-8")

    try:
        hook_path.chmod(0o755)
    except Exception:
        pass

    return True, f"Installed pre-commit hook at {hook_path}"


def uninstall_pre_commit_hook(repo_path: str = ".") -> tuple[bool, str]:
    repo = Path(repo_path).resolve()
    git_dir = find_git_dir(repo)
    if not git_dir:
        return False, "Not a git repository (.git not found)."

    hook_path = git_dir / "hooks" / "pre-commit"
    if not hook_path.exists():
        return True, "No pre-commit hook found."

    existing = hook_path.read_text(encoding="utf-8", errors="ignore")

    if HOOK_MARKER_BEGIN not in existing or HOOK_MARKER_END not in existing:
        return False, "No repoclean hook block found in pre-commit hook."

    # remove only our block
    start = existing.index(HOOK_MARKER_BEGIN)
    end = existing.index(HOOK_MARKER_END) + len(HOOK_MARKER_END)
    new_content = (existing[:start] + existing[end:]).strip()

    if new_content:
        hook_path.write_text(new_content + "\n", encoding="utf-8")
        return True, "Removed repoclean block from existing pre-commit hook."
    else:
        hook_path.unlink()
        return True, "Removed pre-commit hook."

