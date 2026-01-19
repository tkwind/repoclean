from __future__ import annotations

from pathlib import Path

try:
    import tomllib as tomli
except ModuleNotFoundError:
    import tomli


HOOK_META_FILE = "repoclean_hook.toml"
HOOK_MARKER_BEGIN = "# repoclean hook begin"
HOOK_MARKER_END = "# repoclean hook end"


def find_git_dir(repo_path: Path) -> Path | None:
    p = repo_path.resolve()
    if (p / ".git").is_dir():
        return p / ".git"
    return None


def get_hook_status(repo_path: str = ".") -> dict:
    repo = Path(repo_path).resolve()
    git_dir = find_git_dir(repo)

    status = {
        "repo_path": str(repo),
        "has_git": bool(git_dir),
        "hook_installed": False,
        "hook_path": "",
        "mode": "unknown",
        "has_metadata": False,
    }

    if not git_dir:
        return status

    hook_path = git_dir / "hooks" / "pre-commit"
    status["hook_path"] = str(hook_path)

    if hook_path.exists():
        txt = hook_path.read_text(encoding="utf-8", errors="ignore")
        if HOOK_MARKER_BEGIN in txt and HOOK_MARKER_END in txt:
            status["hook_installed"] = True

    meta = read_hook_meta(git_dir)
    if meta:
        status["has_metadata"] = True
        status["mode"] = str(meta.get("mode", "unknown"))

    return status


def build_pre_commit_script(mode: str = "strict") -> str:
    mode = mode.lower().strip()
    if mode not in {"strict", "warn"}:
        mode = "strict"

    if mode == "strict":
        fail_on = "junk,sensitive,large,secrets"
    else:
        fail_on = "secrets"

    return f"""#!/bin/sh
{HOOK_MARKER_BEGIN}

# Prefer python3 if available, fallback to python
if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN=python3
else
  PYTHON_BIN=python
fi

"$PYTHON_BIN" - <<'PY'
import json
import subprocess
import sys

MODE = {mode!r}
FAIL_ON = {fail_on!r}

def run_repoclean(args):
    try:
        return subprocess.run(
            ["repoclean", *args],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print("repoclean hook: 'repoclean' command not found.")
        print("Install it via: pip install repoclean-cli")
        sys.exit(2)

# 0) auto-clean staged junk before commit
fx = run_repoclean(["fix", "--staged-only", "--yes"])
if fx.returncode != 0:
    print("repoclean hook: fix failed (exit code %d)" % fx.returncode)
    err = (fx.stderr or fx.stdout or "").strip()
    if err:
        print(err[:2000])
    sys.exit(2)

p = run_repoclean(["gate", "--staged-only", "--mode", MODE])


out = (p.stdout or "").strip()
try:
    report = json.loads(out) if out else {{}}
except Exception:
    print("repoclean hook: failed to parse JSON output from repoclean ci")
    if out:
        print("repoclean output:")
        print(out[:2000])
    sys.exit(2)

failed = report.get("failed", {{}})
failed_secrets = bool(failed.get("secrets", False))
exit_code = int(report.get("exit_code", p.returncode))

# always block on secrets
if failed_secrets:
    print("repoclean: secrets detected. Commit blocked.")
    sys.exit(1)

# strict blocks on any failing hygiene checks too
if exit_code != 0 and MODE == "strict":
    print("repoclean: repo hygiene checks failed. Commit blocked (strict mode).")
    sys.exit(exit_code)

# warn mode lets hygiene pass
if exit_code != 0 and MODE == "warn":
    print("repoclean: warning (warn mode). Commit allowed.")
    sys.exit(0)

sys.exit(0)
PY

status=$?
exit $status

{HOOK_MARKER_END}
"""


def write_hook_meta(git_dir: Path, mode: str) -> None:
    meta_path = git_dir / HOOK_META_FILE
    meta_path.write_text(f'mode = "{mode}"\n', encoding="utf-8")


def read_hook_meta(git_dir: Path) -> dict:
    meta_path = git_dir / HOOK_META_FILE
    if not meta_path.exists():
        return {}
    try:
        with meta_path.open("rb") as f:
            return tomli.load(f)
    except Exception:
        return {}


def _is_hook_corrupted(existing_text: str) -> bool:
    """
    Quick heuristic:
    if hook has multiple shebangs, it got appended repeatedly.
    """
    return existing_text.count("#!") > 1


def install_pre_commit_hook(repo_path: str = ".", mode: str = "strict") -> tuple[bool, str]:
    repo = Path(repo_path).resolve()
    git_dir = find_git_dir(repo)
    if not git_dir:
        return False, "Not a git repository (.git not found)."

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    hook_path = hooks_dir / "pre-commit"
    content = build_pre_commit_script(mode=mode).strip() + "\n"

    if hook_path.exists():
        existing = hook_path.read_text(encoding="utf-8", errors="ignore")

        # If our block exists -> replace it in-place
        if HOOK_MARKER_BEGIN in existing and HOOK_MARKER_END in existing:
            start = existing.index(HOOK_MARKER_BEGIN)
            end = existing.index(HOOK_MARKER_END) + len(HOOK_MARKER_END)

            new_content = (
                existing[:start].rstrip()
                + "\n"
                + content
                + existing[end:].lstrip()
            )
            hook_path.write_text(new_content, encoding="utf-8")
            write_hook_meta(git_dir, mode)

            try:
                hook_path.chmod(0o755)
            except Exception:
                pass

            return True, f"Updated repoclean pre-commit hook mode to {mode}."

        # If hook is corrupted (multiple shebangs) -> replace entirely
        if _is_hook_corrupted(existing):
            hook_path.write_text(content, encoding="utf-8")
            write_hook_meta(git_dir, mode)

            try:
                hook_path.chmod(0o755)
            except Exception:
                pass

            return True, "Replaced corrupted pre-commit hook with repoclean hook."

        # Otherwise: existing hook without repoclean block -> APPEND ours
        # (we don't want to destroy user's hook logic)
        new_content = existing.rstrip() + "\n\n" + content
        hook_path.write_text(new_content, encoding="utf-8")

    else:
        hook_path.write_text(content, encoding="utf-8")

    write_hook_meta(git_dir, mode)

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

    start = existing.index(HOOK_MARKER_BEGIN)
    end = existing.index(HOOK_MARKER_END) + len(HOOK_MARKER_END)
    new_content = (existing[:start] + existing[end:]).strip()

    if new_content:
        hook_path.write_text(new_content + "\n", encoding="utf-8")
        msg = "Removed repoclean block from existing pre-commit hook."
    else:
        hook_path.unlink()
        msg = "Removed pre-commit hook."

    meta_path = git_dir / HOOK_META_FILE
    if meta_path.exists():
        try:
            meta_path.unlink()
        except Exception:
            pass

    return True, msg
