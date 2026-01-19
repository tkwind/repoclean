import argparse
from pathlib import Path

from rich.console import Console
from rich.table import Table

from repoclean.config_loader import load_config
from repoclean.fixer import apply_fix, get_fix_targets
from repoclean.gitignore import get_default_gitignore
from repoclean.hooks import install_pre_commit_hook, uninstall_pre_commit_hook
from repoclean.scanner import scan_repo
from repoclean.secrets import scan_secrets
from repoclean.serializer import scanresult_to_dict, secrets_to_dict, to_json
from repoclean.tracked_junk import get_tracked_junk, fix_tracked_junk
from repoclean.serializer import trackedjunk_to_dict



SEVERITY_LEVELS = ["low", "medium", "high", "critical"]
console = Console()


FAIL_CATEGORIES = {
    "junk",
    "sensitive",
    "large",
    "secrets",
    # phase 5
    "tracked-junk",
    "gitignore",
    "env",
}


def format_size(num_bytes: int) -> str:
    mb = num_bytes / (1024 * 1024)
    return f"{mb:.1f} MB"

def cmd_tracked_junk(args):
    res = get_tracked_junk(args.path)

    if args.fix:
        removed_count, removed = fix_tracked_junk(args.path, tracked_junk=res.tracked_junk)
        if args.json:
            payload = {
                "repo_path": str(res.repo_path),
                "removed_count": removed_count,
                "removed": removed,
            }
            print(to_json(payload))
            return

        if removed_count == 0:
            console.print("[bold green]No tracked junk removed.[/bold green]")
            return

        console.print(f"[bold green]Removed tracked junk from index:[/bold green] {removed_count}")
        for p in removed[:50]:
            console.print(f"  - {p}")
        if len(removed) > 50:
            console.print(f"  ... and {len(removed) - 50} more")
        console.print("\nNow commit:")
        console.print('  git commit -m "remove tracked junk"')
        return

    if args.json:
        print(to_json(trackedjunk_to_dict(res)))
        return

    if not res.tracked_junk:
        console.print("\n[bold green]No tracked junk found.[/bold green]")
        return

    console.print(f"\n[bold yellow]Tracked junk found:[/bold yellow] {len(res.tracked_junk)}\n")
    for p in res.tracked_junk[:100]:
        console.print(f"  - {p}")
    if len(res.tracked_junk) > 100:
        console.print(f"\n... and {len(res.tracked_junk) - 100} more")

    console.print("\n[bold]Fix it with:[/bold]")
    console.print("  repoclean tracked-junk --fix")


def _parse_fail_on_list(s: str) -> set[str]:
    raw = {x.strip().lower() for x in (s or "").split(",") if x.strip()}
    # allow alias
    normalized = set()
    for x in raw:
        if x == "trackedjunk":
            normalized.add("tracked-junk")
        else:
            normalized.add(x)
    return normalized


def cmd_install_hook(args):
    ok, msg = install_pre_commit_hook(args.path, mode=args.mode)
    console.print(msg)
    if not ok:
        raise SystemExit(1)


def cmd_uninstall_hook(args):
    ok, msg = uninstall_pre_commit_hook(repo_path=args.path)
    console.print(msg)
    if not ok:
        raise SystemExit(1)


def cmd_ci(args):
    cfg = load_config(args.path)

    max_mb = cfg.max_file_mb
    max_kb = cfg.max_secret_file_kb
    fail_on = _parse_fail_on_list(args.fail_on)

    unknown = sorted({x for x in fail_on if x not in FAIL_CATEGORIES})
    if unknown:
        console.print(f"[bold red]Unknown fail-on categories:[/bold red] {', '.join(unknown)}")
        console.print(f"Valid: {', '.join(sorted(FAIL_CATEGORIES))}")
        raise SystemExit(2)

    scan_result = scan_repo(
        repo_path=args.path,
        max_file_mb=max_mb,
        config=cfg,
        staged_only=args.staged_only,
    )

    secret_findings = scan_secrets(
        repo_path=args.path,
        max_kb=max_kb,
        config=cfg,
        min_severity=args.secrets_min_severity,
    )

    # old checks
    failed_junk = ("junk" in fail_on) and ((len(scan_result.junk_dirs) + len(scan_result.junk_files)) > 0)
    failed_sensitive = ("sensitive" in fail_on) and (len(scan_result.sensitive_files) > 0)
    failed_large = ("large" in fail_on) and (len(scan_result.large_files) > 0)
    failed_secrets = ("secrets" in fail_on) and (len(secret_findings) > 0)

    # phase 5 checks (guard for old scan result types)
    failed_tracked_junk = ("tracked-junk" in fail_on) and (len(getattr(scan_result, "tracked_junk", [])) > 0)
    failed_gitignore = ("gitignore" in fail_on) and bool(getattr(scan_result, "gitignore_missing", False))
    failed_env = ("env" in fail_on) and bool(getattr(scan_result, "env_unignored", False))

    exit_code = (
        1
        if (
            failed_junk
            or failed_sensitive
            or failed_large
            or failed_secrets
            or failed_tracked_junk
            or failed_gitignore
            or failed_env
        )
        else 0
    )

    if args.json:
        payload = {
            "repo_path": str(scan_result.repo_path),
            "scan": scanresult_to_dict(scan_result),
            "secrets": secrets_to_dict(secret_findings),
            "fail_on": sorted(fail_on),
            "failed": {
                "junk": failed_junk,
                "sensitive": failed_sensitive,
                "large": failed_large,
                "secrets": failed_secrets,
                "tracked-junk": failed_tracked_junk,
                "gitignore": failed_gitignore,
                "env": failed_env,
            },
            "exit_code": exit_code,
            "mode": "staged-only" if args.staged_only else "full",
        }
        print(to_json(payload))
        raise SystemExit(exit_code)

    console.print("\n[bold]repoclean CI summary[/bold]\n")
    console.print(f"Repo: {scan_result.repo_path}")
    console.print(f"Mode: {'staged-only' if args.staged_only else 'full'}")
    console.print(f"Fail-on: {', '.join(sorted(fail_on)) if fail_on else '(none)'}")

    console.print(f"Health: {getattr(scan_result, 'repo_health_score', 'n/a')}/100")
    console.print(f"Junk items: {len(scan_result.junk_dirs) + len(scan_result.junk_files)}")
    console.print(f"Sensitive files: {len(scan_result.sensitive_files)}")
    console.print(f"Tracked junk: {len(getattr(scan_result, 'tracked_junk', []))}")
    console.print(f"Large files: {len(scan_result.large_files)}")
    console.print(f"Secrets found: {len(secret_findings)}")
    if getattr(scan_result, "gitignore_missing", False):
        console.print("[bold yellow].gitignore missing[/bold yellow]")
    if getattr(scan_result, "env_unignored", False):
        console.print("[bold red].env exists but is not ignored[/bold red]")

    console.print("\nCI status: PASS" if exit_code == 0 else "\nCI status: FAIL")
    raise SystemExit(exit_code)


def cmd_scan(args):
    cfg = load_config(args.path)
    max_mb = args.max_mb if args.max_mb is not None else cfg.max_file_mb

    result = scan_repo(
        repo_path=args.path,
        max_file_mb=max_mb,
        config=cfg,
        staged_only=args.staged_only,
    )

    if args.json:
        print(to_json(scanresult_to_dict(result)))
        return

    console.print(f"\n[bold]Repo:[/bold] {result.repo_path}")
    console.print(f"[bold]Git repo:[/bold] {'yes' if result.has_git else 'no'}")
    console.print(f"[bold].gitignore:[/bold] {'yes' if result.has_gitignore else 'no'}")
    if args.staged_only:
        console.print("[bold cyan]Mode:[/bold cyan] staged-only\n")
    else:
        console.print("")

    # health score is phase 5
    if hasattr(result, "repo_health_score"):
        console.print(f"[bold]Repo Health:[/bold] {result.repo_health_score}/100\n")

    table = Table(title="repoclean scan results", show_lines=True)
    table.add_column("Category", style="bold")
    table.add_column("Count")
    table.add_column("Notes")

    table.add_row("Junk folders", str(len(result.junk_dirs)), "Safe to ignore/remove")
    table.add_row("Junk files", str(len(result.junk_files)), "Safe to ignore/remove")
    table.add_row("Sensitive files", str(len(result.sensitive_files)), "Potential secrets")
    table.add_row("Large files", str(len(result.large_files)), f">{max_mb} MB")

    tracked_junk = getattr(result, "tracked_junk", [])
    table.add_row("Tracked junk", str(len(tracked_junk)), "Already committed/being tracked")

    table.add_row(
        ".gitignore",
        "missing" if getattr(result, "gitignore_missing", False) else "ok",
        "Required for clean repos",
    )
    table.add_row(
        ".env ignored",
        "no" if getattr(result, "env_unignored", False) else "yes",
        ".env should never be tracked",
    )

    console.print(table)

    # phase 5 suggestions
    if getattr(result, "gitignore_missing", False):
        console.print("\n[bold yellow]Suggestion:[/bold yellow] Run:")
        console.print("  repoclean init")

    if getattr(result, "env_unignored", False):
        console.print("\n[bold red]Danger:[/bold red] .env exists but isn't ignored.")
        console.print("Add '.env' to .gitignore immediately.")

    if tracked_junk:
        console.print("\n[bold yellow]Tracked junk detected:[/bold yellow]")
        for p in tracked_junk[:30]:
            console.print(f"  - {p}")
        if len(tracked_junk) > 30:
            console.print(f"  ... and {len(tracked_junk) - 30} more")
        console.print("\n[bold]Fix suggestion:[/bold]")
        console.print("  git rm -r --cached __pycache__")
        console.print("  git rm --cached *.pyc")
        console.print("  git commit -m \"remove tracked junk\"")

    if result.sensitive_files:
        console.print("\n[bold red]Sensitive files found (review immediately):[/bold red]")
        for p in result.sensitive_files[:30]:
            console.print(f"  - {p}")
        if len(result.sensitive_files) > 30:
            console.print(f"  ... and {len(result.sensitive_files) - 30} more")

    if result.large_files:
        console.print("\n[bold yellow]Large files:[/bold yellow]")
        for p, size in sorted(result.large_files, key=lambda x: x[1], reverse=True)[:20]:
            console.print(f"  - {p} ({format_size(size)})")

    fail_on = _parse_fail_on_list(args.fail_on)
    unknown = sorted({x for x in fail_on if x not in FAIL_CATEGORIES})
    if unknown:
        console.print(f"[bold red]Unknown fail-on categories:[/bold red] {', '.join(unknown)}")
        raise SystemExit(2)

    fail = False
    if "junk" in fail_on and (len(result.junk_dirs) + len(result.junk_files)) > 0:
        fail = True
    if "sensitive" in fail_on and len(result.sensitive_files) > 0:
        fail = True
    if "large" in fail_on and len(result.large_files) > 0:
        fail = True
    if "tracked-junk" in fail_on and len(getattr(result, "tracked_junk", [])) > 0:
        fail = True
    if "gitignore" in fail_on and bool(getattr(result, "gitignore_missing", False)):
        fail = True
    if "env" in fail_on and bool(getattr(result, "env_unignored", False)):
        fail = True

    if fail:
        raise SystemExit(1)


def cmd_init(args):
    repo_path = Path(args.path).resolve()
    gitignore_path = repo_path / ".gitignore"

    if gitignore_path.exists() and not args.force:
        console.print("[bold yellow].gitignore already exists. Use --force to overwrite.[/bold yellow]")
        return

    gitignore_path.write_text(get_default_gitignore(), encoding="utf-8")
    console.print(f"[bold green] Created .gitignore at:[/bold green] {gitignore_path}")


def cmd_config_init(args):
    repo = Path(args.path).resolve()
    cfg_path = repo / ".repoclean.toml"

    if cfg_path.exists() and not args.force:
        console.print(".repoclean.toml already exists. Use --force to overwrite.")
        return

    from repoclean.config_template import DEFAULT_REPOCLEAN_TOML
    cfg_path.write_text(DEFAULT_REPOCLEAN_TOML, encoding="utf-8")
    console.print(f"Created config at: {cfg_path}")


def cmd_fix(args):
    repo = Path(args.path).resolve()
    cfg = load_config(args.path)

    junk_dirs, junk_files = get_fix_targets(
        repo,
        config=cfg,
        staged_only=args.staged_only,
    )

    if not junk_dirs and not junk_files:
        console.print("[bold green] Nothing to clean. Repo already clean.[/bold green]")
        return

    title = "Fix Preview (staged-only)" if args.staged_only else "Fix Preview"
    console.print(f"\n[bold]{title}:[/bold]")
    console.print(f"Junk folders to remove: [yellow]{len(junk_dirs)}[/yellow]")
    console.print(f"Junk files to remove: [yellow]{len(junk_files)}[/yellow]\n")

    if args.verbose:
        if junk_dirs:
            console.print("[bold]Folders:[/bold]")
            for d in junk_dirs[:50]:
                console.print(f"  - {d.relative_to(repo).as_posix()}")
            if len(junk_dirs) > 50:
                console.print(f"  ... and {len(junk_dirs)-50} more")

        if junk_files:
            console.print("\n[bold]Files:[/bold]")
            for f in junk_files[:50]:
                console.print(f"  - {f.relative_to(repo).as_posix()}")
            if len(junk_files) > 50:
                console.print(f"  ... and {len(junk_files)-50} more")

    if args.dry_run:
        console.print("\n[bold cyan]Dry-run mode: no changes made.[/bold cyan]")
        return

    if args.unstage and not args.staged_only:
        console.print("[bold red]--unstage only works with --staged-only[/bold red]")
        raise SystemExit(2)

    if not args.yes:
        choice = input("\nProceed with cleanup? (y/N): ").strip().lower()
        if choice != "y":
            console.print("[bold yellow]Cancelled.[/bold yellow]")
            return

    removed_dirs, removed_files = apply_fix(
        junk_dirs,
        junk_files,
        repo=repo,
        staged_only=args.staged_only,
        unstage=args.unstage,
    )

    if args.unstage:
        console.print("\n[bold green] Cleaned staged commit:[/bold green] junk files unstaged (not deleted).")
    else:
        console.print(
            f"\n[bold green] Cleaned repo:[/bold green] removed {removed_dirs} folders and {removed_files} files."
        )


def cmd_hook_print(args):
    from repoclean.hooks import build_pre_commit_script
    print(build_pre_commit_script(mode=args.mode))


def cmd_hook_status(args):
    from repoclean.hooks import get_hook_status
    st = get_hook_status(args.path)

    console.print(f"\nRepo: {st['repo_path']}")
    console.print(f"Git repo: {'yes' if st['has_git'] else 'no'}")
    if not st["has_git"]:
        return

    console.print(f"Hook: {'installed' if st['hook_installed'] else 'not installed'}")
    console.print(f"Hook path: {st['hook_path']}")
    console.print(f"Mode: {st['mode']}")
    console.print(f"Metadata: {'present' if st['has_metadata'] else 'missing'}")


def cmd_secrets(args):
    from repoclean.secrets import SEVERITY_ORDER

    cfg = load_config(args.path)
    max_kb = args.max_kb if args.max_kb is not None else cfg.max_secret_file_kb

    findings = scan_secrets(
        repo_path=args.path,
        max_kb=max_kb,
        config=cfg,
        min_severity=args.min_severity,
    )

    if args.json:
        print(to_json(secrets_to_dict(findings)))

        if getattr(args, "fail_on", None):
            fail_threshold = SEVERITY_ORDER[args.fail_on]
            if any(SEVERITY_ORDER[f.severity] >= fail_threshold for f in findings):
                raise SystemExit(1)
        return

    if not findings:
        console.print("\n[bold green] No secret patterns found.[/bold green]")
        return

    console.print(f"\n[bold red] Potential secrets found: {len(findings)}[/bold red]\n")

    table = Table(title="Secrets Scan", show_lines=True)
    table.add_column("Severity", style="bold")
    table.add_column("Type", style="bold red")
    table.add_column("File", style="bold")
    table.add_column("Line", justify="right")
    table.add_column("Preview")

    for f in findings[:100]:
        table.add_row(f.severity.upper(), f.kind, f.file, str(f.line), f.preview)

    console.print(table)

    if len(findings) > 100:
        console.print(f"\n... and {len(findings) - 100} more")

    if args.fail and not args.fail_on:
        args.fail_on = "low"

    if getattr(args, "fail_on", None):
        fail_threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= fail_threshold for f in findings):
            raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(prog="repoclean", description="Repo hygiene scanner")
    parser.add_argument("--version", action="version", version="repoclean 0.8.0")

    sub = parser.add_subparsers(dest="cmd", required=True)

    ih = sub.add_parser("install-hook", help="Install git pre-commit hook")
    ih.add_argument("--mode", choices=["strict", "warn"], default="strict", help="Hook mode")
    ih.add_argument("--path", default=".", help="Path to repo")
    ih.set_defaults(func=cmd_install_hook)

    uh = sub.add_parser("uninstall-hook", help="Remove repoclean block from pre-commit hook")
    uh.add_argument("--path", default=".", help="Path to repo")
    uh.set_defaults(func=cmd_uninstall_hook)

    hook = sub.add_parser("hook", help="Hook utilities")
    hook_sub = hook.add_subparsers(dest="hook_cmd", required=True)

    hook_print = hook_sub.add_parser("print", help="Print the pre-commit hook script")
    hook_print.add_argument("--mode", choices=["strict", "warn"], default="strict")
    hook_print.set_defaults(func=cmd_hook_print)

    hook_status = hook_sub.add_parser("status", help="Show hook installation status")
    hook_status.add_argument("--path", default=".")
    hook_status.set_defaults(func=cmd_hook_status)

    cfg = sub.add_parser("config", help="Repoclean configuration utilities")
    cfg_sub = cfg.add_subparsers(dest="cfg_cmd", required=True)

    cfg_init = cfg_sub.add_parser("init", help="Create a default .repoclean.toml config")
    cfg_init.add_argument("--path", default=".", help="Path to repo")
    cfg_init.add_argument("--force", action="store_true", help="Overwrite existing config")
    cfg_init.set_defaults(func=cmd_config_init)

    scan = sub.add_parser("scan", help="Scan current repo for common issues")
    scan.add_argument(
        "--fail-on",
        default="",
        help="Comma-separated categories: junk,sensitive,large,secrets,tracked-junk,gitignore,env",
    )
    scan.add_argument("--json", action="store_true", help="Output JSON report")
    scan.add_argument("--path", default=".", help="Path to repo")
    scan.add_argument("--max-mb", type=int, default=None, help="Large file threshold in MB")
    scan.add_argument("--staged-only", action="store_true", help="Scan only staged files")
    scan.set_defaults(func=cmd_scan)

    init = sub.add_parser("init", help="Create a default .gitignore in the repo")
    init.add_argument("--path", default=".", help="Path to repo")
    init.add_argument("--force", action="store_true", help="Overwrite existing .gitignore")
    init.set_defaults(func=cmd_init)

    fix = sub.add_parser("fix", help="Remove common junk files/folders safely")
    fix.add_argument("--path", default=".", help="Path to repo")
    fix.add_argument("--dry-run", action="store_true", help="Preview what would be removed")
    fix.add_argument("--yes", action="store_true", help="Skip confirmation prompt")
    fix.add_argument("--verbose", action="store_true", help="Print files/folders to be removed")

    fix.add_argument("--staged-only", action="store_true", help="Only clean junk staged for commit")
    fix.add_argument("--unstage", action="store_true", help="Only unstage staged junk (do not delete)")
    fix.set_defaults(func=cmd_fix)
    
    tj = sub.add_parser("tracked-junk", help="Detect / fix junk files already tracked in git history")
    tj.add_argument("--path", default=".", help="Path to repo")
    tj.add_argument("--json", action="store_true", help="Output JSON")
    tj.add_argument("--fix", action="store_true", help="Remove tracked junk from git index (keeps files on disk)")
    tj.set_defaults(func=cmd_tracked_junk)


    sec = sub.add_parser("secrets", help="Scan repo for secret/token patterns")
    sec.add_argument("--min-severity", choices=SEVERITY_LEVELS, default="low", help="Minimum severity to report")
    sec.add_argument("--fail-on", choices=SEVERITY_LEVELS, default=None, help="Exit with code 1 if >= this severity")
    sec.add_argument("--path", default=".", help="Path to repo")
    sec.add_argument("--json", action="store_true", help="Output JSON report")
    sec.add_argument("--max-kb", type=int, default=None, help="Skip files larger than this (KB)")
    sec.add_argument("--fail", action="store_true", help="Exit with code 1 if secrets are found")
    sec.set_defaults(func=cmd_secrets)

    ci = sub.add_parser("ci", help="Run repoclean checks for CI pipelines")
    ci.add_argument("--path", default=".", help="Path to repo")
    ci.add_argument("--json", action="store_true", help="Output JSON report")
    ci.add_argument(
        "--fail-on",
        default="secrets,sensitive,large",
        help="Comma-separated categories: junk,sensitive,large,secrets,tracked-junk,gitignore,env",
    )
    ci.add_argument(
        "--secrets-min-severity",
        choices=SEVERITY_LEVELS,
        default="low",
        help="Minimum severity for secrets failing",
    )
    ci.add_argument("--staged-only", action="store_true", help="CI checks only staged files")
    ci.set_defaults(func=cmd_ci)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
