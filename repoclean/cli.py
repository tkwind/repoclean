import argparse
from pathlib import Path
from rich.console import Console
from rich.table import Table
from repoclean.scanner import scan_repo
from repoclean.gitignore import get_default_gitignore
from repoclean.fixer import get_fix_targets, apply_fix
from repoclean.secrets import scan_secrets
from repoclean.rules import DEFAULT_MAX_FILE_MB
from repoclean.serializer import to_json, scanresult_to_dict, secrets_to_dict
from repoclean.hooks import install_pre_commit_hook, uninstall_pre_commit_hook
from repoclean.config_loader import load_config




console = Console()


def format_size(num_bytes: int) -> str:
    mb = num_bytes / (1024 * 1024)
    return f"{mb:.1f} MB"

def cmd_install_hook(args):
    ok, msg = install_pre_commit_hook(repo_path=args.path)
    if ok:
        console.print(msg)
    else:
        console.print(msg)
        raise SystemExit(1)


def cmd_uninstall_hook(args):
    ok, msg = uninstall_pre_commit_hook(repo_path=args.path)
    if ok:
        console.print(msg)
    else:
        console.print(msg)
        raise SystemExit(1)

def cmd_scan(args):
    cfg = load_config(args.path)
    max_mb = args.max_mb if args.max_mb is not None else cfg.max_file_mb
    result = scan_repo(repo_path=args.path, max_file_mb=max_mb, config=cfg)
    if args.json:
        print(to_json(scanresult_to_dict(result)))
        return
    console.print(f"\n[bold]Repo:[/bold] {result.repo_path}")
    console.print(f"[bold]Git repo:[/bold] {'yes' if result.has_git else 'no'}")
    console.print(f"[bold].gitignore:[/bold] {'yes' if result.has_gitignore else 'no'}\n")


    table = Table(title="repoclean scan results", show_lines=True)
    table.add_column("Category", style="bold")
    table.add_column("Count")
    table.add_column("Notes")

    table.add_row("Junk folders", str(len(result.junk_dirs)), "Safe to ignore/remove")
    table.add_row("Junk files", str(len(result.junk_files)), "Safe to ignore/remove")
    table.add_row("Sensitive files", str(len(result.sensitive_files)), "Potential secrets")
    table.add_row("Large files", str(len(result.large_files)), f">{max_mb} MB")
    console.print(table)
    
    if result.sensitive_files:
        console.print("\n[bold red]Sensitive files found (review immediately):[/bold red]")
        for p in result.sensitive_files[:30]:
            console.print(f"  - {p}")
        if len(result.sensitive_files) > 30:
            console.print(f"  ... and {len(result.sensitive_files) - 30} more")

    if not result.has_gitignore:
        console.print("\n[bold yellow]Missing .gitignore[/bold yellow]")
        console.print("Suggested minimum .gitignore:\n")
        console.print(
            "[cyan]"
            "__pycache__/\n*.pyc\n.env\n.venv/\nvenv/\nnode_modules/\ndist/\nbuild/\n"
            "[/cyan]"
        )

    if result.large_files:
        console.print("\n[bold yellow]Large files:[/bold yellow]")
        for p, size in sorted(result.large_files, key=lambda x: x[1], reverse=True)[:20]:
            console.print(f"  - {p} ({format_size(size)})")


def cmd_init(args):
    repo_path = Path(args.path).resolve()
    gitignore_path = repo_path / ".gitignore"

    if gitignore_path.exists() and not args.force:
        console.print("[bold yellow].gitignore already exists. Use --force to overwrite.[/bold yellow]")
        return

    gitignore_path.write_text(get_default_gitignore(), encoding="utf-8")
    console.print(f"[bold green] Created .gitignore at:[/bold green] {gitignore_path}")


def cmd_fix(args):
    repo = Path(args.path).resolve()

    junk_dirs, junk_files = get_fix_targets(repo)

    if not junk_dirs and not junk_files:
        console.print("[bold green] Nothing to clean. Repo already clean.[/bold green]")
        return

    console.print("\n[bold]Fix Preview:[/bold]")
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

    if not args.yes:
        choice = input("\nProceed with deletion? (y/N): ").strip().lower()
        if choice != "y":
            console.print("[bold yellow]Cancelled.[/bold yellow]")
            return

    removed_dirs, removed_files = apply_fix(junk_dirs, junk_files)

    console.print(
        f"\n[bold green] Cleaned repo:[/bold green] removed {removed_dirs} folders and {removed_files} files."
    )


def cmd_secrets(args):
    cfg = load_config(args.path)
    max_kb = args.max_kb if args.max_kb is not None else cfg.max_secret_file_kb
    findings = scan_secrets(repo_path=args.path, max_kb=max_kb, config=cfg)
    
    if args.json:
        print(to_json(secrets_to_dict(findings)))
        if args.fail and len(findings) > 0:
            raise SystemExit(1)
        return
    
    if not findings:
        console.print("\n[bold green] No secret patterns found.[/bold green]")
        return
    
    console.print(f"\n[bold red] Potential secrets found: {len(findings)}[/bold red]\n")

    table = Table(title="Secrets Scan", show_lines=True)
    table.add_column("Type", style="bold red")
    table.add_column("File", style="bold")
    table.add_column("Line", justify="right")
    table.add_column("Preview")
    

    for f in findings[:100]:
        table.add_row(f.kind, f.file, str(f.line), f.preview)

    console.print(table)

    if len(findings) > 100:
        console.print(f"\n... and {len(findings) - 100} more")

    if args.fail:
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="repoclean",
        description="Repo hygiene scanner"
    )
    parser.add_argument("--version", action="version", version="repoclean 0.1.0")

    sub = parser.add_subparsers(dest="cmd", required=True)
    ih = sub.add_parser("install-hook", help="Install git pre-commit hook to prevent secret leaks")
    ih.add_argument("--path", default=".", help="Path to repo")
    ih.set_defaults(func=cmd_install_hook)

    uh = sub.add_parser("uninstall-hook", help="Remove repoclean block from git pre-commit hook")
    uh.add_argument("--path", default=".", help="Path to repo")
    uh.set_defaults(func=cmd_uninstall_hook)

    

    scan = sub.add_parser("scan", help="Scan current repo for common issues")
    scan.add_argument("--json", action="store_true", help="Output JSON report")
    scan.add_argument("--path", default=".", help="Path to repo")
    scan.add_argument("--max-mb", type=int, default=None, help="Large file threshold in MB")
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
    fix.set_defaults(func=cmd_fix)

    sec = sub.add_parser("secrets", help="Scan repo for secret/token patterns")
    sec.add_argument("--path", default=".", help="Path to repo")
    sec.add_argument("--json", action="store_true", help="Output JSON report")
    sec.add_argument("--max-kb", type=int, default=None, help="Skip files larger than this (KB)")
    sec.add_argument("--fail", action="store_true", help="Exit with code 1 if secrets are found")
    sec.set_defaults(func=cmd_secrets)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
