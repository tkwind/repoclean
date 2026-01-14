import argparse
from rich.console import Console
from rich.table import Table
from repoclean.gitignore import get_default_gitignore
from pathlib import Path


from repoclean.scanner import scan_repo
from repoclean.rules import DEFAULT_MAX_FILE_MB
from pathlib import Path
from repoclean.fixer import get_fix_targets, apply_fix


console = Console()


def format_size(num_bytes: int) -> str:
    mb = num_bytes / (1024 * 1024)
    return f"{mb:.1f} MB"

def cmd_fix(args):
    repo = Path(args.path).resolve()

    junk_dirs, junk_files = get_fix_targets(repo)

    if not junk_dirs and not junk_files:
        console.print("[bold green]✅ Nothing to clean. Repo already clean.[/bold green]")
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
                console.print(f"  - {f.relative_to(repo)}")
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
        f"\n[bold green]✅ Cleaned repo:[/bold green] removed {removed_dirs} folders and {removed_files} files."
    )

def cmd_init(args):
    repo_path = Path(args.path).resolve()
    gitignore_path = repo_path / ".gitignore"

    if gitignore_path.exists() and not args.force:
        console.print("[bold yellow].gitignore already exists. Use --force to overwrite.[/bold yellow]")
        return

    gitignore_path.write_text(get_default_gitignore(), encoding="utf-8")
    console.print(f"[bold green]✅ Created .gitignore at:[/bold green] {gitignore_path}")


def cmd_scan(args):
    result = scan_repo(repo_path=args.path, max_file_mb=args.max_mb)

    console.print(f"\n[bold]Repo:[/bold] {result.repo_path}")
    console.print(f"[bold]Git repo:[/bold] {'✅' if result.has_git else '❌'}")
    console.print(f"[bold].gitignore:[/bold] {'✅' if result.has_gitignore else '❌'}\n")

    # Junk dirs/files
    table = Table(title="repoclean scan results", show_lines=True)
    table.add_column("Category", style="bold")
    table.add_column("Count")
    table.add_column("Notes")

    table.add_row("Junk folders", str(len(result.junk_dirs)), "Safe to ignore/remove")
    table.add_row("Junk files", str(len(result.junk_files)), "Safe to ignore/remove")
    table.add_row("Sensitive files", str(len(result.sensitive_files)), "⚠️ Potential secrets")
    table.add_row("Large files", str(len(result.large_files)), f">{args.max_mb} MB")

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


def main():
    parser = argparse.ArgumentParser(prog="repoclean", description="Repo hygiene scanner")
    sub = parser.add_subparsers(dest="cmd", required=True)
    
    parser = argparse.ArgumentParser(...)
    parser.add_argument("--version", action="version", version="repoclean 0.1.0")


    fix = sub.add_parser("fix", help="Remove common junk files/folders safely")
    fix.add_argument("--path", default=".", help="Path to repo")
    fix.add_argument("--dry-run", action="store_true", help="Preview what would be removed")
    fix.add_argument("--yes", action="store_true", help="Skip confirmation prompt")
    fix.add_argument("--verbose", action="store_true", help="Print files/folders to be removed")
    fix.set_defaults(func=cmd_fix)

    init = sub.add_parser("init", help="Create a default .gitignore in the repo")
    init.add_argument("--path", default=".", help="Path to repo")
    init.add_argument("--force", action="store_true", help="Overwrite existing .gitignore")
    init.set_defaults(func=cmd_init)

    
    scan = sub.add_parser("scan", help="Scan current repo for common issues")
    scan.add_argument("--path", default=".", help="Path to repo")
    scan.add_argument("--max-mb", type=int, default=DEFAULT_MAX_FILE_MB, help="Large file threshold in MB")
    scan.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
