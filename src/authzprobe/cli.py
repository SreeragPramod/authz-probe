"""Command-line entry point for authz-probe."""

import typer
from rich.console import Console

from authzprobe import __version__

app = typer.Typer(
    name="authz-probe",
    help="API authorization tester — detects BOLA, BFLA, and missing auth.",
)
console = Console()


@app.command()
def scan(
    spec: str = typer.Argument(..., help="Path to the OpenAPI spec file (YAML/JSON)"),
    policy: str = typer.Option(..., "--policy", "-p", help="Path to the policy file"),
    base_url: str = typer.Option(..., "--base-url", "-b", help="Base URL of the target API"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be tested without sending requests"),
):
    """Run authorization tests against an API."""
    console.print(f"[bold green]authz-probe v{__version__}[/bold green]")
    console.print(f"  Spec:     {spec}")
    console.print(f"  Policy:   {policy}")
    console.print(f"  Base URL: {base_url}")
    console.print(f"  Dry run:  {dry_run}")
    console.print("\n[yellow]⚠ Scanner engine not implemented yet — coming in Phase 4![/yellow]")


@app.command()
def version():
    """Show the tool version."""
    console.print(f"authz-probe v{__version__}")


if __name__ == "__main__":
    app()
