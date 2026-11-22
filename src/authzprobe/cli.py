"""Command-line interface for authz-probe."""

import typer
from rich.console import Console
from rich.table import Table

from authzprobe import __version__
from authzprobe.spec import load_openapi_spec
from authzprobe.policy import load_policy
from authzprobe.engine import run_cross_identity_tests
from authzprobe.verdict import Verdict

app = typer.Typer(
    name="authz-probe",
    help="Spec-driven API authorization testing tool.",
)
console = Console()


@app.command()
def scan(
    spec: str = typer.Argument(..., help="Path to OpenAPI spec file"),
    policy: str = typer.Option(..., "--policy", "-p", help="Path to policy YAML file"),
    base_url: str = typer.Option(..., "--base-url", "-b", help="Base URL of target API"),
):
    """Run cross-identity authorization tests against an API."""
    console.print(f"[bold cyan]🔍 authz-probe v{__version__}[/bold cyan]")
    console.print(f"Target: [green]{base_url}[/green] | Spec: [yellow]{spec}[/yellow]\n")

    # 1. Load Spec and Policy
    operations = load_openapi_spec(spec)
    policy_data = load_policy(policy)

    # 2. Run scan with target seed mapping (alice belongs to user_a)
    target_seed = {"username": "alice"}
    findings = run_cross_identity_tests(
        operations=operations,
        policy=policy_data,
        base_url=base_url,
        target_object_map=target_seed,
    )

    # 3. Print Results in a Rich Table
    table = Table(title="Authorization Scan Results", show_lines=True)
    table.add_column("Endpoint", style="bold")
    table.add_column("Tested Identity", style="cyan")
    table.add_column("Status Code", justify="center")
    table.add_column("Verdict", justify="center")
    table.add_column("Details")

    for f in findings:
        if f.verdict == Verdict.VULNERABLE:
            verdict_style = "[bold red]VULNERABLE[/bold red]"
        elif f.verdict == Verdict.SUSPICIOUS:
            verdict_style = "[bold yellow]SUSPICIOUS[/bold yellow]"
        else:
            verdict_style = "[bold green]OK[/bold green]"

        table.add_row(
            f"{f.method} {f.path}",
            f.tested_identity,
            str(f.status_code),
            verdict_style,
            f.detail,
        )

    console.print(table)


@app.command()
def version():
    """Show tool version."""
    console.print(f"authz-probe v{__version__}")


if __name__ == "__main__":
    app()
