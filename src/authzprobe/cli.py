"""Command-line interface for authz-probe with grouped findings and severity ratings."""

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from authzprobe import __version__
from authzprobe.spec import load_openapi_spec
from authzprobe.policy import load_policy
from authzprobe.engine import run_cross_identity_tests
from authzprobe.verdict import Verdict, Severity

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
    """Run authorization tests and display findings grouped by type and severity."""
    console.print(Panel(
        f"[bold white]authz-probe v{__version__}[/bold white]\n"
        f"Target: [green]{base_url}[/green] | Spec: [yellow]{spec}[/yellow]",
        title="[bold cyan]API Authorization Security Scanner[/bold cyan]",
        expand=False,
    ))

    operations = load_openapi_spec(spec)
    policy_data = load_policy(policy)

    target_seed = {"username": "alice"}
    findings = run_cross_identity_tests(
        operations=operations,
        policy=policy_data,
        base_url=base_url,
        target_object_map=target_seed,
    )

    # Filter to findings that require attention (VULNERABLE and SUSPICIOUS)
    vulnerabilities = [f for f in findings if f.verdict in (Verdict.VULNERABLE, Verdict.SUSPICIOUS)]

    if not vulnerabilities:
        console.print("\n[bold green]✔ No authorization vulnerabilities detected![/bold green]\n")
        return

    # Build Beautiful Rich Table
    table = Table(title="🚨 Authorization Findings Detected", show_lines=True)
    table.add_column("Type", style="bold magenta", no_wrap=True)
    table.add_column("Severity", justify="center")
    table.add_column("Endpoint", style="bold")
    table.add_column("Tested By", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Remediation Hint", style="italic yellow")

    for f in vulnerabilities:
        # Color code severity
        if f.severity == Severity.HIGH:
            sev_style = "[bold red]HIGH[/bold red]"
        elif f.severity == Severity.MEDIUM:
            sev_style = "[bold yellow]MEDIUM[/bold yellow]"
        else:
            sev_style = "[blue]LOW[/blue]"

        table.add_row(
            f.vuln_type.value,
            sev_style,
            f"{f.method} {f.path}",
            f.tested_identity,
            str(f.status_code),
            f.remediation,
        )

    console.print("\n")
    console.print(table)
    console.print(f"\n[bold red]Total Findings:[/bold red] {len(vulnerabilities)} authorization failure(s) identified.\n")


@app.command()
def version():
    """Show tool version."""
    console.print(f"authz-probe v{__version__}")


if __name__ == "__main__":
    app()
