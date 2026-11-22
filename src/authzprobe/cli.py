"""Command-line interface with reporting exports and CI exit codes."""

import sys
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from authzprobe import __version__
from authzprobe.spec import load_openapi_spec
from authzprobe.policy import load_policy
from authzprobe.engine import run_cross_identity_tests
from authzprobe.verdict import Verdict, Severity
from authzprobe.reporters.markdown import export_reports
from authzprobe.reporters.sarif import export_sarif

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
    output_md: str = typer.Option(None, "--output-md", help="Export Markdown report to path"),
    output_json: str = typer.Option(None, "--output-json", help="Export JSON report to path"),
    output_sarif: str = typer.Option(None, "--output-sarif", help="Export SARIF report to path"),
    fail_on_vuln: bool = typer.Option(True, "--fail/--no-fail", help="Exit with non-zero code on findings"),
):
    """Run authorization tests and optionally export reports."""
    console.print(Panel(
        f"[bold white]authz-probe v{__version__}[/bold white]\n"
        f"Target: [green]{base_url}[/green] | Spec: [yellow]{spec}[/yellow]",
        title="[bold cyan]API Authorization Security Scanner[/bold cyan]",
        expand=False,
    ))

    operations = load_openapi_spec(spec)
    policy_data = load_policy(policy)

    target_seed = {
        "username": "alice",
        "doc_id": "alice_doc",
        "id": "alice",
        "user": "alice",
    }
    findings = run_cross_identity_tests(
        operations=operations,
        policy=policy_data,
        base_url=base_url,
        target_object_map=target_seed,
    )

    vulnerabilities = [f for f in findings if f.verdict in (Verdict.VULNERABLE, Verdict.SUSPICIOUS)]

    # 1. Print Rich Console Table
    if vulnerabilities:
        table = Table(title="🚨 Authorization Findings Detected", show_lines=True)
        table.add_column("Type", style="bold magenta", no_wrap=True)
        table.add_column("Severity", justify="center")
        table.add_column("Endpoint", style="bold")
        table.add_column("Tested By", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Remediation Hint", style="italic yellow")

        for f in vulnerabilities:
            sev_style = "[bold red]HIGH[/bold red]" if f.severity == Severity.HIGH else "[bold yellow]MEDIUM[/bold yellow]"
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
    else:
        console.print("\n[bold green]✔ No authorization vulnerabilities detected![/bold green]\n")

    # 2. Export Files
    if output_md or output_json:
        export_reports(findings, base_url, md_path=output_md, json_path=output_json)
        if output_md:
            console.print(f"[green]✔ Saved Markdown report to:[/green] {output_md}")
        if output_json:
            console.print(f"[green]✔ Saved JSON report to:[/green] {output_json}")

    if output_sarif:
        export_sarif(findings, base_url, output_sarif)
        console.print(f"[green]✔ Saved SARIF report to:[/green] {output_sarif}")

    # 3. CI Exit Code
    if vulnerabilities and fail_on_vuln:
        console.print("[bold red]❌ CI Status: FAILED (Vulnerabilities detected)[/bold red]")
        sys.exit(1)
    else:
        sys.exit(0)


@app.command()
def version():
    """Show tool version."""
    console.print(f"authz-probe v{__version__}")


if __name__ == "__main__":
    app()
