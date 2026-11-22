"""Markdown and JSON report generators with secret redaction."""

import json
import re
from pathlib import Path
from typing import List
from authzprobe.engine import Finding


def redact_secrets(text: str) -> str:
    """Mask JWT tokens and sensitive bearer headers."""
    # Matches Bearer eyJ... tokens
    jwt_pattern = r"(Bearer\s+)[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"
    return re.sub(jwt_pattern, r"\1[REDACTED_JWT]", text, flags=re.IGNORECASE)


def generate_markdown_report(findings: List[Finding], target_url: str) -> str:
    """Produce a GitHub-flavored Markdown security report."""
    vulns = [f for f in findings if f.verdict.value in ("VULNERABLE", "SUSPICIOUS")]

    md = [
        f"# 🛡️ authz-probe Security Assessment Report",
        f"\n**Target:** `{target_url}`",
        f"**Total Findings:** {len(vulns)}\n",
        "| Severity | Type | Endpoint | Tested Identity | Status |",
        "|:---:|:---|:---|:---:|:---:|",
    ]

    for f in vulns:
        badge = "🔴 HIGH" if f.severity.value == "HIGH" else "🟡 MEDIUM"
        md.append(f"| {badge} | {f.vuln_type.value} | `{f.method} {f.path}` | `{f.tested_identity}` | `{f.status_code}` |")

    md.append("\n## Detailed Findings & Remediation\n")

    for idx, f in enumerate(vulns, 1):
        md.append(f"### {idx}. {f.vuln_type.value} on `{f.path}`")
        md.append(f"- **Severity:** `{f.severity.value}`")
        md.append(f"- **Tested Identity:** `{f.tested_identity}`")
        md.append(f"- **HTTP Response:** `{f.status_code}`")
        md.append(f"- **Evidence:** {redact_secrets(f.detail)}")
        md.append(f"- **💡 Remediation:** {f.remediation}\n")

    return "\n".join(md)


def export_reports(findings: List[Finding], target_url: str, md_path: str = None, json_path: str = None):
    """Write markdown and JSON reports to disk if paths are provided."""
    if md_path:
        content = generate_markdown_report(findings, target_url)
        Path(md_path).write_text(content, encoding="utf-8")

    if json_path:
        data = [f.model_dump() for f in findings]
        Path(json_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
