"""SARIF 2.1.0 generator for GitHub Code Scanning integration."""

import json
from pathlib import Path
from typing import List
from authzprobe.engine import Finding


def generate_sarif(findings: List[Finding], target_url: str) -> dict:
    """Generate SARIF JSON structure for authorization findings."""
    rules = []
    results = []
    seen_rules = set()

    rule_definitions = {
        "BOLA": {
            "id": "AUTHZ-001",
            "name": "BrokenObjectLevelAuthorization",
            "shortDescription": {"text": "Broken Object Level Authorization (BOLA/IDOR)"},
            "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        },
        "BFLA": {
            "id": "AUTHZ-002",
            "name": "BrokenFunctionLevelAuthorization",
            "shortDescription": {"text": "Broken Function Level Authorization (BFLA)"},
            "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
        },
        "Missing Authentication": {
            "id": "AUTHZ-003",
            "name": "MissingAuthentication",
            "shortDescription": {"text": "Unauthenticated access to protected resource"},
            "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
        },
    }

    for f in findings:
        if f.verdict.value not in ("VULNERABLE", "SUSPICIOUS"):
            continue

        rule_key = "BOLA"
        if "BFLA" in f.vuln_type.value:
            rule_key = "BFLA"
        elif "Missing" in f.vuln_type.value:
            rule_key = "Missing Authentication"

        rule_info = rule_definitions.get(rule_key, rule_definitions["BOLA"])
        rule_id = rule_info["id"]

        if rule_id not in seen_rules:
            rules.append({
                "id": rule_id,
                "name": rule_info["name"],
                "shortDescription": rule_info["shortDescription"],
                "help": {"text": f.remediation},
                "helpUri": rule_info["helpUri"],
                "properties": {"precision": "very-high"},
            })
            seen_rules.add(rule_id)

        results.append({
            "ruleId": rule_id,
            "level": "error" if f.severity.value == "HIGH" else "warning",
            "message": {"text": f"{f.vuln_type.value} detected on {f.method} {f.path}: {f.detail}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path.lstrip("/")},
                }
            }],
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "authz-probe",
                    "version": "0.1.0",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }


def export_sarif(findings: List[Finding], target_url: str, sarif_path: str):
    """Write SARIF output to file."""
    sarif_data = generate_sarif(findings, target_url)
    Path(sarif_path).write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
