"""Verdict classification engine with vulnerability types and remediation hints."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel


class Verdict(str, Enum):
    VULNERABLE = "VULNERABLE"
    SUSPICIOUS = "SUSPICIOUS"
    OK = "OK"


class VulnType(str, Enum):
    BOLA = "BOLA / IDOR (API1:2023)"
    BFLA = "BFLA (API5:2023)"
    MISSING_AUTH = "Missing Authentication (API2:2023)"
    UNKNOWN = "Unknown / Suspicious"


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Evaluation(BaseModel):
    verdict: Verdict
    vuln_type: VulnType
    severity: Severity
    detail: str
    remediation: str


def evaluate_response(
    status_code: int,
    body_text: str,
    target_owner: Optional[str],
    requesting_identity: str,
    is_admin_endpoint: bool = False,
    is_anonymous: bool = False,
) -> Evaluation:
    """Evaluate whether an HTTP response indicates an authorization failure."""

    # 1. Access correctly rejected
    if status_code in (401, 403):
        return Evaluation(
            verdict=Verdict.OK,
            vuln_type=VulnType.UNKNOWN,
            severity=Severity.INFO,
            detail=f"Access correctly denied with HTTP {status_code}",
            remediation="None needed.",
        )

    # 2. Resource masked (404)
    if status_code == 404:
        return Evaluation(
            verdict=Verdict.OK,
            vuln_type=VulnType.UNKNOWN,
            severity=Severity.INFO,
            detail="Resource masked or not found (HTTP 404)",
            remediation="None needed.",
        )

    # 3. Successful responses (200, 201, etc.)
    if 200 <= status_code < 300:
        # Case A: Missing Authentication
        if is_anonymous:
            return Evaluation(
                verdict=Verdict.VULNERABLE,
                vuln_type=VulnType.MISSING_AUTH,
                severity=Severity.HIGH,
                detail=f"Endpoint accessible without authentication (HTTP {status_code})",
                remediation="Enforce authentication middleware or decorator (e.g., @login_required) on this route.",
            )

        # Case B: BFLA (Regular user accessing admin function)
        if is_admin_endpoint:
            return Evaluation(
                verdict=Verdict.VULNERABLE,
                vuln_type=VulnType.BFLA,
                severity=Severity.HIGH,
                detail=f"Administrative endpoint accessible by regular identity '{requesting_identity}'",
                remediation="Implement role-based access control (RBAC): verify caller has 'admin' role before executing.",
            )

        # Case C: BOLA (User accessing another user's object)
        if target_owner and target_owner.lower() in body_text.lower():
            return Evaluation(
                verdict=Verdict.VULNERABLE,
                vuln_type=VulnType.BOLA,
                severity=Severity.HIGH,
                detail=f"HTTP {status_code} leaked data of '{target_owner}' to unauthorized '{requesting_identity}'",
                remediation="Validate object ownership on every request: verify current_user.id == object.owner_id.",
            )

        # Case D: Empty or generic body (needs manual inspection)
        if not body_text.strip() or body_text.strip() in ("{}", "[]"):
            return Evaluation(
                verdict=Verdict.SUSPICIOUS,
                vuln_type=VulnType.UNKNOWN,
                severity=Severity.LOW,
                detail=f"HTTP {status_code} returned empty/blank payload",
                remediation="Ensure authorization failure returns 403 Forbidden rather than empty 200 OK.",
            )

        # Generic 200 OK on an object endpoint
        return Evaluation(
            verdict=Verdict.VULNERABLE,
            vuln_type=VulnType.BOLA,
            severity=Severity.HIGH,
            detail=f"HTTP {status_code} returned data without object ownership check",
            remediation="Enforce server-side ownership checks before returning database queries.",
        )

    return Evaluation(
        verdict=Verdict.OK,
        vuln_type=VulnType.UNKNOWN,
        severity=Severity.INFO,
        detail=f"HTTP {status_code}",
        remediation="None needed.",
    )
