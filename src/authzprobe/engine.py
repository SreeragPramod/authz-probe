"""Core test replay engine supporting BOLA and BFLA checks."""

from typing import List, Dict, Any
import httpx
from pydantic import BaseModel

from authzprobe.spec import Operation
from authzprobe.policy import Policy, Identity
from authzprobe.verdict import Verdict, VulnType, Severity, Evaluation, evaluate_response


class Finding(BaseModel):
    path: str
    method: str
    target_owner: str
    tested_identity: str
    status_code: int
    verdict: Verdict
    vuln_type: VulnType
    severity: Severity
    detail: str
    remediation: str


def run_cross_identity_tests(
    operations: List[Operation],
    policy: Policy,
    base_url: str,
    target_object_map: Dict[str, str],
) -> List[Finding]:
    """Replay cross-identity authorization and function-level privilege tests."""
    findings: List[Finding] = []
    base_url = base_url.rstrip("/")

    with httpx.Client(timeout=10.0) as client:
        for op in operations:
            if op.method != "GET":
                continue

            is_admin_route = "debug" in op.path.lower() or "admin" in op.path.lower()
            has_params = bool(op.path_params)

            # We test both object-parameterized endpoints AND admin/debug routes
            if not has_params and not is_admin_route:
                continue

            # Build target URL
            test_path = op.path
            owner = ""
            if has_params:
                for param_name in op.path_params:
                    if param_name in target_object_map:
                        owner = target_object_map[param_name]
                        test_path = test_path.replace(f"{{{param_name}}}", owner)
                if not owner:
                    continue

            # Replay against every identity in the policy
            for id_name, identity in policy.identities.items():
                if id_name == "user_a" and has_params:
                    # Skip legitimate owner testing their own resource
                    continue
                if id_name == "admin" and is_admin_route:
                    # Skip legitimate admin accessing admin route
                    continue

                headers = {}
                if identity.auth_header and identity.auth_header.strip() != "Bearer":
                    headers["Authorization"] = identity.auth_header

                url = f"{base_url}{test_path}"

                try:
                    response = client.get(url, headers=headers)
                    eval_result: Evaluation = evaluate_response(
                        status_code=response.status_code,
                        body_text=response.text,
                        target_owner=owner if has_params else None,
                        requesting_identity=id_name,
                        is_admin_endpoint=is_admin_route,
                        is_anonymous=(identity.role == "anonymous"),
                    )

                    findings.append(
                        Finding(
                            path=test_path,
                            method="GET",
                            target_owner=owner or "N/A",
                            tested_identity=id_name,
                            status_code=response.status_code,
                            verdict=eval_result.verdict,
                            vuln_type=eval_result.vuln_type,
                            severity=eval_result.severity,
                            detail=eval_result.detail,
                            remediation=eval_result.remediation,
                        )
                    )
                except Exception as exc:
                    findings.append(
                        Finding(
                            path=test_path,
                            method="GET",
                            target_owner=owner or "N/A",
                            tested_identity=id_name,
                            status_code=0,
                            verdict=Verdict.SUSPICIOUS,
                            vuln_type=VulnType.UNKNOWN,
                            severity=Severity.LOW,
                            detail=f"Request error: {str(exc)}",
                            remediation="Check API network connectivity and server logs.",
                        )
                    )

    return findings
