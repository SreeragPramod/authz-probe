"""Core test replay engine."""

from typing import List, Dict, Any
import httpx
from pydantic import BaseModel

from authzprobe.spec import Operation
from authzprobe.policy import Policy, Identity
from authzprobe.verdict import Verdict, evaluate_response


class Finding(BaseModel):
    path: str
    method: str
    target_owner: str
    tested_identity: str
    status_code: int
    verdict: Verdict
    detail: str


def run_cross_identity_tests(
    operations: List[Operation],
    policy: Policy,
    base_url: str,
    target_object_map: Dict[str, str],  # e.g., {"username": "alice"}
) -> List[Finding]:
    """Replay operations using other identities against target objects."""
    findings: List[Finding] = []
    base_url = base_url.rstrip("/")

    # Focus on GET operations for the MVP
    get_ops = [op for op in operations if op.method == "GET" and op.path_params]

    with httpx.Client(timeout=10.0) as client:
        for op in get_ops:
            # Substitute path parameters (e.g., /users/v1/{username} -> /users/v1/alice)
            test_path = op.path
            owner = None
            for param_name in op.path_params:
                if param_name in target_object_map:
                    owner = target_object_map[param_name]
                    test_path = test_path.replace(f"{{{param_name}}}", owner)

            if not owner:
                continue

            # For each identity that is NOT the owner, test access
            for id_name, identity in policy.identities.items():
                if id_name == "user_a":
                    # user_a is the legitimate owner of 'alice', skip self-test
                    continue

                headers = {}
                if identity.auth_header:
                    headers["Authorization"] = identity.auth_header

                url = f"{base_url}{test_path}"

                try:
                    response = client.get(url, headers=headers)
                    verdict, detail = evaluate_response(
                        status_code=response.status_code,
                        body_text=response.text,
                        target_owner=owner,
                        requesting_identity=id_name,
                    )

                    findings.append(
                        Finding(
                            path=test_path,
                            method="GET",
                            target_owner=owner,
                            tested_identity=id_name,
                            status_code=response.status_code,
                            verdict=verdict,
                            detail=detail,
                        )
                    )
                except Exception as exc:
                    findings.append(
                        Finding(
                            path=test_path,
                            method="GET",
                            target_owner=owner,
                            tested_identity=id_name,
                            status_code=0,
                            verdict=Verdict.SUSPICIOUS,
                            detail=f"Request error: {str(exc)}",
                        )
                    )

    return findings
