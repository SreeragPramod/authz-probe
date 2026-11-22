"""Verdict classification engine for authorization responses."""

from enum import Enum
from typing import Optional


class Verdict(str, Enum):
    VULNERABLE = "VULNERABLE"
    SUSPICIOUS = "SUSPICIOUS"
    OK = "OK"


def evaluate_response(
    status_code: int,
    body_text: str,
    target_owner: str,
    requesting_identity: str,
) -> tuple[Verdict, str]:
    """Evaluate whether an HTTP response indicates an authorization failure."""

    # 1. Clear explicit rejection
    if status_code in (401, 403):
        return Verdict.OK, f"Access correctly denied with HTTP {status_code}"

    # 2. Information hiding / Not found rejection
    if status_code == 404:
        return Verdict.OK, "Resource masked or not found (HTTP 404)"

    # 3. Successful responses (200, 201, etc.)
    if 200 <= status_code < 300:
        # Check if the response leaked the actual owner identifier
        if target_owner and target_owner.lower() in body_text.lower():
            return (
                Verdict.VULNERABLE,
                f"HTTP {status_code} returned owner data ('{target_owner}') to unauthorized identity '{requesting_identity}'",
            )
       
        # If body is empty or very generic
        if not body_text.strip() or body_text.strip() in ("{}", "[]"):
            return (
                Verdict.SUSPICIOUS,
                f"HTTP {status_code} with empty/blank payload",
            )

        return (
            Verdict.VULNERABLE,
            f"HTTP {status_code} returned data without ownership validation",
        )

    return Verdict.OK, f"HTTP {status_code}"
