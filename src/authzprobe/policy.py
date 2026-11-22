"""Policy file loader with environment variable expansion."""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional
import yaml
from pydantic import BaseModel


class Identity(BaseModel):
    name: str
    auth_header: str
    role: str


class Policy(BaseModel):
    identities: Dict[str, Identity]


def expand_env_vars(text: str) -> str:
    """Replace ${VAR_NAME} with actual environment variable value."""
    pattern = re.compile(r"\$\{([A-Za-z0-9_]+)\}")

    def replacer(match):
        var_name = match.group(1)
        val = os.getenv(var_name)
        if val is None:
            return ""  # If unset, defaults to empty string
        return val

    return pattern.sub(replacer, text)


def load_policy(policy_path: str) -> Policy:
    """Load and parse the policy YAML file."""
    path = Path(policy_path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found at: {policy_path}")

    raw_text = path.read_text(encoding="utf-8")
    expanded_text = expand_env_vars(raw_text)
    data = yaml.safe_load(expanded_text)

    identities = {}
    for name, info in data.get("identities", {}).items():
        identities[name] = Identity(
            name=name,
            auth_header=info.get("auth_header", ""),
            role=info.get("role", "user"),
        )

    return Policy(identities=identities)
