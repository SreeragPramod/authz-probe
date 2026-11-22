"""OpenAPI specification parser."""

import json
from pathlib import Path
from typing import Any, Dict, List
import yaml
from pydantic import BaseModel


class Operation(BaseModel):
    path: str
    method: str
    summary: str = ""
    parameters: List[Dict[str, Any]] = []

    @property
    def path_params(self) -> List[str]:
        """Extract parameter names that appear in the URL path."""
        params = []
        for p in self.parameters:
            if p.get("in") == "path":
                params.append(p.get("name"))
        return params


def load_openapi_spec(spec_path: str) -> List[Operation]:
    """Load an OpenAPI spec from JSON or YAML and extract operations."""
    path = Path(spec_path)
    if not path.exists():
        raise FileNotFoundError(f"OpenAPI spec not found at: {spec_path}")

    content = path.read_text(encoding="utf-8")
    data = json.loads(content) if path.suffix.lower() == ".json" else yaml.safe_load(content)

    operations: List[Operation] = []
    paths = data.get("paths", {})

    for route, methods in paths.items():
        for method, details in methods.items():
            if method.lower() in {"get", "post", "put", "patch", "delete"}:
                params = details.get("parameters", [])
                operations.append(
                    Operation(
                        path=route,
                        method=method.upper(),
                        summary=details.get("summary", ""),
                        parameters=params,
                    )
                )

    return operations
