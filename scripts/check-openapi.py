#!/usr/bin/env python3
"""Validate the contract and exact explicit route coverage (no running server).

Install the validator in an isolated environment, not the application's dependencies:
  python3 -m venv /tmp/cdt-openapi-check
  /tmp/cdt-openapi-check/bin/pip install openapi-spec-validator==0.7.2
  /tmp/cdt-openapi-check/bin/python scripts/check-openapi.py
Runtime/schema and Go AST coverage tests: go test ./internal/httpapi -run TestOpenAPI

The .yaml intentionally uses JSON syntax, a YAML 1.2 subset, allowing the Go
standard library to consume the same contract without a new Go dependency.
"""

import json
from pathlib import Path
import re
import sys


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON member: {key}")
        result[key] = value
    return result


def main():
    try:
        from openapi_spec_validator import validate_spec
    except ImportError:
        sys.exit("Missing openapi-spec-validator. Install it in a venv as shown in this script's docstring.")
    root = Path(__file__).resolve().parents[1]
    spec = json.loads((root / "api/openapi.yaml").read_text(), object_pairs_hook=unique_object)

    # Fail closed on remote refs: validation never fetches application endpoints.
    def references(node):
        if isinstance(node, dict):
            if "$ref" in node:
                pointer = node["$ref"]
                if not pointer.startswith("#/"):
                    raise ValueError(f"Only local refs allowed: {pointer}")
                target = spec
                for part in pointer[2:].split("/"):
                    target = target[part.replace("~1", "/").replace("~0", "~")]
            for value in node.values():
                references(value)
        elif isinstance(node, list):
            for value in node:
                references(value)

    references(spec)
    validate_spec(spec)
    source = "\n".join(path.read_text() for path in sorted((root / "internal/httpapi").glob("*.go")) if not path.name.endswith("_test.go"))
    actual = set(re.findall(r'mux\.Handle(?:Func)?\("([A-Z]+) ([^\"]+)"', source))
    documented = {
        (method.upper(), path)
        for path, item in spec["paths"].items()
        for method in item
        if method in {"get", "head", "post", "put", "patch", "delete", "options", "trace"}
    }
    if actual != documented:
        raise ValueError(f"Route mismatch; missing={sorted(actual-documented)}, extra={sorted(documented-actual)}")
    operation_ids = []
    for path, item in spec["paths"].items():
        for method, operation in item.items():
            if (method.upper(), path) not in documented:
                continue
            operation_ids.append(operation["operationId"])
            if "security" not in operation:
                raise ValueError(f"Explicit security required: {method} {path}")
            if not any(code.startswith("2") for code in operation["responses"]):
                raise ValueError(f"Missing success response: {method} {path}")
            for response in operation["responses"].values():
                for media in response.get("content", {}).values():
                    if not media.get("schema"):
                        raise ValueError(f"Missing response shape: {method} {path}")
    if len(operation_ids) != len(set(operation_ids)):
        raise ValueError("Duplicate operationId")
    # Detect newly introduced handler error branches; middleware/helpers are also
    # exercised by the Go tests. This inventory deliberately checks literal error
    # codes, leaving dynamic human-readable messages unconstrained.
    statuses = {"BadRequest": "400", "Unauthorized": "401", "Forbidden": "403",
                "NotFound": "404", "Conflict": "409", "TooManyRequests": "429",
                "InternalServerError": "500", "BadGateway": "502", "ServiceUnavailable": "503"}
    for path, item in spec["paths"].items():
        for method, operation in item.items():
            if (method.upper(), path) not in documented:
                continue
            handler = operation["operationId"]
            match = re.search(r'func \(s \*Server\) ' + re.escape(handler)
                              + r'\([^\n]+\n(.*?)(?=\nfunc |\ntype |\nconst |\nvar |\Z)',
                              source, re.S)
            if match is None:
                raise ValueError(f"Handler not found: {handler}")
            branches = [(statuses[status], code) for status, code in re.findall(
                r'writeError\(w, http.Status(\w+), "([^"]+)"', match[1])]
            branches += [("400", code) for code in re.findall(
                r'writeStoreValidationError\(w, "([^"]+)"', match[1])]
            if "pathInt64(" in match[1]:
                branches.append(("400", "invalid_id"))
            for status, code in branches:
                if code not in operation["responses"].get(status, {}).get("x-error-codes", []):
                    raise ValueError(f"Undocumented error: {method} {path} {status} {code}")
    print(f"PASS OpenAPI {spec['openapi']}, local references, {len(spec['paths'])} paths / {len(documented)} explicit operations.")
    print("GET also serves implicit HEAD; static assets excluded. Run Go contract tests for handler evidence.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError) as exc:
        sys.exit(str(exc))
