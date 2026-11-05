import json
import re
from typing import Any

import yaml

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
SENSITIVE = re.compile(r"/(admin|internal|debug|auth|login|users|accounts|payments|billing)(/|$)", re.I)


class SpecError(ValueError):
    pass


def parse_spec(content: bytes, filename: str) -> dict[str, Any]:
    try:
        text = content.decode("utf-8-sig")
        spec = json.loads(text) if filename.lower().endswith(".json") else yaml.safe_load(text)
    except (UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise SpecError(f"Could not parse API description: {exc}") from exc
    if not isinstance(spec, dict) or not str(spec.get("openapi", "")).startswith("3."):
        raise SpecError("A valid OpenAPI 3.x document is required.")
    if not isinstance(spec.get("paths"), dict) or not spec["paths"]:
        raise SpecError("The document must contain at least one path under 'paths'.")
    return spec


def _security_present(spec: dict, operation: dict) -> bool:
    security = operation.get("security", spec.get("security", []))
    return bool(security)


def inspect_spec(spec: dict[str, Any]) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    endpoints: list[dict] = []
    global_security = spec.get("security", [])
    schemes = spec.get("components", {}).get("securitySchemes", {})
    has_cors_policy = bool(spec.get("x-cors-policy") or spec.get("x-cors"))
    has_rate_limit = bool(spec.get("x-rate-limit") or spec.get("x-ratelimit"))

    def add(rule, severity, title, path, method, detail, fix):
        findings.append({"id": f"{rule}:{method}:{path}", "rule": rule, "severity": severity,
                         "title": title, "path": path, "method": method.upper(),
                         "detail": detail, "remediation": fix})

    for path, path_item in spec["paths"].items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            method = method.lower()
            secured = _security_present(spec, operation)
            endpoint = {"path": path, "method": method.upper(),
                        "operation_id": operation.get("operationId", ""),
                        "summary": operation.get("summary", ""),
                        "authenticated": secured, "tags": operation.get("tags", [])}
            endpoints.append(endpoint)
            if not secured:
                add("API2", "high", "No authentication requirement", path, method,
                    "The operation has no effective OpenAPI security requirement.",
                    "Declare a security requirement globally or on this operation and enforce it in the service.")
            if method in {"put", "patch", "delete"} and not secured:
                add("API5", "critical", "Unauthenticated state change", path, method,
                    "An unauthenticated operation can modify or remove server-side data.",
                    "Require strong authorization and verify access against the specific resource owner.")
            if method in {"post", "put", "patch"} and "requestBody" not in operation:
                add("API8", "medium", "Missing request body schema", path, method,
                    "A write operation has no documented request body for input validation.",
                    "Define a request body with bounded fields, types, and validation constraints.")
            if method == "get" and "responses" not in operation:
                add("API3", "medium", "Missing response contract", path, method,
                    "No response schema is documented, so data exposure is difficult to review.",
                    "Document response properties and return only fields required by the caller.")
            if method == "get" and not any(p in path.lower() for p in ("{id}", "{page}", "{limit}", "{cursor}")):
                add("API4", "low", "Collection may be unbounded", path, method,
                    "The route may return a collection without documented pagination controls.",
                    "Add bounded pagination parameters and enforce a server-side maximum page size.")
            if SENSITIVE.search(path) and not secured:
                add("API1", "critical", "Sensitive route lacks access control", path, method,
                    "The route name suggests privileged or personal data and has no declared authentication.",
                    "Require authentication and object-level authorization; avoid relying on route obscurity.")
    if not schemes and not global_security:
        add("API2", "high", "No security scheme defined", "(document)", "*",
            "The API description does not define an authentication scheme.",
            "Define an appropriate OAuth2, OpenID Connect, HTTP bearer, or API key scheme and apply it.")
    if not has_cors_policy:
        add("API8", "medium", "CORS policy not documented", "(document)", "*",
            "No CORS policy is described in the API document.",
            "Set an explicit allowlist of trusted origins, methods, and headers in the API gateway.")
    if not has_rate_limit:
        add("API4", "medium", "Rate limiting not documented", "(document)", "*",
            "No rate limit policy is described in the API document.",
            "Configure per-client and per-operation quotas with stricter limits for sensitive actions.")
    return endpoints, findings


def summarize(findings: list[dict]) -> dict:
    counts = {severity: sum(1 for f in findings if f["severity"] == severity)
              for severity in ("critical", "high", "medium", "low")}
    return {"total": len(findings), "by_severity": counts}
