#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from typing import Any
from urllib import error, request


ROLE_DEFINITION_FIELDS = (
    "actions",
    "notActions",
    "dataActions",
    "notDataActions",
    "assignableScopes",
)

ROLE_ASSIGNMENT_FIELDS = (
    "roleDefinitionId",
    "principalId",
    "scope",
)

COLORS = {
    "info": "\033[36m",
    "notice": "\033[34m",
    "warning": "\033[33m",
    "critical": "\033[31m",
    "reset": "\033[0m",
}


@dataclass(frozen=True)
class DiffEntry:
    document: str
    category: str
    field: str
    change: str
    old: Any
    new: Any
    severity: str
    summary: str


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Diff two Azure RBAC JSON files and summarize effective permission changes."
    )
    parser.add_argument("old", help="Old Azure RBAC JSON file")
    parser.add_argument("new", help="New Azure RBAC JSON file")
    parser.add_argument("--format", choices=("text", "sarif"), default="text")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color in text output")
    parser.add_argument("--ai-summary", action="store_true", help="Add an AI-generated risk summary to text output")
    parser.add_argument("--ai-model", default=os.getenv("OPENAI_MODEL", "gpt-4o-mini"), help="OpenAI-compatible model name")
    parser.add_argument("--ai-base-url", default=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"), help="OpenAI-compatible API base URL")
    parser.add_argument("--ai-timeout", type=int, default=30, help="AI request timeout in seconds")
    args = parser.parse_args(argv)

    try:
        old_documents = load_documents(args.old)
        new_documents = load_documents(args.new)
        entries = diff_documents(old_documents, new_documents)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    ai_summary = None
    if args.ai_summary:
        if args.format != "text":
            print("error: --ai-summary is only supported with --format text", file=sys.stderr)
            return 2
        try:
            ai_summary = generate_ai_summary(entries, args.ai_model, args.ai_base_url, args.ai_timeout)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.format == "sarif":
        print(json.dumps(format_sarif(entries), indent=2))
    else:
        use_color = sys.stdout.isatty() and not args.no_color
        print(format_text(entries, use_color, ai_summary))

    return 1 if any(entry.severity == "critical" for entry in entries) else 0


def load_documents(path: str) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    if isinstance(data, dict) and isinstance(data.get("value"), list):
        data = data["value"]

    if isinstance(data, list):
        documents = data
    elif isinstance(data, dict):
        documents = [data]
    else:
        raise ValueError(f"{path} must contain a JSON object, JSON array, or Azure list response")

    if not all(isinstance(document, dict) for document in documents):
        raise ValueError(f"{path} contains a non-object RBAC document")

    return documents


def diff_documents(old_documents: list[dict[str, Any]], new_documents: list[dict[str, Any]]) -> list[DiffEntry]:
    old_by_key = {document_key(document): document for document in old_documents}
    new_by_key = {document_key(document): document for document in new_documents}
    entries: list[DiffEntry] = []

    for key in sorted(old_by_key.keys() - new_by_key.keys()):
        old_document = old_by_key[key]
        entries.append(
            DiffEntry(
                document=key,
                category=document_category(old_document),
                field="document",
                change="removed",
                old=key,
                new=None,
                severity="notice",
                summary=f"RBAC document {key} was removed.",
            )
        )

    for key in sorted(new_by_key.keys() - old_by_key.keys()):
        new_document = new_by_key[key]
        entries.append(
            DiffEntry(
                document=key,
                category=document_category(new_document),
                field="document",
                change="added",
                old=None,
                new=key,
                severity=severity_for_added_document(new_document),
                summary=f"RBAC document {key} was added.",
            )
        )

    for key in sorted(old_by_key.keys() & new_by_key.keys()):
        old_document = old_by_key[key]
        new_document = new_by_key[key]
        if is_role_definition(old_document) or is_role_definition(new_document):
            entries.extend(diff_role_definition(key, old_document, new_document))
        elif is_role_assignment(old_document) or is_role_assignment(new_document):
            entries.extend(diff_role_assignment(key, old_document, new_document))
        else:
            raise ValueError(f"Unsupported Azure RBAC document shape for {key}")

    return entries


def diff_role_definition(key: str, old_document: dict[str, Any], new_document: dict[str, Any]) -> list[DiffEntry]:
    entries: list[DiffEntry] = []

    for field in ROLE_DEFINITION_FIELDS:
        old_values = set(read_role_definition_values(old_document, field))
        new_values = set(read_role_definition_values(new_document, field))

        for value in sorted(new_values - old_values):
            severity = severity_for_added_role_definition_value(field, value, old_values)
            entries.append(
                DiffEntry(
                    document=key,
                    category="role_definition",
                    field=field,
                    change="added",
                    old=None,
                    new=value,
                    severity=severity,
                    summary=summarize_role_definition_addition(field, value, old_values, severity),
                )
            )

        for value in sorted(old_values - new_values):
            severity = severity_for_removed_role_definition_value(field)
            entries.append(
                DiffEntry(
                    document=key,
                    category="role_definition",
                    field=field,
                    change="removed",
                    old=value,
                    new=None,
                    severity=severity,
                    summary=summarize_role_definition_removal(field, value, severity),
                )
            )

    return entries


def diff_role_assignment(key: str, old_document: dict[str, Any], new_document: dict[str, Any]) -> list[DiffEntry]:
    entries: list[DiffEntry] = []

    for field in ROLE_ASSIGNMENT_FIELDS:
        old_value = read_property(old_document, field)
        new_value = read_property(new_document, field)
        if old_value == new_value:
            continue

        severity = severity_for_assignment_change(field, old_value, new_value)
        entries.append(
            DiffEntry(
                document=key,
                category="role_assignment",
                field=field,
                change="modified",
                old=old_value,
                new=new_value,
                severity=severity,
                summary=summarize_assignment_change(field, old_value, new_value, severity),
            )
        )

    return entries


def document_category(document: dict[str, Any]) -> str:
    if is_role_definition(document):
        return "role_definition"
    if is_role_assignment(document):
        return "role_assignment"
    return "unknown"


def is_role_definition(document: dict[str, Any]) -> bool:
    properties = properties_of(document)
    return "permissions" in document or "permissions" in properties or "assignableScopes" in document or "assignableScopes" in properties


def is_role_assignment(document: dict[str, Any]) -> bool:
    fields = set(document) | set(properties_of(document))
    return {"roleDefinitionId", "principalId", "scope"}.issubset(fields)


def document_key(document: dict[str, Any]) -> str:
    prefix = "roleDefinition" if is_role_definition(document) else "roleAssignment"
    stable_id = document.get("id") or document.get("name") or read_property(document, "id") or read_property(document, "name")
    if stable_id:
        return f"{prefix}:{stable_id}"

    if prefix == "roleAssignment":
        role_definition_id = read_property(document, "roleDefinitionId") or "unknown-role"
        principal_id = read_property(document, "principalId") or "unknown-principal"
        scope = read_property(document, "scope") or "unknown-scope"
        return f"{prefix}:{role_definition_id}:{principal_id}:{scope}"

    role_name = read_property(document, "roleName") or "unknown-role-definition"
    return f"{prefix}:{role_name}"


def properties_of(document: dict[str, Any]) -> dict[str, Any]:
    properties = document.get("properties")
    return properties if isinstance(properties, dict) else {}


def read_property(document: dict[str, Any], field: str) -> Any:
    if field in document:
        return document[field]
    return properties_of(document).get(field)


def read_role_definition_values(document: dict[str, Any], field: str) -> list[str]:
    if field == "assignableScopes":
        return as_string_list(read_property(document, field))

    permissions = read_property(document, "permissions")
    if not isinstance(permissions, list):
        return []

    values: list[str] = []
    for permission in permissions:
        if isinstance(permission, dict):
            values.extend(as_string_list(permission.get(field)))
    return values


def as_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return sorted(str(item) for item in value if item is not None)
    return [str(value)]


def severity_for_added_document(document: dict[str, Any]) -> str:
    if is_role_assignment(document):
        return "warning"

    if any(is_wildcard_permission(value) for value in read_role_definition_values(document, "actions")):
        return "critical"
    if any(is_wildcard_permission(value) for value in read_role_definition_values(document, "dataActions")):
        return "critical"
    if any(is_root_scope(value) for value in read_role_definition_values(document, "assignableScopes")):
        return "critical"
    return "warning"


def severity_for_added_role_definition_value(field: str, value: str, old_values: set[str]) -> str:
    if field in ("actions", "dataActions"):
        return "critical" if is_wildcard_permission(value) else "warning"
    if field in ("notActions", "notDataActions"):
        return "notice"
    if field == "assignableScopes":
        if is_root_scope(value) or any(scope_contains(value, old_value) for old_value in old_values):
            return "critical"
        return "warning"
    return "info"


def severity_for_removed_role_definition_value(field: str) -> str:
    if field in ("actions", "dataActions", "assignableScopes"):
        return "notice"
    if field in ("notActions", "notDataActions"):
        return "warning"
    return "info"


def severity_for_assignment_change(field: str, old_value: Any, new_value: Any) -> str:
    if field == "scope":
        old_scope = str(old_value or "")
        new_scope = str(new_value or "")
        return "critical" if is_root_scope(new_scope) or scope_contains(new_scope, old_scope) else "warning"
    if field == "principalId":
        return "warning"
    if field == "roleDefinitionId":
        return "warning"
    return "info"


def is_wildcard_permission(value: str) -> bool:
    stripped = value.strip()
    return stripped == "*" or stripped.endswith("/*")


def is_root_scope(value: str) -> bool:
    return normalize_scope(value) == "/"


def scope_contains(candidate_parent: str, candidate_child: str) -> bool:
    parent = normalize_scope(candidate_parent)
    child = normalize_scope(candidate_child)
    if parent == "/":
        return child != "/"
    return child != parent and child.startswith(parent + "/")


def normalize_scope(value: str) -> str:
    stripped = value.strip().rstrip("/")
    return stripped or "/"


def summarize_role_definition_addition(field: str, value: str, old_values: set[str], severity: str) -> str:
    if field in ("actions", "dataActions"):
        prior = f" Previously, only {format_values(old_values)} was allowed." if old_values else ""
        net = "privilege escalation" if severity == "critical" else "privilege increase"
        return f"This change grants {value}.{prior} Net effect: {net}."
    if field in ("notActions", "notDataActions"):
        return f"This change adds exclusion {value} to {field}. Net effect: privilege reduction."
    if field == "assignableScopes":
        net = "privilege escalation" if severity == "critical" else "broader assignment reach"
        return f"This change broadens assignableScopes to {value}. Net effect: {net}."
    return f"This change adds {value} to {field}."


def summarize_role_definition_removal(field: str, value: str, severity: str) -> str:
    if field in ("actions", "dataActions"):
        return f"This change removes granted permission {value}. Net effect: privilege reduction."
    if field in ("notActions", "notDataActions"):
        return f"This change removes exclusion {value} from {field}. Net effect: privilege increase."
    if field == "assignableScopes":
        return f"This change removes assignable scope {value}. Net effect: narrower assignment reach."
    return f"This change removes {value} from {field}."


def summarize_assignment_change(field: str, old_value: Any, new_value: Any, severity: str) -> str:
    if field == "principalId":
        return f"This change moves the assignment from principal {old_value} to principal {new_value}. Net effect: changed assigned principal."
    if field == "scope":
        net = "privilege escalation" if severity == "critical" else "changed assignment reach"
        return f"This change modifies assignment scope from {old_value} to {new_value}. Net effect: {net}."
    if field == "roleDefinitionId":
        return f"This change modifies assigned role from {old_value} to {new_value}. Net effect: changed effective permissions."
    return f"This change modifies {field} from {old_value} to {new_value}."


def format_values(values: set[str] | list[str] | tuple[str, ...]) -> str:
    ordered = sorted(values)
    if not ordered:
        return "none"
    if len(ordered) == 1:
        return ordered[0]
    return ", ".join(ordered[:-1]) + f" and {ordered[-1]}"


def format_text(entries: list[DiffEntry], use_color: bool, ai_summary: str | None = None) -> str:
    if not entries:
        lines = ["No RBAC permission changes detected."]
        if ai_summary:
            lines.extend(["", "AI risk summary:", ai_summary])
        return "\n".join(lines)

    lines = ["Azure RBAC diff", "===============", "", "Structural diff:"]
    for entry in entries:
        severity = colorize(entry.severity.upper(), entry.severity, use_color)
        lines.append(f"- [{severity}] {entry.document}")
        lines.append(f"  {entry.change}: {entry.field}")
        lines.append(f"  old: {entry.old}")
        lines.append(f"  new: {entry.new}")

    lines.extend(["", "Effective permissions summary:"])
    for entry in entries:
        severity = colorize(entry.severity.upper(), entry.severity, use_color)
        lines.append(f"- [{severity}] {entry.summary}")

    if ai_summary:
        lines.extend(["", "AI risk summary:", ai_summary])

    return "\n".join(lines)


def colorize(text: str, severity: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{COLORS.get(severity, '')}{text}{COLORS['reset']}"


def generate_ai_summary(entries: list[DiffEntry], model: str, base_url: str, timeout: int) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY must be set to use --ai-summary")

    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an Azure RBAC security review agent. Summarize only the RBAC diff data provided. "
                    "Do not invent resources, principals, or permissions. Keep the answer concise and actionable."
                ),
            },
            {"role": "user", "content": build_ai_prompt(entries)},
        ],
        "temperature": 0.2,
    }
    body = json.dumps(payload).encode("utf-8")
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    http_request = request.Request(url, data=body, headers=headers, method="POST")

    try:
        with request.urlopen(http_request, timeout=timeout) as response:
            response_payload = json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise OSError(f"AI provider returned HTTP {exc.code}: {detail}") from exc
    except error.URLError as exc:
        raise OSError(f"AI provider request failed: {exc.reason}") from exc

    try:
        content = response_payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError("AI provider returned an unexpected response shape") from exc

    return str(content).strip()


def build_ai_prompt(entries: list[DiffEntry]) -> str:
    if not entries:
        return "No Azure RBAC permission changes were detected. Confirm that there is no apparent permission impact."

    diff_payload = [
        {
            "document": entry.document,
            "category": entry.category,
            "field": entry.field,
            "change": entry.change,
            "old": entry.old,
            "new": entry.new,
            "severity": entry.severity,
            "rule_summary": entry.summary,
        }
        for entry in entries
    ]
    return (
        "Review this Azure RBAC structural diff and produce a short agent-style risk assessment. "
        "Include: highest risk, who/what changed if visible, effective permission impact, and recommended next step.\n\n"
        f"Diff JSON:\n{json.dumps(diff_payload, indent=2)}"
    )


def format_sarif(entries: list[DiffEntry]) -> dict[str, Any]:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "azure-rbac-diff",
                        "informationUri": "https://learn.microsoft.com/azure/role-based-access-control/",
                        "rules": [
                            {
                                "id": f"azure-rbac-{severity}",
                                "name": f"Azure RBAC {severity}",
                                "shortDescription": {"text": f"Azure RBAC {severity} change"},
                                "defaultConfiguration": {"level": sarif_level(severity)},
                            }
                            for severity in ("info", "notice", "warning", "critical")
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": f"azure-rbac-{entry.severity}",
                        "level": sarif_level(entry.severity),
                        "message": {"text": entry.summary},
                        "locations": [],
                        "properties": {
                            "severity": entry.severity,
                            "document": entry.document,
                            "category": entry.category,
                            "field": entry.field,
                            "change": entry.change,
                            "old": entry.old,
                            "new": entry.new,
                        },
                    }
                    for entry in entries
                ],
            }
        ],
    }


def sarif_level(severity: str) -> str:
    if severity == "critical":
        return "error"
    if severity == "warning":
        return "warning"
    return "note"


if __name__ == "__main__":
    raise SystemExit(main())
