#!/usr/bin/env python3
import argparse
import json
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

COLOR = {
    "reset": "\x1b[0m",
    "red": "\x1b[31m",
    "yellow": "\x1b[33m",
    "green": "\x1b[32m",
    "blue": "\x1b[34m",
}

PRIVILEGE_FIELDS = ["actions", "notActions", "dataActions", "notDataActions"]

@dataclass
class DiffEntry:
    category: str
    field: str
    old: Any
    new: Any
    severity: str
    summary: str


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def is_role_definition(payload: Any) -> bool:
    return isinstance(payload, dict) and "permissions" in payload


def is_role_assignment(payload: Any) -> bool:
    return isinstance(payload, dict) and "roleDefinitionId" in payload and "principalId" in payload


def normalize_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return sorted(str(item) for item in value if item is not None)
    return []


def compare_list(old: Any, new: Any) -> Tuple[List[str], List[str]]:
    old_set = set(normalize_list(old))
    new_set = set(normalize_list(new))
    return sorted(new_set - old_set), sorted(old_set - new_set)


def widen_scope(old_scopes: List[str], new_scopes: List[str]) -> Optional[str]:
    if "/" in new_scopes and "/" not in old_scopes:
        return "/"
    for new_scope in new_scopes:
        for old_scope in old_scopes:
            if old_scope and new_scope != old_scope and new_scope.startswith(old_scope.rstrip("/")):
                return new_scope
    return None


def classify_change(field: str, added: List[str], removed: List[str], old: Any, new: Any) -> str:
    if field == "assignableScopes":
        if "/" in added:
            return "critical"
        return "warning" if added else "notice" if removed else "info"
    if field in ["actions", "dataActions"]:
        if any(item == "*" for item in added):
            return "critical"
        if added:
            return "warning"
        if removed:
            return "notice"
        return "info"
    if field in ["notActions", "notDataActions"]:
        if removed:
            return "warning"
        return "info" if added else "notice"
    if field in ["principalId", "scope", "roleDefinitionId"]:
        return "warning" if old and new and old != new else "info"
    return "info"


def summarize_permission_change(old: List[str], new: List[str], field_name: str) -> Optional[str]:
    added, removed = compare_list(old, new)
    if added and removed:
        return f"{field_name} changed: added {added}, removed {removed}."
    if added:
        return f"Added {field_name}: {added}."
    if removed:
        return f"Removed {field_name}: {removed}."
    return None


def format_list(items: List[str]) -> str:
    if not items:
        return "none"
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + f" and {items[-1]}"


def compare_role_definition(old: Dict[str, Any], new: Dict[str, Any]) -> Tuple[List[DiffEntry], str]:
    entries: List[DiffEntry] = []
    old_permissions = old.get("permissions", [])
    new_permissions = new.get("permissions", [])
    old_perm = old_permissions[0] if old_permissions else {}
    new_perm = new_permissions[0] if new_permissions else {}

    summary_parts: List[str] = []
    effective_parts: List[str] = []
    risk_parts: List[str] = []
    action_added: List[str] = []
    action_removed: List[str] = []

    for field in PRIVILEGE_FIELDS:
        old_values = normalize_list(old_perm.get(field, []))
        new_values = normalize_list(new_perm.get(field, []))
        added, removed = compare_list(old_values, new_values)
        if added or removed:
            summary = summarize_permission_change(old_values, new_values, field)
            entries.append(DiffEntry(
                category="role_definition",
                field=field,
                old=old_values,
                new=new_values,
                severity=classify_change(field, added, removed, old_perm.get(field), new_perm.get(field)),
                summary=summary or "No change",
            ))
            if summary:
                summary_parts.append(summary)
            if field == "actions":
                action_added = added
                action_removed = removed
                if added:
                    effective_parts.append(f"This change grants {format_list(added)}.")
                    if any("*" in a or "write" in a or "delete" in a for a in added):
                        risk_parts.append(f"Security risk: added write/delete capability {format_list(added)}.")
                if removed:
                    effective_parts.append(f"It removes {format_list(removed)}.")
            if field == "dataActions" and added:
                effective_parts.append(f"This change grants data actions {format_list(added)}.")
                risk_parts.append(f"Security risk: added data-level access {format_list(added)}.")

    old_scopes = normalize_list(old.get("assignableScopes", []))
    new_scopes = normalize_list(new.get("assignableScopes", []))
    added_scopes, removed_scopes = compare_list(old_scopes, new_scopes)
    if added_scopes or removed_scopes:
        summary = summarize_permission_change(old_scopes, new_scopes, "assignableScopes")
        entries.append(DiffEntry(
            category="role_definition",
            field="assignableScopes",
            old=old_scopes,
            new=new_scopes,
            severity=classify_change("assignableScopes", added_scopes, removed_scopes, old_scopes, new_scopes),
            summary=summary or "No change",
        ))
        if summary:
            summary_parts.append(summary)
        widened = widen_scope(old_scopes, new_scopes)
        if widened:
            effective_parts.append(f"Assignable scope broadened to {widened}.")
            effective_parts.append(f"The role can now be assigned more broadly, from {format_list(old_scopes)} to {format_list(new_scopes)}.")
            risk_parts.append(f"Security risk: scope widened to {widened} — this role is now assignable across all subscriptions and resources.")
        else:
            effective_parts.append(f"Assignable scopes changed from {format_list(old_scopes)} to {format_list(new_scopes)}.")

    if action_added and old_perm.get("actions"):
        effective_parts.append(f"Previously, only {format_list(normalize_list(old_perm.get('actions', [])))} was allowed.")

    if any(entry.severity == "critical" for entry in entries):
        effective_parts.append("Net effect: privilege escalation.")
        if risk_parts:
            effective_parts.append(f"Why this is insecure: {' '.join(risk_parts)}")
    elif any(entry.severity == "warning" for entry in entries):
        effective_parts.append("Net effect: increased privileges.")
        if risk_parts:
            effective_parts.append(f"Why this is insecure: {' '.join(risk_parts)}")

    effect = "Role definition changed." if summary_parts else "No material role-definition change detected."
    narrative = " ".join(effective_parts) if effective_parts else effect
    return entries, narrative


def compare_role_assignment(old: Dict[str, Any], new: Dict[str, Any]) -> Tuple[List[DiffEntry], str]:
    entries: List[DiffEntry] = []
    summary_parts: List[str] = []
    narrative_parts: List[str] = []

    for key in ["principalId", "roleDefinitionId", "scope"]:
        old_value = old.get(key)
        new_value = new.get(key)
        if old_value != new_value:
            summary = f"{key} changed from {old_value} to {new_value}."
            entries.append(DiffEntry(
                category="role_assignment",
                field=key,
                old=old_value,
                new=new_value,
                severity=classify_change(key, [new_value] if new_value else [], [old_value] if old_value else [], old_value, new_value),
                summary=summary,
            ))
            summary_parts.append(summary)
            if key == "principalId":
                narrative_parts.append(f"The assignment was moved from principal {old_value} to {new_value}.")
            elif key == "roleDefinitionId":
                narrative_parts.append(f"The assigned role changed from {old_value} to {new_value}.")
            elif key == "scope":
                narrative_parts.append(f"The assignment scope changed from {old_value} to {new_value}.")

    if narrative_parts:
        narrative_parts.append("This assignment change affects who has access, what role is granted, and where it applies.")
    if not summary_parts:
        summary_parts.append("No role-assignment changes detected.")
    narrative = " ".join(narrative_parts) if narrative_parts else "No role-assignment changes detected."
    return entries, narrative


def format_text(entries: List[DiffEntry], summary: str, use_color: bool) -> str:
    lines: List[str] = [f"Effective permissions summary: {summary}", ""]
    for entry in entries:
        color = {
            "critical": COLOR["red"],
            "warning": COLOR["yellow"],
            "notice": COLOR["blue"],
            "info": COLOR["green"],
        }.get(entry.severity, "") if use_color else ""
        reset = COLOR["reset"] if use_color else ""
        lines.append(f"{color}[{entry.severity.upper()}]{reset} {entry.field}: {entry.summary}")
        lines.append(f"  old: {entry.old}")
        lines.append(f"  new: {entry.new}")
    return "\n".join(lines)


def format_sarif(entries: List[DiffEntry], summary: str) -> Dict[str, Any]:
    results = []
    for entry in entries:
        results.append({
            "ruleId": entry.field,
            "level": entry.severity,
            "message": {"text": entry.summary},
            "properties": {
                "category": entry.category,
                "old": entry.old,
                "new": entry.new,
            },
            "locations": [],
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "azure-rbac-diff",
                        "informationUri": "https://github.com/example/azure-rbac-diff",
                        "rules": [
                            {"id": entry.field, "shortDescription": {"text": entry.summary}, "defaultConfiguration": {"level": entry.severity}} for entry in entries
                        ],
                    }
                },
                "results": results,
            }
        ],
    }


def find_highest_severity(entries: List[DiffEntry]) -> str:
    if any(entry.severity == "critical" for entry in entries):
        return "critical"
    if any(entry.severity == "warning" for entry in entries):
        return "warning"
    if any(entry.severity == "notice" for entry in entries):
        return "notice"
    return "info"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Azure RBAC structural diff and effective permission summary.")
    parser.add_argument("old", help="Old JSON file")
    parser.add_argument("new", help="New JSON file")
    parser.add_argument("--format", choices=["text", "sarif"], default="text", help="Output format")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color")
    args = parser.parse_args(argv)

    old_data = load_json(args.old)
    new_data = load_json(args.new)

    if is_role_definition(old_data) and is_role_definition(new_data):
        entries, summary = compare_role_definition(old_data, new_data)
    elif is_role_assignment(old_data) and is_role_assignment(new_data):
        entries, summary = compare_role_assignment(old_data, new_data)
    else:
        print("Input files must both be role definitions or both be role assignments.", file=sys.stderr)
        return 2

    use_color = sys.stdout.isatty() and not args.no_color and args.format == "text"
    if args.format == "sarif":
        output = json.dumps(format_sarif(entries, summary), indent=2)
    else:
        output = format_text(entries, summary, use_color)

    print(output)
    severity = find_highest_severity(entries)
    return 3 if severity == "critical" else 0


if __name__ == "__main__":
    raise SystemExit(main())
