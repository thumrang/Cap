import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "rbac_diff.py"

ROLE_DEF_OLD = {
    "name": "Contoso Reader",
    "description": "Read-only storage role.",
    "permissions": [
        {
            "actions": ["Microsoft.Storage/storageAccounts/read"],
            "notActions": [],
            "dataActions": [],
            "notDataActions": [],
        }
    ],
    "assignableScopes": ["/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-prod"]
}

ROLE_DEF_NEW = {
    "name": "Contoso Reader Plus",
    "description": "Read and write storage role.",
    "permissions": [
        {
            "actions": ["Microsoft.Storage/storageAccounts/read", "Microsoft.Storage/storageAccounts/write"],
            "notActions": [],
            "dataActions": [],
            "notDataActions": [],
        }
    ],
    "assignableScopes": ["/"]
}

ROLE_ASSIGN_OLD = {
    "roleDefinitionId": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/reader",
    "principalId": "11111111-1111-1111-1111-111111111111",
    "scope": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-prod"
}

ROLE_ASSIGN_NEW = {
    "roleDefinitionId": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/contributor",
    "principalId": "22222222-2222-2222-2222-222222222222",
    "scope": "/subscriptions/00000000-0000-0000-0000-000000000000"
}

def run_cli(old, new, extra=None):
    extra = extra or []
    result = subprocess.run(
        [sys.executable, str(CLI), str(old), str(new), *extra],
        capture_output=True,
        text=True,
    )
    return result

@pytest.mark.parametrize("tmp_name, data", [("old.json", ROLE_DEF_OLD), ("new.json", ROLE_DEF_NEW)])
def test_role_definition_files(tmp_path, tmp_name, data):
    path = tmp_path / tmp_name
    path.write_text(json.dumps(data))
    assert path.exists()

def test_role_definition_summary_critical(tmp_path):
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(json.dumps(ROLE_DEF_OLD))
    new_path.write_text(json.dumps(ROLE_DEF_NEW))

    result = run_cli(old_path, new_path)
    assert result.returncode == 3
    assert "Assignable scope broadened to /" in result.stdout
    assert "This change grants" in result.stdout
    assert "Net effect: privilege escalation." in result.stdout

def test_role_definition_sarif_output(tmp_path):
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(json.dumps(ROLE_DEF_OLD))
    new_path.write_text(json.dumps(ROLE_DEF_NEW))

    result = run_cli(old_path, new_path, ["--format", "sarif"])
    assert result.returncode == 3
    payload = json.loads(result.stdout)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"]

def test_role_assignment_diff(tmp_path):
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(json.dumps(ROLE_ASSIGN_OLD))
    new_path.write_text(json.dumps(ROLE_ASSIGN_NEW))

    result = run_cli(old_path, new_path)
    assert result.returncode == 0
    assert "Effective permissions summary:" in result.stdout
    assert "This assignment change affects who has access" in result.stdout

@pytest.mark.parametrize("bad_old,bad_new", [
    ({}, ROLE_DEF_NEW),
    (ROLE_ASSIGN_OLD, {}),
])
def test_mixed_type_error(tmp_path, bad_old, bad_new):
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(json.dumps(bad_old))
    new_path.write_text(json.dumps(bad_new))

    result = run_cli(old_path, new_path)
    assert result.returncode == 2
    assert "must both be role definitions or both be role assignments" in result.stderr
