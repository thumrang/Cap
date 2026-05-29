import json
import subprocess
import sys
from pathlib import Path

from rbac_diff import DiffEntry, build_ai_prompt


ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "rbac_diff.py"
SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"


def write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def run_cli(tmp_path, old_value, new_value, *args):
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    write_json(old_path, old_value)
    write_json(new_path, new_value)

    return subprocess.run(
        [sys.executable, str(CLI), str(old_path), str(new_path), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def role_definition(actions=None, assignable_scopes=None, not_actions=None, data_actions=None):
    return {
        "id": f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/roleDefinitions/custom-role",
        "name": "custom-role",
        "type": "Microsoft.Authorization/roleDefinitions",
        "properties": {
            "roleName": "Custom Storage Operator",
            "description": "Canned Azure-shaped custom role for tests.",
            "permissions": [
                {
                    "actions": actions or [],
                    "notActions": not_actions or [],
                    "dataActions": data_actions or [],
                    "notDataActions": [],
                }
            ],
            "assignableScopes": assignable_scopes or [
                f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-prod-eastus-a"
            ],
        },
    }


def role_assignment(scope=None, principal_id="11111111-1111-1111-1111-111111111111"):
    return {
        "id": f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-prod-eastus-a/providers/Microsoft.Authorization/roleAssignments/assignment-a",
        "name": "assignment-a",
        "type": "Microsoft.Authorization/roleAssignments",
        "properties": {
            "roleDefinitionId": f"/subscriptions/{SUBSCRIPTION}/providers/Microsoft.Authorization/roleDefinitions/custom-role",
            "principalId": principal_id,
            "scope": scope or f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-prod-eastus-a",
        },
    }


def test_role_definition_added_action_gets_warning_and_plain_english_summary(tmp_path):
    result = run_cli(
        tmp_path,
        role_definition(actions=["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]),
        role_definition(
            actions=[
                "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
                "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
            ]
        ),
    )

    assert result.returncode == 0
    assert "Structural diff:" in result.stdout
    assert "WARNING" in result.stdout
    assert "actions" in result.stdout
    assert "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete" in result.stdout
    assert "This change grants" in result.stdout
    assert "Previously, only Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read was allowed" in result.stdout
    assert "Net effect: privilege increase" in result.stdout
    assert "\033[" not in result.stdout


def test_wildcard_action_is_critical_and_returns_nonzero(tmp_path):
    result = run_cli(
        tmp_path,
        role_definition(actions=["Microsoft.Storage/storageAccounts/read"]),
        role_definition(actions=["Microsoft.Storage/storageAccounts/read", "*"]),
    )

    assert result.returncode != 0
    assert "CRITICAL" in result.stdout
    assert "*" in result.stdout
    assert "Net effect: privilege escalation" in result.stdout


def test_assignable_scopes_widened_to_root_is_critical(tmp_path):
    result = run_cli(
        tmp_path,
        role_definition(assignable_scopes=[f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-prod-eastus-a"]),
        role_definition(assignable_scopes=["/"]),
    )

    assert result.returncode != 0
    assert "CRITICAL" in result.stdout
    assert "assignableScopes" in result.stdout
    assert "broadens assignableScopes to /" in result.stdout


def test_role_assignment_principal_change_is_reported(tmp_path):
    result = run_cli(
        tmp_path,
        role_assignment(),
        role_assignment(principal_id="22222222-2222-2222-2222-222222222222"),
    )

    assert result.returncode == 0
    assert "WARNING" in result.stdout
    assert "principalId" in result.stdout
    assert "changed assigned principal" in result.stdout


def test_role_assignment_scope_widening_is_critical(tmp_path):
    result = run_cli(
        tmp_path,
        role_assignment(scope=f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg-prod-eastus-a"),
        role_assignment(scope=f"/subscriptions/{SUBSCRIPTION}"),
    )

    assert result.returncode != 0
    assert "CRITICAL" in result.stdout
    assert "scope" in result.stdout
    assert "privilege escalation" in result.stdout


def test_accepts_flat_lists_of_role_definitions(tmp_path):
    result = run_cli(
        tmp_path,
        [role_definition(actions=["Microsoft.Compute/virtualMachines/read"])],
        [
            role_definition(
                actions=[
                    "Microsoft.Compute/virtualMachines/read",
                    "Microsoft.Compute/virtualMachines/start/action",
                ]
            )
        ],
    )

    assert result.returncode == 0
    assert "Microsoft.Compute/virtualMachines/start/action" in result.stdout


def test_accepts_azure_list_response_shape(tmp_path):
    result = run_cli(
        tmp_path,
        {"value": [role_definition(actions=[])]},
        {"value": [role_definition(actions=["Microsoft.Storage/storageAccounts/read"])]},
    )

    assert result.returncode == 0
    assert "Microsoft.Storage/storageAccounts/read" in result.stdout


def test_sarif_output_for_critical_finding(tmp_path):
    result = run_cli(
        tmp_path,
        role_definition(actions=[]),
        role_definition(actions=["*"]),
        "--format",
        "sarif",
    )

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "azure-rbac-diff"
    assert payload["runs"][0]["results"][0]["level"] == "error"
    assert payload["runs"][0]["results"][0]["properties"]["severity"] == "critical"


def test_no_changes_prints_no_changes_message(tmp_path):
    document = role_definition(actions=["Microsoft.Storage/storageAccounts/read"])

    result = run_cli(tmp_path, document, document)

    assert result.returncode == 0
    assert "No RBAC permission changes detected." in result.stdout


def test_ai_summary_requires_api_key(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    result = run_cli(
        tmp_path,
        role_definition(actions=[]),
        role_definition(actions=["Microsoft.Storage/storageAccounts/read"]),
        "--ai-summary",
    )

    assert result.returncode == 2
    assert "OPENAI_API_KEY must be set" in result.stderr


def test_build_ai_prompt_contains_diff_data():
    prompt = build_ai_prompt(
        [
            DiffEntry(
                document="roleDefinition:custom-role",
                category="role_definition",
                field="actions",
                change="added",
                old=None,
                new="*",
                severity="critical",
                summary="This change grants *. Net effect: privilege escalation.",
            )
        ]
    )

    assert "Azure RBAC structural diff" in prompt
    assert "roleDefinition:custom-role" in prompt
    assert "privilege escalation" in prompt
