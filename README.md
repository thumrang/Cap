# Azure RBAC Diff CLI

A small Python CLI to compare two Azure RBAC JSON files and print structural diffs and a plain-English summary of effective permission changes.

## Usage

```bash
python rbac_diff.py old.json new.json
python rbac_diff.py old.json new.json --format sarif
python rbac_diff.py old.json new.json --ai-summary
```

## Output

- Default output is plain text.
- ANSI color is enabled when stdout is a TTY.
- Exit code `1` indicates at least one critical finding.

## Optional AI Agent Summary

The default CLI is deterministic and rule-based. To add an AI-generated agent summary, set an OpenAI-compatible API key and pass `--ai-summary`:

```powershell
$env:OPENAI_API_KEY="your-api-key"
python rbac_diff.py old.json new.json --ai-summary
```

Optional settings:

```powershell
$env:OPENAI_MODEL="gpt-4o-mini"
$env:OPENAI_BASE_URL="https://api.openai.com/v1"
```

`--ai-summary` is only supported with text output. The structured rule-based findings still determine severities and exit codes.

## Examples

Run the provided sample fixtures from a clean clone:

```bash
python rbac_diff.py examples/role-definition-old.json examples/role-definition-new.json
python rbac_diff.py examples/role-assignment-old.json examples/role-assignment-new.json
```

Or run the demo script directly:

```powershell
./demo.ps1
```

```bash
./demo.sh
```

## Testing

```bash
python -m pytest
```

## Planning

The implementation is guided by the plan in `docs/plans/2026-05-26-azure-rbac-diff-plan.md`.
