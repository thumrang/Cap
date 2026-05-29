# Plan: Azure RBAC Diff CLI

## Goal

Build a small Python CLI that compares two Azure RBAC JSON files and reports:

1. A structural diff of role definition or role assignment fields.
2. A plain-English summary of effective permission changes.

## CLI

```sh
python3 rbac_diff.py old.json new.json --format text
python3 rbac_diff.py old.json new.json --format sarif
python3 rbac_diff.py old.json new.json --ai-summary
```

`text` is the default format. Text output uses ANSI color only when stdout is a TTY. SARIF output emits SARIF 2.1.0 JSON.

`--ai-summary` adds an optional OpenAI-compatible agent summary to text output. The deterministic structural diff remains the source of truth for severity and exit codes.

## Supported Azure RBAC Inputs

The CLI accepts two JSON files. Each file may contain:

- A single Azure role definition.
- A single Azure role assignment.
- A flat list of role definitions or role assignments.
- An Azure list response with a top-level `value` array.

Real Azure-shaped documents are supported, including fields under `properties`.

## Compared Fields

Role definitions:

- `permissions[].actions`
- `permissions[].notActions`
- `permissions[].dataActions`
- `permissions[].notDataActions`
- `assignableScopes`

Role assignments:

- `roleDefinitionId`
- `principalId`
- `scope`

## Severity Rules

Each diff entry is classified as one of `info`, `notice`, `warning`, or `critical`.

- `critical`: wildcard permissions such as `*`, assignment scope widened to an ancestor scope, or `assignableScopes` widened to `/` or another ancestor scope.
- `warning`: added non-wildcard permissions, removed exclusions, changed assigned principal, or changed role assignment.
- `notice`: removed granted permissions, added exclusions, removed assignable scopes, or removed documents.
- `info`: reserved for low-risk changes.

## Exit Codes

- `0`: no critical findings.
- `1`: one or more critical findings.
- `2`: invalid input, unreadable files, malformed JSON, or unsupported document shape.

## Tests

Pytest coverage includes:

- Added role-definition action detection.
- Wildcard action detection and non-zero critical exit.
- `assignableScopes` widening to `/`.
- Role-assignment `principalId` changes.
- Role-assignment scope widening.
- Flat list input.
- Azure list response input.
- SARIF output.
- Plain text output without ANSI color when stdout is not a TTY.

## Status

- [x] CLI argument parsing.
- [x] Role-definition diff logic.
- [x] Role-assignment diff logic.
- [x] Flat list and Azure `value` list response support.
- [x] Plain-English effective permission summaries.
- [x] Severity classification.
- [x] Text output and SARIF output.
- [x] Optional OpenAI-compatible AI summary mode.
- [x] Pytest coverage.

