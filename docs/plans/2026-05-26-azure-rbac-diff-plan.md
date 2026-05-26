# Plan: Azure RBAC Diff CLI

## Goal

Build a small Python CLI that compares two Azure RBAC JSON files and reports structural diffs plus an English summary of permission changes.

## Decisions

| Decision | Options | Chosen | Rationale |
|---|---|---|---|
| CLI output formats | `text`, `sarif`, `json` | `text`, `sarif` | `text` is default and human-friendly; `sarif` supports automated scanning. |
| Data shapes to support | role definitions only, role assignments only, both | both | acceptance criteria requires both common shapes. |
| Severity mapping | binary critical/non-critical, multi-level, heuristic | multi-level | needed to distinguish privilege escalation, scope widening, and informational changes. |

## Plan

1. Create the CLI entrypoint and parse arguments.
2. Detect whether inputs are role definitions or role assignments.
3. Compare permission arrays and assignable scopes.
4. Emit a text summary and SARIF output.
5. Add pytest coverage for both data shapes.

## Risks and Alternatives

| Risk / question | Alternative 1 | Alternative 2 | Notes |
|---|---|---|---|
| Shape detection | Infer from payload fields | Require explicit type flag | Inference is simpler and meets common Azure formats. |
| SARIF implementation | Minimal valid SARIF | Full rule metadata support | Minimal SARIF is enough for acceptance. |
| Broad scope detection | Only root `/` widening | Any ancestor-broadened scope | Root widening is treated as critical; ancestor broadening is treated as warning. |

## Milestones

- [x] CLI scaffold
- [x] Role-definition diff logic
- [x] Role-assignment diff logic
- [x] Plain text and SARIF output
- [x] Unit tests
