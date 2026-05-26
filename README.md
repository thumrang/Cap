# Azure RBAC Diff CLI

A small Python CLI to compare two Azure RBAC JSON files and print structural diffs and a plain-English summary of effective permission changes.

## Usage

```bash
python rbac_diff.py old.json new.json
python rbac_diff.py old.json new.json --format sarif
```

## Output

- Default output is plain text.
- ANSI color is enabled when stdout is a TTY.
- Exit code `3` indicates at least one critical finding.

## Testing

```bash
python -m pytest
```
