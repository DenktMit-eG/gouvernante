---
tags:
  - operations
  - scanning
  - cli
---

# Running Scans

!!! tldr "TL;DR"

    - `gouvernante -rules <dir>` is the minimum viable command.
    - The scanner auto-detects lockfiles (`pnpm-lock.yaml`, `package-lock.json`, `yarn.lock`) in the target directory.
    - Use `-lockfile` to scan a single file, `-host` to check filesystem IOCs.
    - Exit code `0` = clean, `1` = error, `2` = findings detected.

!!! tip "Who is this for?"

    **Audience:** Engineers running gouvernante locally or scripting it into workflows.
    **Reading time:** ~6 minutes.

---

## CLI Flags

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `-rules` | Yes | — | Path to the rules directory containing JSON rule files. |
| `-dir` | No | `.` | Directory to scan for lockfiles. |
| `-lockfile` | No | — | Path to a specific lockfile (skips auto-detection). |
| `-host` | No | `false` | Enable host filesystem IOC checks. |
| `-output` | No | — | Write output to a file. Use `auto` for a timestamped filename. |
| `-json` | No | `false` | Emit output as JSON instead of human-readable text. |

## Scanning a Directory

By default, gouvernante walks the target directory and auto-detects all supported lockfiles:

```bash
gouvernante -rules ./rules -dir /path/to/project
```

If you omit `-dir`, the scanner uses the current working directory:

```bash
cd /path/to/project
gouvernante -rules ./rules
```

The scanner looks for:

- `pnpm-lock.yaml`
- `package-lock.json`
- `yarn.lock`

All detected lockfiles are scanned in a single run. Findings from each lockfile are reported separately.

## Scanning a Specific Lockfile

When you already know which lockfile you want to check, skip auto-detection:

```bash
gouvernante -rules ./rules -lockfile ./package-lock.json
```

This is useful when a project has multiple lockfiles and you only care about one, or when the lockfile lives outside the project directory.

## Host Indicator Checks

The `-host` flag enables filesystem IOC checks defined in your rules. These look for artifacts left by known attacks: malware binaries, exfiltration dumps, hidden directories.

```bash
gouvernante -rules ./rules -dir ./project -host
```

Host checks run after lockfile scanning. They inspect paths defined in each rule's `host_indicators` array (e.g., `/tmp/ld.py`, `~/.node_modules/.cache`).

!!! warning

    Host checks read the local filesystem. On shared build agents or containers, paths may not be meaningful. Use `-host` primarily on developer workstations or long-lived servers.

## Output Formats

### Text Output (Default)

Human-readable text written to stdout:

```bash
gouvernante -rules ./rules -dir ./project
```

```
[FINDING] axios@1.7.9 in package-lock.json
  Rule: SSC-2025-001 — Compromised axios release
  Severity: critical

[FINDING] plain-crypto-js@1.0.0 in pnpm-lock.yaml
  Rule: SSC-2025-001 — Dropper package installed by compromised axios
  Severity: critical

Scan complete: 2 findings in 2 lockfiles (14ms)
```

### JSON Output

Machine-parseable JSON, suitable for piping into `jq` or ingesting in CI:

```bash
gouvernante -rules ./rules -dir ./project -json
```

```json
{
  "findings": [
    {
      "rule_id": "SSC-2025-001",
      "package": "axios",
      "version": "1.7.9",
      "lockfile": "package-lock.json",
      "severity": "critical",
      "kind": "compromised-release"
    }
  ],
  "summary": {
    "total_findings": 1,
    "lockfiles_scanned": 2,
    "elapsed_ms": 14
  }
}
```

## Writing Output to a File

Use `-output` to write the report to a file instead of (or in addition to) stdout:

```bash
# Write to a specific file
gouvernante -rules ./rules -dir ./project -output report.txt

# Timestamped filename (auto)
gouvernante -rules ./rules -dir ./project -output auto
```

When `-output auto` is used, the scanner generates a filename like `gouvernante-2026-04-01T14-30-00.txt` (or `.json` if `-json` is also set).

Combine flags for CI artifact collection:

```bash
gouvernante -rules ./rules -dir ./project -json -output auto
```

## Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| `0` | Clean — no findings. | No action needed. |
| `1` | Error — scanner could not complete (bad rules path, unparseable lockfile, etc.). | Fix the error and re-run. |
| `2` | Findings detected — at least one package matched a rule. | Triage findings and remediate. |

Use exit codes in scripts to branch on results:

```bash
gouvernante -rules ./rules -dir ./project
case $? in
  0) echo "Clean" ;;
  1) echo "Scanner error — check configuration" ;;
  2) echo "Findings detected — review output" ;;
esac
```

---

## Self-Assessment

- [ ] Can you run a scan against the current directory with just a rules path?
- [ ] Do you know the difference between exit code 1 and exit code 2?
- [ ] Can you produce JSON output and write it to an auto-named file in one command?

## Next Steps

- **Integrate into CI/CD** --> [CI/CD Integration](ci-cd-integration.md)
- **Respond to an incident** --> [New npm Compromise Runbook](runbooks/new-npm-compromise.md)
- **Understand the rule format** --> [Rule Format](../architecture/rule-format.md)
