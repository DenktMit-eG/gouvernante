---
tags:
  - operations
  - scanning
  - cli
---

# Running Scans

!!! tldr "TL;DR"

    - `gouvernante -rules <dir>` is the minimum viable command.
    - The scanner auto-detects lockfiles (`pnpm-lock.yaml`, `package-lock.json`, `yarn.lock`, `package.json`) in the target directory.
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
| `-recursive` | No | `false` | Recursively scan subdirectories for lockfiles. |
| `-host` | No | `false` | Enable host filesystem IOC checks and scan installed packages. |
| `-heuristic` | No | `false` | Scan JS/shell files in node_modules for malware patterns. No rules needed. |
| `-output` | No | — | Write output to a file. Use `auto` for a timestamped filename. |
| `-json` | No | `false` | Emit output as JSON instead of human-readable text. |
| `-trace` | No | `false` | Enable debug-level logging. |

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
- `package.json` (dependencies and devDependencies; range expressions are checked for overlap with compromised versions)

All detected lockfiles are scanned in a single run. Findings from each lockfile are reported separately.

## Scanning a Specific Lockfile

When you already know which lockfile you want to check, skip auto-detection:

```bash
gouvernante -rules ./rules -lockfile ./package-lock.json
```

This is useful when a project has multiple lockfiles and you only care about one, or when the lockfile lives outside the project directory.

## Recursive Scanning

The `-recursive` flag tells gouvernante to walk all subdirectories of the target directory looking for lockfiles. This is useful for monorepos or workspaces with many nested projects:

```bash
gouvernante -rules ./rules -dir ./monorepo -recursive
```

Without `-recursive`, only the top-level target directory is checked for lockfiles. With it, every subdirectory is searched.

Combine with other flags as needed:

```bash
# Recursive scan with host checks and JSON output
gouvernante -rules ./rules -dir ./monorepo -recursive -host -json -output auto
```

## Host Indicator Checks

The `-host` flag performs a comprehensive scan of the host filesystem. It goes well beyond checking rule-defined IOC paths:

1. **Host IOC files** — checks paths defined in each rule's `host_indicators` array (e.g., `/tmp/ld.py`, `~/.node_modules/.cache`).
2. **Project `node_modules`** — scans `node_modules` directories within the target project directories.
3. **Global `node_modules`** — scans global `node_modules` directories using `$NPM_CONFIG_PREFIX` and well-known OS paths (no external binaries are executed).
4. **pnpm store and cache** — scans the pnpm content-addressable store and cache directories.
5. **nvm cache and globals** — scans nvm's cached versions and globally installed packages.
6. **npm cache blobs** — scans the npm cache blob storage.

```bash
gouvernante -rules ./rules -dir ./project -host
```

Host checks run after lockfile scanning.

!!! warning

    Host checks read the local filesystem. On shared build agents or containers, paths may not be meaningful. Use `-host` primarily on developer workstations or long-lived servers.

## Heuristic Scanning

The `-heuristic` flag runs a separate scan pipeline that checks JavaScript and shell files inside `node_modules` for high-confidence malware patterns. Unlike rule-based scanning, heuristic mode does not require a rules directory — it detects suspicious code patterns directly.

```bash
# Scan a single project
gouvernante -heuristic -dir ./my-project

# Recursive scan across a monorepo
gouvernante -heuristic -dir ./monorepo -recursive

# JSON output for CI
gouvernante -heuristic -dir . -json -output auto
```

Heuristic mode detects five patterns:

| Pattern | What it catches |
|---------|----------------|
| `HEUR-EVAL-DECODE` | `eval(atob(...))` or `eval(Buffer.from(...))` — decoded payload execution |
| `HEUR-PIPE-SHELL` | `curl ... \| sh` or `wget ... \| bash` — download and execute |
| `HEUR-POSTINSTALL-EXEC` | Suspicious `preinstall`/`postinstall`/`preuninstall` lifecycle scripts |
| `HEUR-ENV-HARVEST` | 3+ secret environment variables accessed with a network call in the same file |
| `HEUR-HEX-EXEC` | Long hex-encoded payload (100+ chars) near `eval`/`exec`/`Function` |

Files scanned per package: `.js`, `.cjs`, `.mjs`, `.sh` — up to 50 files, max 512 KB each. Minified files (`.min.js`) are skipped.

!!! info

    Heuristic findings are labeled with severity `high` (not `critical`) because they are pattern-based suspicions, not confirmed compromises. Use them as an early warning alongside rule-based scanning.

## Output Formats

### Text Output (Default)

Human-readable text written to stdout:

```bash
gouvernante -rules ./rules -dir ./project
```

```
=== Scan Configuration ===
...

=== Supply Chain Scan Report ===

Files scanned: 2
Total packages analyzed: 150
Findings: 2

--- Finding 1 ---
  Rule:     SSC-2025-001
  Title:    Compromised axios release
  Severity: critical
  Type:     package
  Package:  axios@1.7.9
  Lockfile: package-lock.json

--- Finding 2 ---
  Rule:     SSC-2025-001
  Title:    Dropper package
  Severity: critical
  Type:     package
  Package:  plain-crypto-js@1.0.0
  Lockfile: pnpm-lock.yaml

Scan complete: 2 findings in 2 lockfiles.
```

### JSON Output

Machine-parseable JSON, suitable for piping into `jq` or ingesting in CI.

> **Note:** JSON mode emits only `findings` and `summary`. The detailed Host
> Indicator Checks and Node Modules Checks inventories shown in text mode are
> not included in JSON output.

```bash
gouvernante -rules ./rules -dir ./project -json
```

```json
{
  "findings": [
    {
      "rule_id": "SSC-2025-001",
      "rule_title": "Compromised axios release",
      "severity": "critical",
      "type": "package",
      "package": "axios",
      "version": "1.7.9",
      "lockfile": "package-lock.json"
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

Use `-output` to write the report to a file instead of stdout:

```bash
# Write to a specific file
gouvernante -rules ./rules -dir ./project -output report-heuristics.txt

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
