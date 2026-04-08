---
tags:
  - rules
  - schema
  - reference
---

# Rule Format

!!! abstract "TL;DR"

    - Rules are JSON files following `pkg/rules/schema.json`.
    - Each file has a `schema_version` and a `rules` array.
    - A rule combines package detection, dropper identification, host IOCs, and remediation.
    - Version expressions use npm semver syntax.

!!! tip "Who is this for?"

    **Audience:** Anyone writing, reviewing, or consuming rules.
    **Reading time:** ~8 minutes.

---

## Structure

```json
{
  "schema_version": "1.0.0",
  "rules": [
    {
      "id": "SSC-2025-001",
      "title": "Human-readable title",
      "kind": "compromised-release",
      "ecosystem": "npm",
      "severity": "critical",
      "summary": "Brief description.",
      "aliases": [],
      "references": [],
      "package_rules": [],
      "dropper_packages": [],
      "host_indicators": [],
      "remediation": {},
      "metadata": {}
    }
  ]
}
```

## Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier. Convention: `SSC-YYYY-NNN`. |
| `title` | string | Human-readable title. |
| `kind` | enum | Incident type (see below). |
| `ecosystem` | enum | Currently only `"npm"`. |
| `severity` | enum | `low`, `medium`, `high`, `critical`. |
| `package_rules` | array | At least one package rule entry. |

## Kind Values

| Value | Use when |
|-------|----------|
| `compromised-release` | Legitimate package had malicious versions published. |
| `malicious-package` | Purpose-built malicious package (typosquat, etc.). |
| `vulnerability` | Traditional CVE-style vulnerability. |
| `dropper` | Package whose sole purpose is payload delivery. |
| `suspicious-artifact` | Artifact that warrants investigation. |

## Package Rules

```json
{
  "package_name": "axios",
  "affected_versions": ["=1.7.8", "=1.7.9", "=1.8.1"],
  "lockfile_ecosystems": ["npm", "pnpm", "yarn", "bun"],
  "notes": "Optional context."
}
```

### Version Expressions

| Format | Example | Meaning |
|--------|---------|---------|
| Exact | `=1.7.8` | Only version 1.7.8. |
| Bare | `1.7.8` | Same as `=1.7.8`. |
| Wildcard | `*` | Any version. |
| Range | `>=1.0.0 <2.0.0` | Versions satisfying the semver constraint. |
| Caret | `^1.7.0` | Compatible versions (same major). |
| Tilde | `~1.7.0` | Patch-level versions (same major.minor). |

Semver range matching is implemented using [Masterminds/semver v3](https://github.com/Masterminds/semver). `VersionSet.Matches()` checks exact match first, then evaluates semver constraints. `VersionSet.RangeCoversVersion()` checks if a `package.json` range expression could resolve to a compromised version. Both sides are compiled into intervals with optional lower/upper bounds (e.g., `<1.0.0` → `(-∞, 1.0.0)`), and overlap is structural: two intervals overlap unless one ends strictly before the other starts. Disjunctive constraints (`||`) are a union of intervals.

## Dropper Packages

```json
{
  "package_name": "plain-crypto-js",
  "notes": "Installed by compromised axios postinstall script."
}
```

Dropper packages are indexed with wildcard matching — any version is a finding.

## Host Indicators

```json
{
  "type": "file",
  "path": "/tmp",
  "file_name": "ld.py",
  "oses": ["linux"],
  "hashes": [
    { "algorithm": "sha256", "value": "abcdef..." }
  ],
  "confidence": "high",
  "notes": "RAT payload dropped by postinstall script."
}
```

### Indicator Types

| Type | Description | Status |
|------|-------------|--------|
| `file` | File existence check (`path` and/or `file_name`); hash verification when `hashes` are present. | Done |
| `process` | Running process name. | Schema only |
| `registry` | Windows registry key. | Schema only |
| `network` | Network connection indicator. | Schema only |
| `environment` | Environment variable check. | Schema only |

### Hash Arrays

One file indicator can have multiple hashes for variant builds:

```json
"hashes": [
  { "algorithm": "sha256", "value": "aaa..." },
  { "algorithm": "sha256", "value": "bbb..." }
]
```

Validated lengths: md5=32, sha1=40, sha256=64, sha512=128 hex characters.

### Path Expansion

- `%PROGRAMDATA%` → Windows ProgramData directory.
- `%APPDATA%` → Windows AppData/Roaming directory.
- `~` → Current user's home directory.

## Aliases, References, Remediation, Metadata

See the full JSON Schema at `pkg/rules/schema.json` in the repository for all optional fields including `aliases`, `references`, `remediation`, and `metadata`.

---

!!! question "Check your understanding"

    - [ ] Can you write a minimal valid rule from memory?
    - [ ] Do you know the difference between a package rule and a dropper package?
    - [ ] Can you explain why host indicator hashes are arrays?

## Next Steps

- **Write a real rule** → [Writing Rules](../developer-guide/writing-rules.md)
- **See existing rules** → browse the `rules/` directory
- **Validate rules** → check against `pkg/rules/schema.json`
