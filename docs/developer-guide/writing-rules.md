---
title: Writing Rules
tags:
  - developer-guide
  - rules
  - json
  - supply-chain
  - contributing
---

# Writing Rules

!!! tldr "TL;DR"

    Copy an existing rule, fill in the incident details, test with
    `gouvernante -rules <dir> -lockfile <test-lockfile>`, and verify exit code 2.

!!! info "Who is this for?"

    Security analysts and contributors who need to encode a new supply-chain
    incident as a machine-readable rule that gouvernante can evaluate.

## Overview

Rules are JSON files that you provide to gouvernante via the `-rules` flag.
Each file contains a `schema_version` and a `rules` array. The scanner loads
all `.json` files from the rules directory, builds a package index, and matches
lockfile entries against it.

The canonical schema is defined in `pkg/rules/schema.json`. The Go-side
`Validate()` method in `pkg/rules/validate.go` enforces the same constraints
programmatically.

## Rule JSON Structure

Use this template based on the real axios incident rule:

```json
{
  "schema_version": "1.0.0",
  "rules": [
    {
      "id": "SSC-2026-001",
      "title": "Short human-readable incident title",
      "kind": "compromised-release",
      "ecosystem": "npm",
      "severity": "critical",
      "summary": "Brief description of what happened and what the attack does.",
      "aliases": [
        { "type": "cve", "value": "CVE-2026-XXXXX" }
      ],
      "references": [
        { "type": "advisory", "url": "https://example.com/advisory" }
      ],
      "package_rules": [
        {
          "package_name": "compromised-pkg",
          "affected_versions": ["=1.0.0", "=1.0.1"],
          "lockfile_ecosystems": ["npm", "pnpm", "yarn", "bun"]
        }
      ],
      "dropper_packages": [
        {
          "package_name": "malicious-helper",
          "notes": "Installed by postinstall script of compromised-pkg."
        }
      ],
      "host_indicators": [
        {
          "type": "file",
          "path": "/tmp",
          "file_name": "payload.bin",
          "oses": ["linux"],
          "hashes": [
            {
              "algorithm": "sha256",
              "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }
          ],
          "confidence": "high",
          "notes": "RAT binary dropped by postinstall script."
        }
      ],
      "remediation": {
        "summary": "Pin to a safe version, remove dropper packages, check for host artifacts.",
        "steps": [
          "Pin compromised-pkg to a known-good version.",
          "Remove malicious-helper from dependencies.",
          "Regenerate lockfiles.",
          "Check for host indicator files.",
          "Rotate credentials if host indicators are confirmed."
        ]
      },
      "metadata": {
        "published_at": "2026-01-15T00:00:00Z",
        "last_updated_at": "2026-01-16T00:00:00Z"
      }
    }
  ]
}
```

## Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | string | Semver format (e.g., `"1.0.0"`). |
| `id` | string | Unique identifier. Convention: `SSC-YYYY-NNN`. |
| `title` | string | Human-readable one-line summary. |
| `kind` | enum | `compromised-release`, `malicious-package`, `vulnerability`, `dropper`, `suspicious-artifact`. |
| `ecosystem` | enum | Currently only `"npm"`. |
| `severity` | enum | `low`, `medium`, `high`, `critical`. |
| `package_rules` | array | At least one entry (see below). |

### Package rule entry

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `package_name` | string | Yes | npm package name (e.g., `"axios"`, `"@scope/pkg"`). |
| `affected_versions` | array | Yes | At least one version expression. |
| `lockfile_ecosystems` | array | No | Restrict to specific lockfile types: `npm`, `pnpm`, `yarn`, `bun`. |
| `notes` | string | No | Context for analysts. |

### Version expressions

`affected_versions` entries are interpreted as logical OR:

| Format | Example | Meaning |
|--------|---------|---------|
| Exact (with =) | `"=1.7.8"` | Only version 1.7.8. |
| Exact (bare) | `"1.7.8"` | Same as `"=1.7.8"`. |
| Wildcard | `"*"` | Any version (use for dropper/typosquat packages). |

| Range | `">=1.0.0 <2.0.0"` | Versions satisfying the semver constraint. |
| Caret | `"^1.7.0"` | Compatible versions (same major). |
| Tilde | `"~1.7.0"` | Patch-level versions (same major.minor). |

Semver range matching is implemented using Masterminds/semver v3. Ranges are evaluated via `VersionSet.Matches()` (exact match first, then semver constraints). When scanning `package.json`, `VersionSet.RangeCoversVersion()` checks whether a dependency range could resolve to a compromised version. Both the rule and dependency ranges are compiled into intervals with optional lower/upper bounds (e.g., `<1.0.0` becomes `(-∞, 1.0.0)`), and overlap is determined structurally: two intervals overlap unless one ends strictly before the other starts. Disjunctive constraints (`||`) are handled as a union of intervals.

## Optional Fields

### aliases

Alternative identifiers for the incident:

```json
"aliases": [
  { "type": "cve", "value": "CVE-2025-12345" },
  { "type": "ghsa", "value": "GHSA-xxxx-yyyy-zzzz" },
  { "type": "snyk", "value": "SNYK-JS-PKG-111111" },
  { "type": "article", "value": "Blog post title" },
  { "type": "internal", "value": "INC-2025-042" },
  { "type": "other", "value": "Vendor reference" }
]
```

### references

Links to advisories and articles:

```json
"references": [
  { "type": "advisory", "url": "https://example.com/advisory" },
  { "type": "article", "url": "https://example.com/blog" },
  { "type": "vendor", "url": "https://example.com/vendor" },
  { "type": "repository", "url": "https://github.com/org/repo" },
  { "type": "other", "url": "https://example.com/other" }
]
```

### dropper_packages

Auxiliary malicious packages. Indexed with wildcard version matching — any
version is a finding:

```json
"dropper_packages": [
  { "package_name": "plain-crypto-js", "notes": "Payload delivery via postinstall." }
]
```

### host_indicators

Filesystem artifacts left by the compromise. The schema supports five types,
though only `file` is currently checked by the scanner:

| Type | Status | Fields |
|------|--------|--------|
| `file` | Implemented | `path` and/or `file_name` (at least one required), optional `hashes` (schema-validated but not yet checked at runtime) |

> **Note:** When only `file_name` is provided without `path`, the scanner resolves the file relative to the working directory where the CLI is launched.
| `process` | Schema only | `value` (process name) |
| `registry` | Schema only | `value` (registry key path) |
| `network` | Schema only | `value` (host:port or domain) |
| `environment` | Schema only | `value` (env var name) |

File indicators can include multiple hashes for variant builds:

```json
{
  "type": "file",
  "path": "/tmp",
  "file_name": "payload.bin",
  "oses": ["linux", "macos"],
  "hashes": [
    { "algorithm": "sha256", "value": "<64 hex chars>" },
    { "algorithm": "sha256", "value": "<64 hex chars, different build>" }
  ],
  "confidence": "high",
  "notes": "Description of what this file is."
}
```

Hash lengths are validated per algorithm: md5=32, sha1=40, sha256=64, sha512=128 hex characters.

Confidence values: `low`, `medium`, `high`.

OS values: `linux`, `macos`, `windows`.

**Constraint:** hashes are only allowed on `file` type indicators.

### remediation

Guidance for affected teams:

```json
"remediation": {
  "summary": "One-line action summary.",
  "steps": [
    "Step 1.",
    "Step 2."
  ]
}
```

### metadata

Publication timestamps (ISO 8601):

```json
"metadata": {
  "published_at": "2025-09-15T00:00:00Z",
  "last_updated_at": "2025-09-16T00:00:00Z"
}
```

## Step-by-Step

### 1. Assign a unique ID

Check existing rule files for the highest `SSC-YYYY-NNN` value, then increment.

### 2. Fill in incident details

Populate `title`, `kind`, `severity`, `summary`, and `references` from the
advisory source.

### 3. Define affected packages

List every compromised package name, its affected versions, and optionally
restrict to specific lockfile ecosystems.

### 4. Add dropper packages (if any)

Typosquats and helper packages published alongside the primary compromise.

### 5. Add host indicators (if any)

File paths, hashes, or other IOCs that the scanner can check with the `-host`
flag. Remember: file indicators need at least one of `path` or `file_name`.

### 6. Write remediation steps

Tell the user exactly what to upgrade, remove, and check.

### 7. Validate the rule

Use the Go-side validation to catch schema errors before distribution:

```bash
# Quick test: does the scanner load the rule without errors?
gouvernante -rules /path/to/your/rules -dir /path/to/project
```

For programmatic rule construction, call `RuleSet.Validate()` before
serializing to guarantee schema compliance.

### 8. Test detection

Create or find a lockfile containing the affected package, then verify:

```bash
gouvernante -rules /path/to/rules -lockfile /path/to/test-lockfile
echo $?
# Expected: 2 (findings detected)
```

Also test against a clean lockfile to verify no false positives:

```bash
gouvernante -rules /path/to/rules -lockfile /path/to/clean-lockfile
echo $?
# Expected: 0 (clean)
```

## Quality Checklist

Before distributing a new rule:

- [ ] **Unique ID** — no other rule uses the same `SSC-YYYY-NNN`.
- [ ] **All required fields** — `id`, `title`, `kind`, `ecosystem`, `severity`, `package_rules`.
- [ ] **Verified versions** — confirmed from the upstream advisory, not just a blog post.
- [ ] **Hash lengths** — SHA-256 = 64 hex chars, SHA-1 = 40, MD5 = 32, SHA-512 = 128.
- [ ] **File indicators have path or file_name** — at least one is required.
- [ ] **Hashes only on file indicators** — not on process/network/registry/environment.
- [ ] **Actionable remediation** — tells the user what to do, not just what is wrong.
- [ ] **Valid JSON** — `python3 -m json.tool <file>` exits cleanly.
- [ ] **Scanner test** — detection verified with a test lockfile (exit code 2).
- [ ] **No false positives** — clean lockfile returns exit code 0.

## Self-Assessment

- [ ] Can you write a minimal valid rule from memory (required fields only)?
- [ ] Do you know the difference between `package_rules` and `dropper_packages`?
- [ ] Can you explain why file indicators need `path` or `file_name` but process indicators don't?

## Next Steps

- [Rule Format Specification](../architecture/rule-format.md) — full schema reference.
- [Adding Parsers](adding-parsers.md) — if the incident involves a lockfile
  format gouvernante does not yet support.
- [Testing](testing.md) — how to write and run tests for rule loading.
