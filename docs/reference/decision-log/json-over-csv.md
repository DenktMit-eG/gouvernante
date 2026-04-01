---
tags:
  - reference
  - decisions
  - adr
  - rules
---

# ADR-002: JSON over CSV

!!! tldr "TL;DR"

    Use JSON as the canonical rule format. CSV is supported as an import-only
    format for bulk data entry, but rules are always stored and consumed as JSON.

!!! tip "Who is this for?"

    **Audience:** Rule authors and contributors working on the rule pipeline.
    **Reading time:** ~5 minutes.

---

## Status

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2025-01 |
| **Deciders** | Core team |

---

## Context

Each gouvernante rule describes a supply chain incident. A single rule can
contain:

- Multiple affected packages, each with multiple affected versions.
- Multiple host indicators (file paths, hashes, process names) across
  different operating systems.
- Aliases (CVE, GHSA, Snyk IDs), references (URLs), and remediation steps.

This structure is inherently nested. The rule format must be:

1. Machine-readable with schema validation.
2. Easy for humans to author and review in pull requests.
3. Parseable with Go's standard library (no external dependencies).
4. Expressive enough to represent one-to-many relationships without ambiguity.

---

## Options Considered

| Criterion | CSV | YAML | JSON |
|-----------|-----|------|------|
| **Nested data** | Poor — requires flattening, repeated rows, or multi-value columns | Excellent — native nesting | Excellent — native nesting |
| **Schema validation** | No standard schema language | JSON Schema via conversion | JSON Schema (native, mature tooling) |
| **Go standard library** | `encoding/csv` | Not available — requires `gopkg.in/yaml.v3` or custom parser | `encoding/json` |
| **Diff readability** | Good for flat data | Good | Good — especially with sorted keys |
| **Ambiguity** | High — delimiter conflicts, quoting edge cases, no types | Low | Very low — strict syntax, typed values |
| **Bulk authoring** | Excellent — spreadsheet-friendly | Moderate | Moderate |
| **Ecosystem tooling** | Spreadsheets, database exports | Text editors | Text editors, `jq`, schema validators |

---

## Decision

**Use JSON as the canonical format. Support CSV as an import-only path.**

Reasoning:

1. **Rules have nested structure.** A single rule can reference multiple
   packages, each with multiple affected versions and multiple IOCs. JSON
   represents this naturally. CSV would require either multiple files,
   repeated rows, or comma-separated-within-comma-separated hacks.

2. **JSON Schema validation.** The `pkg/rules/schema.json` file defines the exact
   structure, types, and constraints for rule files. This catches errors
   before they reach the scanner. No equivalent exists for CSV.

3. **Maps directly to Go structs.** `encoding/json` unmarshals rule files into
   Go structs with minimal external dependencies. Field tags handle naming
   conventions. This is the path of least resistance in Go.

4. **CSV remains useful for intake.** When a threat intel team produces a
   spreadsheet of compromised packages, a CSV import helper converts it to
   JSON. This keeps the authoring workflow flexible without compromising the
   canonical format.

5. **YAML was rejected** because Go's standard library does not include a YAML
   parser, and adding `gopkg.in/yaml.v3` would conflict with the minimal-dependency
   policy (see [ADR-003](minimal-dependencies.md)). YAML also introduces
   ambiguity risks (the Norway problem, implicit type coercion).

---

## Consequences

### Positive

- Rule files are validated at rest with JSON Schema and at load time by Go's
  JSON decoder.
- No external dependencies needed for rule parsing.
- Diffs in pull requests are clear — JSON changes are unambiguous.
- `jq` can be used for ad-hoc rule queries and transformations.

### Negative

- JSON is more verbose than YAML for deeply nested structures.
- Authors must manage commas and braces — no significant-whitespace shorthand.
- CSV import requires a conversion step, adding a tool to maintain.

---

## Next Steps

- **Learn the rule schema** --> [Rule Format](../../architecture/rule-format.md)
- **Write a rule** --> [Writing Rules](../../developer-guide/writing-rules.md)
- **Back to decision log** --> [Decision Log](index.md)
