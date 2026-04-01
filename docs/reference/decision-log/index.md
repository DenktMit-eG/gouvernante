---
tags:
  - reference
  - decisions
  - adr
---

# Decision Log

!!! tldr "TL;DR"

    This section records significant architectural and design decisions using
    Architecture Decision Records (ADRs). Each record captures the context,
    options considered, the decision made, and its consequences.

!!! tip "Who is this for?"

    **Audience:** Contributors, maintainers, and anyone asking "why did you do it this way?"
    **Reading time:** ~2 minutes for this index; ~5 minutes per decision record.

---

## What is an ADR?

An Architecture Decision Record (ADR) documents a single decision that has
a significant impact on the project's structure, dependencies, or behavior.
ADRs exist so that future contributors can understand the reasoning behind
past decisions without having to reverse-engineer intent from the code.

Each ADR follows a consistent structure:

1. **TL;DR** — one-sentence summary of the decision.
2. **Status / Date / Deciders** — current state and who made the call.
3. **Context** — the situation that required a decision.
4. **Options Considered** — comparison table of alternatives.
5. **Decision** — what was chosen and why.
6. **Consequences** — positive and negative outcomes.

---

## Decision index

| ID | Decision | Status |
|----|----------|--------|
| ADR-001 | [Go over Node.js](go-over-nodejs.md) — Use Go instead of Node.js or Bash for the scanner binary. | Accepted |
| ADR-002 | [JSON over CSV](json-over-csv.md) — Use JSON as the canonical rule format with CSV as import-only. | Accepted |
| ADR-003 | [Minimal Dependencies](minimal-dependencies.md) — Minimal, carefully weighed external Go modules. | Accepted |
| ADR-004 | [YAML Parser](custom-yaml-parser.md) — goccy/go-yaml for pnpm lockfile parsing. | Accepted |
| ADR-005 | [npm Semver Syntax](npm-semver-syntax.md) — Use npm semver expressions for affected_versions fields. | Accepted |

---

## When to write a new ADR

Write a new ADR when a decision:

- Changes the project's language, framework, or build system.
- Adds or removes an external dependency.
- Alters the rule format or lockfile parsing strategy.
- Affects how the scanner is distributed or deployed.
- Is something a future contributor would question.

Use the next available ID (ADR-006, ADR-007, ...) and add the entry to both
the table above and the `nav` section in `mkdocs.yml`.

---

## Next Steps

- **Start with the foundational decision** --> [Go over Node.js](go-over-nodejs.md)
- **Understand the rule format choice** --> [JSON over CSV](json-over-csv.md)
- **See the full project layout** --> [Configuration Files](../configuration-files.md)
