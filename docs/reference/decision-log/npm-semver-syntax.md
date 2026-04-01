---
tags:
  - reference
  - decisions
  - adr
  - semver
  - rules
---

# ADR-005: npm Semver Syntax

!!! tldr "TL;DR"

    Use npm semver expressions (e.g., `>=6.1.0 <6.1.2`, `1.0.0 - 1.0.5`) for
    the `affected_versions` field in rules, not Maven-style range notation.

!!! tip "Who is this for?"

    **Audience:** Rule authors and contributors working on version matching.
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

Each package rule in gouvernante includes an `affected_versions` array that
specifies which versions of a package are compromised. The scanner matches
resolved versions from lockfiles against these expressions.

The version syntax must be:

1. Familiar to the people writing rules (security engineers in the npm
   ecosystem).
2. Expressive enough to represent ranges, exact versions, and combinations.
3. Implementable in Go without external dependencies.

Two conventions exist in the industry:

- **npm semver syntax:** `>=1.0.0 <2.0.0`, `~1.2.3`, `^1.2.3`, `1.0.0 - 1.0.5`.
  Used by npm, pnpm, yarn, and the broader Node.js ecosystem.
- **Maven-style ranges:** `[1.0.0,2.0.0)`, `(,1.5.0]`. Used by Maven, Ivy,
  and some advisory databases (OSV uses a different format entirely).

---

## Options Considered

| Criterion | npm semver | Maven ranges | Custom syntax |
|-----------|-----------|--------------|---------------|
| **Familiarity for npm rule authors** | Native — this is what they write every day | Foreign — requires learning bracket notation | Requires documentation and training |
| **Ecosystem alignment** | Matches the ecosystem being scanned | Mismatched | N/A |
| **Expressiveness** | Full range support, tilde, caret, hyphen ranges, pre-release tags | Full range support | Depends on design |
| **Advisory database compatibility** | npm advisory format uses this directly | GitHub/OSV advisories use their own formats | N/A |
| **Implementation complexity** | Medium — well-documented spec, but many features | Medium — simpler syntax, fewer features | Variable |
| **Conversion from other formats** | Can receive Maven ranges via converter | Native | Requires converters for everything |

---

## Decision

**Use npm semver syntax for `affected_versions`.**

Reasoning:

1. **The scanner targets the npm ecosystem.** Rule authors are JavaScript and
   Node.js developers and security engineers. They already read and write npm
   semver expressions daily. Using the same syntax eliminates a cognitive
   translation step.

2. **Direct compatibility with advisories.** When a new npm advisory is
   published, the affected version range is already in npm semver syntax.
   Rule authors can copy it directly into the rule file without conversion.

3. **Maven ranges would require a converter at authoring time.** If rules used
   Maven-style `[1.0.0,2.0.0)` notation, every rule author would need to
   mentally (or programmatically) convert from the npm advisory format. This
   adds friction and introduces conversion errors.

4. **Import helper planned for other formats.** For cases where version ranges
   arrive in Maven or OSV format (e.g., from cross-ecosystem advisory feeds),
   an import helper will convert them to npm semver syntax before they enter
   the rule file. This keeps the canonical format consistent while supporting
   multiple input sources.

5. **The semver matching logic is implementable in Go.** The scanner implements
   the subset of npm semver needed for version matching (comparators, ranges,
   hyphen ranges, tilde, caret) without external dependencies. The full npm
   semver spec is well-documented at [node-semver](https://github.com/npm/node-semver).

---

## Consequences

### Positive

- Rule authors work in a syntax they already know.
- Advisory version ranges can be copied into rules without conversion.
- Rules are readable by anyone familiar with the npm ecosystem.
- A single semver implementation covers both rule matching and future
  lockfile version comparisons.

### Negative

- The Go semver implementation must be maintained in-house (consistent with
  the minimal-dependency policy in [ADR-003](minimal-dependencies.md)).
- Rules are less portable to non-npm ecosystems. If gouvernante ever expands
  beyond npm, the version syntax may need to be revisited or made
  ecosystem-specific.
- An import helper for Maven-style ranges adds a tool to build and maintain.

---

## Next Steps

- **Write a rule with version ranges** --> [Writing Rules](../../developer-guide/writing-rules.md)
- **See the rule schema** --> [Rule Format](../../architecture/rule-format.md)
- **Back to decision log** --> [Decision Log](index.md)
