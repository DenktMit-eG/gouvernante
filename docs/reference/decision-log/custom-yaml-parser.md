---
tags:
  - reference
  - decisions
  - adr
  - parser
  - pnpm
---

# ADR-004: YAML Parser for pnpm Lockfiles

!!! tldr "TL;DR"

    Use `goccy/go-yaml` for pnpm lockfile parsing. A proper YAML library is
    more resilient to formatting changes across pnpm versions and eliminates
    an entire class of parser maintenance.

!!! tip "Who is this for?"

    **Audience:** Contributors working on lockfile parsers.
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

gouvernante needs to parse `pnpm-lock.yaml` to extract package names and
resolved versions. The minimal-dependency policy ([ADR-003](minimal-dependencies.md))
favors standard library solutions, but pnpm lockfiles are YAML, and Go's
standard library does not include a YAML parser.

A custom line-based parser is possible — pnpm lockfiles follow a rigid
structure — but it is fragile. Any change to pnpm's YAML formatting
(indentation, quoting, comment placement, flow vs block style) could break
extraction even when the actual data fields are unchanged. This creates
maintenance burden and risks silent breakage on pnpm upgrades.

---

## Options Considered

| Criterion | `gopkg.in/yaml.v3` | `goccy/go-yaml` | Custom line-based parser |
|-----------|--------------------|--------------------|--------------------------|
| **Correctness** | Full YAML spec | Full YAML spec | Only handles pnpm lockfile structure |
| **Resilience to format changes** | High | High | Low — breaks on formatting changes |
| **Network policy** | Blocked (`gopkg.in`) | OK (`github.com`) | No network needed |
| **Maintenance burden** | Low — upstream maintains | Low — upstream maintains | Medium — must track pnpm versions |
| **Dependency cost** | One external module | One external module | None |

---

## Decision

**Use `goccy/go-yaml` for pnpm lockfile parsing.**

Reasoning:

1. **Robustness over purity.** A minor formatting change in pnpm's output
   (different quoting, extra whitespace, reordered keys) would break a custom
   parser but is handled transparently by a real YAML library. Shipping more
   binary versions to chase formatting changes is worse than adding one
   dependency.

2. **`goccy/go-yaml` over `gopkg.in/yaml.v3`.** The `goccy/go-yaml` library
   is hosted on `github.com`, avoiding network-policy issues with `gopkg.in`.
   It also supports `yaml.MapSlice` for preserving key order.

3. **Simpler code.** The YAML library handles unmarshaling into a struct with
   `packages` and `snapshots` map keys. The `splitPackageKey` function still
   parses the key format (`axios@1.7.9`, `@scope/pkg/1.0.0`), which is the
   domain-specific part that belongs in our code.

4. **Consistent with ADR-003.** The minimal-dependency policy allows vetted
   libraries for format parsers. YAML parsing for a YAML-based lockfile is
   exactly the kind of use case that justifies a dependency.

---

## Consequences

### Positive

- Resilient to pnpm lockfile formatting changes across versions.
- Eliminates an entire class of parser bugs (indentation sensitivity,
  quoting edge cases, comment handling).
- Code is shorter and easier to understand.
- Handles YAML features that a custom parser would skip (flow mappings,
  anchors, multi-line keys if pnpm ever uses them).

### Negative

- Adds a runtime dependency (`goccy/go-yaml`). This is a trust surface
  expansion, though the library is well-maintained and widely used.
- The binary size increases slightly.

---

## Next Steps

- **See the dependency policy** --> [Minimal Dependencies](minimal-dependencies.md)
- **Learn about adding new parsers** --> [Adding Lockfile Parsers](../../developer-guide/adding-parsers.md)
- **Back to decision log** --> [Decision Log](index.md)
