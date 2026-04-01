---
tags:
  - reference
  - decisions
  - adr
  - dependencies
  - security
---

# ADR-003: Minimal Dependencies

!!! tldr "TL;DR"

    gouvernante keeps external dependencies minimal and carefully weighed.
    The scanning engine uses only the Go standard library. Format parsers
    may use vetted libraries where robustness justifies the trust surface.

!!! tip "Who is this for?"

    **Audience:** Contributors who want to add a dependency, and security reviewers.
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

gouvernante is a supply chain scanner. Its entire purpose is to detect
compromised dependencies in other projects. If the scanner itself has a
sprawling dependency tree, it becomes vulnerable to the same attack class
it is designed to detect.

This is not a theoretical concern:

- The `event-stream` incident (2018) showed that a single transitive dependency
  can inject malicious code.
- The `ua-parser-js`, `coa`, and `rc` compromises (2021) hit widely-used
  packages.
- Go modules are not immune — the `ctx` typosquat demonstrated this in the Go
  ecosystem.

At the same time, dogmatic purity has costs. Writing a custom YAML parser to
avoid a dependency creates maintenance burden and fragility that outweighs
the risk of a well-vetted library.

The policy must balance: **minimal trust surface** against **robust, maintainable code**.

---

## Options Considered

| Criterion | Zero dependencies | Minimal, vetted dependencies | Unconstrained dependencies |
|-----------|-------------------|------------------------------|---------------------------|
| **Supply chain risk** | None | Low — small, auditable set | High — transitive deps are opaque |
| **Audit surface** | Only this repository | This repo + 2-3 vetted modules | Large — `go.sum` can be hundreds of lines |
| **Robustness** | Lower — bespoke parsers break on format changes | Higher — libraries handle edge cases | Highest |
| **Maintenance** | Higher — must maintain custom parsers | Moderate | Lower |
| **Build reproducibility** | No network needed | Needs `github.com` at build time | Depends on module proxy |

---

## Decision

**Keep dependencies minimal and carefully weighed. Each dependency must justify
its trust surface expansion with a concrete robustness or correctness benefit.**

The dependency policy is scoped:

| Scope | Policy | Current dependencies |
|-------|--------|---------------------|
| **Scanning & matching engine** | Go standard library only | None |
| **Format parsers** | Vetted libraries allowed | `goccy/go-yaml` for pnpm lockfile parsing |
| **Test infrastructure** | Test-only deps allowed | `santhosh-tekuri/jsonschema` for schema validation |
| **CLI framework** | Standard library | `flag` package |

Reasoning:

1. **The scanning engine must be above suspicion.** The package matching,
   host indicator checking, and report generation code uses only the Go
   standard library. This is the code that makes security decisions.

2. **Format parsers benefit from real libraries.** A pnpm lockfile YAML
   change should not require a new binary release. `goccy/go-yaml` is
   well-maintained, hosted on `github.com` (no `gopkg.in` network issues),
   and handles edge cases that a custom parser would miss.

3. **Test-only dependencies don't ship in the binary.** `santhosh-tekuri/jsonschema`
   validates rules against the JSON Schema during testing but is not compiled
   into the production binary.

4. **The core invariant is: gouvernante never depends on the npm ecosystem
   it scans.** No JavaScript, no Node.js modules, no npm packages. This
   is non-negotiable.

---

## Consequences

### Positive

- The scanning engine's attack surface is limited to the Go standard library.
- The full dependency set is small enough to audit by hand.
- Format parsers are robust against upstream format changes.
- Test-only dependencies provide strong schema fidelity guarantees without
  bloating the production binary.

### Negative

- Contributors must evaluate whether a new dependency falls in the "parser"
  or "engine" scope before adding it.
- Builds require network access to `github.com` (though `go mod vendor`
  can restore offline builds).
- Each new dependency requires justification — this intentionally slows
  down dependency growth.

---

## Next Steps

- **See the YAML parser decision** --> [YAML Parser](custom-yaml-parser.md)
- **Understand the language choice** --> [Go over Node.js](go-over-nodejs.md)
- **Back to decision log** --> [Decision Log](index.md)
