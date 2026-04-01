---
tags:
  - reference
  - decisions
  - adr
  - go
---

# ADR-001: Go over Node.js

!!! tldr "TL;DR"

    Use Go to build the supply chain scanner instead of Node.js, Bash, or Rust.
    A compromised npm toolchain cannot be trusted to scan itself.

!!! tip "Who is this for?"

    **Audience:** Contributors wondering why this is a Go project, not a Node.js CLI.
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

gouvernante detects compromised packages in the npm ecosystem. When a supply
chain attack is active, the Node.js runtime and its package manager may
themselves be compromised. Running `npm audit` or a Node.js-based scanner
during an active incident means trusting the very toolchain under attack.

Requirements:

- The scanner must not depend on npm or any npm packages.
- It must produce a single binary that can be copied to any machine.
- It must run on Linux, macOS, and Windows without additional runtimes.
- It must be easy to test and maintain for a small team.

---

## Options Considered

| Criterion | Bash | Node.js | Go | Rust |
|-----------|------|---------|-----|------|
| **No npm dependency** | Yes | No — runtime is the attack surface | Yes | Yes |
| **Single binary** | No — requires bash + coreutils | No — requires Node.js runtime | Yes — static binary via `go build` | Yes — static binary via `cargo build` |
| **Cross-platform** | Poor — Windows support is painful | Good | Excellent — built-in cross-compilation | Excellent |
| **Real parsing** | Fragile — regex/sed/awk | Good — native JSON, YAML libs available | Good — strong standard library | Good |
| **Team familiarity** | High | High | Medium | Low |
| **Testing** | Manual/fragile | Good — Jest, Vitest | Excellent — `go test` built in | Good — `cargo test` built in |
| **Build complexity** | None | npm install + bundler | `go build` — one command | `cargo build` — one command, but slower |
| **Dependency risk** | Low | High — transitive npm deps | Controllable — minimal deps policy | Moderate — crates ecosystem |

---

## Decision

**Use Go.**

Reasoning:

1. **Cannot trust the compromised toolchain.** This is the decisive factor. A
   Node.js scanner that runs `npm install` to set up its own dependencies
   is vulnerable to the exact attack class it is meant to detect. Go produces
   a static binary with no runtime dependency on npm.

2. **Single static binary.** `go build` produces one executable. No runtime,
   no `node_modules`, no installer. Copy the binary to a CI runner or an
   engineer's laptop and it works.

3. **Cross-compilation is trivial.** `GOOS=linux GOARCH=amd64 go build` — no
   toolchain setup, no Docker cross-build.

4. **Built-in testing.** `go test` is part of the standard toolchain. Table-driven
   tests, race detection, and coverage are available without third-party
   frameworks.

5. **Rust was considered but rejected** due to lower team familiarity and longer
   compile times. The scanner does not have performance requirements that would
   justify the steeper learning curve.

---

## Consequences

### Positive

- The scanner is immune to npm supply chain attacks by construction.
- Distribution is a single file copy — no package manager, no installer.
- CI/CD integration is straightforward: download binary, run it.
- The standard library covers JSON parsing, file I/O, flag parsing, and testing.

### Negative

- Contributors must know Go (or learn it).
- The npm/pnpm lockfile parsers must be written from scratch — no existing Go
  libraries for these formats.
- The custom YAML parser (see [ADR-004](custom-yaml-parser.md)) was a direct
  consequence of this decision combined with the minimal-dependency policy.

---

## Next Steps

- **See the dependency policy** --> [Minimal Dependencies](minimal-dependencies.md)
- **See the custom parser** --> [Custom YAML Parser](custom-yaml-parser.md)
- **Back to decision log** --> [Decision Log](index.md)
