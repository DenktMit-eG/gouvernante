---
tags:
  - reference
  - configuration
  - project-structure
---

# Configuration Files

!!! tldr "TL;DR"

    gouvernante has no runtime config file — behavior is controlled entirely by
    CLI flags. This page documents the repository layout, rule directory structure,
    linter configuration, Makefile targets, and documentation setup.

!!! tip "Who is this for?"

    **Audience:** Contributors and maintainers who need to understand the project structure.
    **Reading time:** ~5 minutes.

---

## Repository structure

```text
gouvernante/
├── cmd/
│   └── gouvernante/          # CLI entrypoint (main.go)
├── pkg/
│   ├── lockfile/            # Lockfile parsers (pnpm, npm, yarn)
│   ├── rules/               # Rule loading, indexing, validation
│   │   └── schema.json      # JSON Schema for rule validation
│   └── scanner/             # Core scan engine
├── testdata/                # Test fixtures and sample data
│   ├── package-lock.json    # npm lockfile fixture
│   ├── pnpm-lock.yaml       # pnpm lockfile fixture
│   └── rules/
│       ├── valid/           # 18 schema-valid rule fixtures
│       ├── invalid/         # 18 schema-invalid rule fixtures
│       └── incidents/       # Sample incident rules (axios, shai-hulud-2)
├── docs/                    # MkDocs documentation source
├── .golangci.yml            # golangci-lint configuration
├── .woodpecker.yml          # Woodpecker CI pipeline
├── Makefile                 # Build, test, lint, and demo targets
├── mkdocs.yml               # MkDocs site configuration
├── go.mod                   # Go module definition
└── docker-compose.docs.yml       # Local docs preview server
```

---

## pkg/rules/schema.json

The JSON Schema (draft-07) lives alongside the Go code it validates. It defines
the structure of rule files: required fields, enum values, and conditional
constraints (file indicators need path or file_name, hashes only on files,
hash length per algorithm).

The Go-side `Validate()` method in `pkg/rules/validate.go` enforces the same
constraints programmatically for rules constructed in code.

See [Rule Format](../architecture/rule-format.md) for the full schema documentation and [Writing Rules](../developer-guide/writing-rules.md) for authoring guidance.

## testdata/rules/incidents/

Sample incident rule files for testing and demos. Each follows the naming
convention `<incident>-<year>.json` and contains a `schema_version` + `rules` array.

---

## .golangci.yml

The linter configuration enables a strict set of linters beyond the defaults:

- **Default linters:** `errcheck`, `gosimple`, `govet`, `ineffassign`, `staticcheck`, `unused`.
- **Additional linters:** `bodyclose`, `dupl`, `errorlint`, `exhaustive`, `gocognit`, `gocyclo`, `godot`, `gofumpt`, `goimports`, `gosec`, `misspell`, `nestif`, `revive`, and others.

Key settings:

| Setting | Value | Reason |
|---------|-------|--------|
| `gocyclo.min-complexity` | 15 | Flag overly complex functions. |
| `gocognit.min-complexity` | 20 | Flag hard-to-understand functions. |
| `dupl.threshold` | 150 | Detect duplicated code blocks. |
| `gosec.excludes` | `G304` | File-path-from-variable is expected for a scanner tool. |
| Test file exclusions | `goconst`, `dupl` | Allow repetition in test code. |

Run the linter with:

```bash
make lint
```

---

## Makefile targets

The Makefile is the primary build interface. The default target (`make` with no arguments) runs `ensure-tools`, `fmt`, `lint`, `cover`, `build`, and `test-integration` in sequence.

See [CLI Cheatsheet](cli-cheatsheet.md#makefile-targets) for the full target reference.

---

## mkdocs.yml and docs/

Documentation is built with [MkDocs Material](https://squidfunk.github.io/mkdocs-material/). The configuration lives in `mkdocs.yml` at the repository root.

| File/Directory | Purpose |
|----------------|---------|
| `mkdocs.yml` | Site name, navigation tree, theme settings. |
| `docs/` | Markdown source files organized by section. |
| `docker-compose.docs.yml` | Runs the MkDocs dev server on `localhost:8000` with live reload. |

To preview documentation locally:

```bash
docker compose -f docker-compose.docs.yml up
```

---

## testdata/

The `testdata/` directory contains fixtures used by automated tests and the `make demo` target.

| Path | Purpose |
|------|---------|
| `testdata/package-lock.json` | npm lockfile fixture with compromised entries. |
| `testdata/pnpm-lock.yaml` | pnpm lockfile fixture with compromised entries. |
| `testdata/rules/valid/*.json` | 18 schema-valid rule fixtures covering every field and conditional path. |
| `testdata/rules/invalid/*.json` | 18 schema-invalid rule fixtures for negative validation testing. |

The rule fixtures have hand-written Go struct equivalents in `pkg/rules/schema_fidelity_test.go` for bidirectional fidelity testing.

---

## Next Steps

- **Understand the rule schema** --> [Rule Format](../architecture/rule-format.md)
- **Set up your development environment** --> [Prerequisites](../getting-started/prerequisites.md)
- **See the design decisions** --> [Decision Log](decision-log/index.md)
