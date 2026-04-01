---
title: Code Style
tags:
  - developer-guide
  - style
  - linting
  - formatting
  - quality
---

# Code Style

!!! tldr "TL;DR"
    Format with `gofumpt`, lint with `golangci-lint` (30+ linters), write
    Godoc on every exported symbol, wrap errors with `%w`, keep dependencies
    minimal, and run `make fmt` + `make lint` before every push.

!!! info "Who is this for?"
    All contributors. These conventions are enforced in CI and locally via
    `make all`.

## Formatting

### gofumpt

gouvernante uses [gofumpt](https://github.com/mvdan/gofumpt) -- a stricter
superset of `gofmt`. Key differences from plain `gofmt`:

- No empty lines at the start or end of function bodies.
- No empty lines around a lone statement in a block.
- Grouped `var`/`const` blocks are kept compact.

Apply formatting:

```bash
make fmt
```

Check formatting without modifying files (used in CI):

```bash
make fmt-check
```

### Import grouping

Use `goimports` ordering -- three groups separated by blank lines:

```go
import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"

	"gouvernante/pkg/lockfile"
	"gouvernante/pkg/rules"
)
```

1. **Standard library** imports.
2. **Third-party** imports (vetted external dependencies).
3. **Local module** imports.

`gofumpt` with the `module-path: gouvernante` setting in `.golangci.yml`
enforces this three-group layout automatically.

## Linting

### golangci-lint

The project runs [golangci-lint](https://golangci-lint.run/) with **30+
linters** enabled. Configuration lives in `.golangci.yml` at the repository
root.

```bash
make lint
```

Notable enabled linters include:

| Linter | Purpose |
|---|---|
| `staticcheck` | Advanced static analysis (SA/S/ST/QF checks). |
| `errcheck` | Ensures returned errors are handled. |
| `govet` | Reports suspicious constructs (`printf` args, struct tags, etc.). |
| `ineffassign` | Detects assignments to variables that are never read. |
| `unparam` | Flags unused function parameters. |
| `gocritic` | Opinionated style and performance checks. |
| `gosec` | Security-oriented checks (hardcoded credentials, weak crypto). |
| `misspell` | Catches common spelling mistakes in comments and strings. |
| `revive` | Configurable replacement for `golint`. |
| `bodyclose` | Ensures HTTP response bodies are closed. |

### staticcheck

`staticcheck` runs as part of `golangci-lint` but can also be invoked
standalone for more detailed output:

```bash
staticcheck ./...
```

Fix every finding -- the project does not maintain a baseline of accepted
warnings.

## Godoc Comments

Every exported symbol -- functions, types, constants, variables, and methods
-- must have a Godoc comment that starts with the symbol name:

```go
// PackageEntry represents a single resolved package from a lockfile.
type PackageEntry struct {
	Name    string
	Version string
}

// BuildPackageIndex constructs an index of rules keyed by package name for
// O(1) lookup during scanning.
func BuildPackageIndex(rules []Rule) PackageIndex {
	// ...
}
```

Rules:

- Start with the symbol name (`// BuildPackageIndex ...`).
- Use complete sentences.
- Document non-obvious parameters and return values.
- Unexported helpers benefit from comments too, but it is not enforced by the
  linter.

## Error Handling

### Wrap with %w

Always wrap errors so callers can use `errors.Is` / `errors.As`:

```go
if err != nil {
	return nil, fmt.Errorf("loading rule %s: %w", path, err)
}
```

### No panics

Never call `panic` in library code. Return an error instead. The only
acceptable `panic` is in `main()` or test helpers via `t.Fatal`.

### Sentinel errors

Define package-level sentinel errors for conditions callers need to branch on:

```go
// ErrUnsupportedLockfile indicates that no parser is registered for the
// detected lockfile format.
var ErrUnsupportedLockfile = errors.New("unsupported lockfile format")
```

Check them with `errors.Is`:

```go
if errors.Is(err, lockfile.ErrUnsupportedLockfile) {
	log.Printf("skipping: %v", err)
	return
}
```

## Dependency Policy

gouvernante keeps external dependencies minimal and vetted. The scanning and
matching engine uses only the Go standard library. Format parsers may use
vetted libraries where robustness outweighs purity (e.g., `goccy/go-yaml`
for pnpm lockfile parsing).

| Scope | Policy |
|-------|--------|
| Scanning & matching engine | Go standard library only |
| Format parsers | Vetted libraries allowed |
| Test infrastructure | Test-only dependencies allowed |
| CLI framework | `flag` package (standard library) |

Before adding a new dependency, open an issue to discuss scope and justification.
See the [Minimal Dependencies ADR](../reference/decision-log/minimal-dependencies.md)
for the full rationale and policy evolution.

## Makefile Targets

| Target | Command | Description |
|---|---|---|
| `make all` | `fmt` + `lint` + `cover` + `build` + `test-integration` | Full pre-push validation. |
| `make build` | Cross-compile all platforms | Binaries in `dist/binaries/`. |
| `make test` | `go test -race ./...` | Run tests with race detector. |
| `make cover` | `go test -race -coverprofile=... ./...` | Generate coverage report. |
| `make fmt` | `gofumpt -w .` | Format all Go files in place. |
| `make fmt-check` | `gofumpt -d .` (fail on diff) | Check formatting without writing. |
| `make lint` | `golangci-lint run ./...` | Run the full linter suite. |
| `make test-integration` | Docker build + run | End-to-end integration test with planted IOCs. |

Run `make all` before pushing. CI runs the same targets and will reject any
commit that fails.

## Self-Assessment Checklist

- [ ] `make fmt` produces no diff.
- [ ] `make lint` reports zero findings.
- [ ] Every exported symbol has a Godoc comment starting with its name.
- [ ] Errors are wrapped with `fmt.Errorf("context: %w", err)`.
- [ ] No `panic` calls outside of `main()` or test helpers.
- [ ] No unapproved external dependencies added to `go.mod`.
- [ ] `make all` passes.

## Next Steps

- [Testing](testing.md) -- test conventions that complement these style rules.
- [Adding Parsers](adding-parsers.md) -- apply these patterns when writing a
  new lockfile parser.
- [Writing Rules](writing-rules.md) -- JSON style conventions for rule files.
