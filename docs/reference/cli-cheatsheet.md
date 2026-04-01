---
tags:
  - reference
  - cli
---

# CLI Cheatsheet

!!! tldr "TL;DR"

    Quick reference for every gouvernante flag, common command patterns, and
    Makefile targets. Print this page and pin it next to your terminal.

!!! tip "Who is this for?"

    **Audience:** Developers and operators who use gouvernante regularly.
    **Reading time:** ~3 minutes.

---

## Command-line flags

```text
gouvernante [flags]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-rules` | `string` | *(required)* | Directory containing rule JSON files. |
| `-dir` | `string` | `.` | Directory to scan for lockfiles. |
| `-lockfile` | `string` | | Path to a specific lockfile (overrides `-dir`). |
| `-host` | `bool` | `false` | Also check host filesystem for IOC artifacts. |
| `-output` | `string` | | Write report to file. Use `auto` for a timestamped filename. |
| `-json` | `bool` | `false` | Output findings as JSON instead of text. |

---

## Common patterns

### Scan a project directory

```bash
gouvernante -rules ./rules -dir ./my-project
```

### Scan a specific lockfile

```bash
gouvernante -rules ./rules -lockfile ./my-project/pnpm-lock.yaml
```

### JSON output for CI pipelines

```bash
gouvernante -rules ./rules -dir . -json
```

### Include host filesystem checks

```bash
gouvernante -rules ./rules -dir . -host
```

### Write report to a file

```bash
# Explicit filename
gouvernante -rules ./rules -dir . -output report.txt

# Auto-generated timestamped filename
gouvernante -rules ./rules -dir . -output auto
```

### Full scan with JSON output saved to file

```bash
gouvernante -rules ./rules -dir . -host -json -output auto
```

---

## Makefile targets

Run these from the repository root with `make <target>`.

| Target | Description |
|--------|-------------|
| `make all` | Format, lint, test, and build (default). Checks for required tools first. |
| `make build` | Cross-compile for all platforms (output in `dist/binaries/`). |
| `make test` | Run all tests with the race detector. |
| `make cover` | Run tests with coverage report (output in `dist/reports/`). |
| `make fmt` | Format code with `gofumpt` and `goimports`. |
| `make fmt-check` | Check formatting without modifying files. |
| `make vet` | Run `go vet` on all packages. |
| `make staticcheck` | Run `staticcheck` on all packages. |
| `make lint` | Run `golangci-lint` (includes `vet`). |
| `make setup` | Install all development tools (`gofumpt`, `goimports`, `staticcheck`, `golangci-lint`). |
| `make clean` | Remove all build artifacts (`dist/`, binaries, reports). |
| `make demo` | Build and run a demo scan against `testdata/`. |
| `make help` | Show all available targets. |

---

## Next Steps

- **Understand exit codes** --> [Exit Codes](exit-codes.md)
- **Set up CI/CD** --> [CI/CD Integration](../operations-guide/ci-cd-integration.md)
- **Run your first scan** --> [Quickstart](../getting-started/quickstart.md)
