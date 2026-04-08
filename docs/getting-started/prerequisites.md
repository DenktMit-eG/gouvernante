---
tags:
  - getting-started
  - setup
---

# Prerequisites

!!! tldr "TL;DR"

    To **use** gouvernante you need the binary and a rules directory. Nothing else.
    To **build from source** or **contribute**, you additionally need Go and dev tooling.

!!! tip "Who is this for?"

    **Everyone.** Pick the section that matches your situation.

---

## Using gouvernante

You need exactly two things:

1. **The `gouvernante` binary** — a single static executable with no runtime dependencies.
2. **A rules directory** — one or more JSON rule files describing known incidents.

That's it. No Go, no Node.js, no package manager, no runtime.

### Get the binary

Download a prebuilt binary from your team's artifact store or build it yourself (see below).

### Get the rules

Clone or copy the rules directory. At minimum you need one `.json` rule file following the [Rule Format](../architecture/rule-format.md).

### Verify it works

```bash
gouvernante -rules ./rules -dir /path/to/your/project
```

You should see a scan report. If the directory has no lockfiles, you'll see a warning — that's expected.

---

## Building from source

Only needed if you don't have a prebuilt binary or want to contribute.

### Required tools

| Tool | Purpose |
|------|---------|
| `go` (1.22+) | Build the binary |
| `make` | Build automation |

```bash
# macOS
brew install go

# Ubuntu / Debian
sudo apt install golang-go
```

### Build

```bash
git clone <repository-url>
cd gouvernante
make build
```

This produces platform-specific binaries in `dist/binaries/` (e.g. `gouvernante-linux-amd64`). Copy the binary for your platform anywhere on your `PATH`.

---

## Contributing (development setup)

Only needed if you're modifying the scanner itself.

### Additional tools

| Tool | Purpose |
|------|---------|
| `gofumpt` | Strict code formatting |
| `goimports` | Import organization |
| `staticcheck` | Static analysis |
| `golangci-lint` | Meta-linter with 34 checks |

```bash
go install mvdan.cc/gofumpt@latest
go install golang.org/x/tools/cmd/goimports@latest
go install honnef.co/go/tools/cmd/staticcheck@latest
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
```

### Verify the dev setup

```bash
make all
```

This runs formatting, linting, tests, and builds the binary. If it passes, you're ready to contribute.

---

## Self-Assessment

- [ ] Can you run `gouvernante -rules ./rules -dir .` and get a report?
- [ ] (Contributors only) Does `make all` pass?

## Next Steps

- **Get started** → [Quickstart](quickstart.md)
- **Want to contribute?** Read [Code Style & Linting](../developer-guide/code-style.md)
