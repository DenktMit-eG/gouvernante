---
title: Adding Lockfile Parsers
tags:
  - developer-guide
  - lockfile
  - parser
  - contributing
---

# Adding Lockfile Parsers

!!! tldr "TL;DR"
    Create a `pkg/lockfile/<format>.go` file that exports a `Parse<Format>` function
    returning `[]PackageEntry`, register it in `detect.go`, add tests with fixture
    data, and run `make all` to validate.

!!! info "Who is this for?"
    Contributors who want gouvernante to support a new package-manager lockfile
    format (e.g. `bun.lock`, `deno.lock`, Gradle lockfiles).

## Overview

gouvernante discovers which lockfile format is present and delegates to
format-specific parsers in `pkg/lockfile/`. Each parser is a single Go file
that converts the on-disk format into a flat slice of `PackageEntry` values the
scanner can reason about.

## Step-by-Step

### 1. Create the parser file

Add `pkg/lockfile/<format>.go` (e.g. `bun.go`).

The file must export **exactly one** public function with this signature:

```go
// Parse<Format> reads a <format> lockfile at path and returns every resolved
// package entry.
func Parse<Format>(path string) ([]PackageEntry, error)
```

Concrete example for Bun:

```go
package lockfile

import (
	"encoding/json"
	"fmt"
	"os"
)

// ParseBun reads a bun.lock file at path and returns every resolved package
// entry.
func ParseBun(path string) ([]PackageEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading bun lockfile: %w", err)
	}

	// bun.lock is a JSON-like format; parse it here.
	var raw bunLockfile
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing bun lockfile: %w", err)
	}

	entries := make([]PackageEntry, 0, len(raw.Packages))
	for name, meta := range raw.Packages {
		entries = append(entries, PackageEntry{
			Name:    name,
			Version: meta.Version,
		})
	}
	return entries, nil
}

// bunLockfile is the on-disk representation of bun.lock.
type bunLockfile struct {
	Packages map[string]bunPackageMeta `json:"packages"`
}

type bunPackageMeta struct {
	Version string `json:"version"`
}
```

Key rules:

- **For JSON-based formats:** use `encoding/json` from the standard library.
- **For YAML-based formats:** use `goccy/go-yaml` (already a project dependency).
- **For text-based formats:** use `bufio.Scanner` with line-by-line parsing.
- Wrap errors with `%w` so callers can inspect them.
- Keep unexported helper types in the same file.

### 2. Register the parser in detect.go

Open `pkg/lockfile/detect.go` and add an entry to the detection table inside
`DetectAndParse()` so that auto-detection picks up the new format:

```go
lockfiles := []struct {
	name   string
	parser func(string) ([]PackageEntry, error)
}{
	{"pnpm-lock.yaml", ParsePnpmLock},
	{"package-lock.json", ParsePackageLockJSON},
	{"yarn.lock", ParseYarnLock},
	{"bun.lock", ParseBun}, // <-- add this line
}
```

Also add the corresponding case to the `ParseFile()` switch statement in the
same file:

```go
case "bun.lock":
	parser = ParseBun
```

The scanner walks the table top-to-bottom and uses the first match, so order
matters only when a project contains multiple lockfiles.

### 3. Write tests

Create `pkg/lockfile/<format>_test.go` (e.g. `bun_test.go`).

Place fixture files under `pkg/lockfile/testdata/`:

```
pkg/lockfile/testdata/bun/
    basic.lock          # minimal happy-path fixture
    empty.lock          # edge case: zero packages
    malformed.lock      # edge case: invalid JSON
```

Use table-driven tests:

```go
package lockfile_test

import (
	"path/filepath"
	"testing"

	"gouvernante/pkg/lockfile"
)

func TestParseBun(t *testing.T) {
	tests := []struct {
		name      string
		fixture   string
		wantCount int
		wantErr   bool
	}{
		{"basic", "testdata/bun/basic.lock", 3, false},
		{"empty", "testdata/bun/empty.lock", 0, false},
		{"malformed", "testdata/bun/malformed.lock", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := lockfile.ParseBun(filepath.Join(".", tt.fixture))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseBun() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(entries) != tt.wantCount {
				t.Errorf("got %d entries, want %d", len(entries), tt.wantCount)
			}
		})
	}
}
```

### 4. Run the full pipeline

```bash
make all
```

This runs `fmt-check`, `lint`, `test` (with the race detector), and `build` in
sequence. Every check must pass before the parser is considered ready.

## Common Pitfalls

| Mistake | Fix |
|---|---|
| Returning `nil` instead of an empty slice | Always return `make([]PackageEntry, 0)` for zero-package files. |
| Forgetting to close a file handle | Prefer `os.ReadFile` for small-to-medium lockfiles. |
| Bare `errors.New` without context | Wrap with `fmt.Errorf("parsing <format>: %w", err)`. |
| Adding an unapproved external library | Use the standard library or `goccy/go-yaml` (already available). For anything else, open an issue first. |

## Self-Assessment Checklist

- [ ] Parser file follows the `Parse<Format>(path string) ([]PackageEntry, error)` signature.
- [ ] Parser is registered in `detect.go`.
- [ ] Tests cover happy path, empty input, and malformed input.
- [ ] Fixture data is committed under `pkg/lockfile/testdata/`.
- [ ] `make all` passes with zero warnings.
- [ ] Godoc comment on the exported function.
- [ ] Errors are wrapped with `%w`.

## Next Steps

- [Writing Rules](writing-rules.md) -- define detection rules that the scanner
  matches against parsed lockfile entries.
- [Testing](testing.md) -- deeper dive into the project's testing conventions.
- [Code Style](code-style.md) -- formatting and linting expectations.
