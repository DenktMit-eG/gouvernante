---
title: Testing
tags:
  - developer-guide
  - testing
  - coverage
  - quality
---

# Testing

!!! tldr "TL;DR"

    Run `make test` for the full suite (race detector enabled by default),
    `make cover` for an HTML coverage report in `dist/reports/`, and follow
    table-driven test patterns with `t.TempDir()` for filesystem work.

!!! info "Who is this for?"

    Contributors who need to write, run, or debug tests for any gouvernante
    package.

## Running Tests

### Full suite

```bash
make test
```

This executes `go test -race ./...`, which runs every test in every package
with the **race detector always enabled**.

### Verbose output

```bash
go test -v -race ./...
```

### Specific package

```bash
go test -v -race ./pkg/lockfile/...
go test -v -race ./pkg/rules/...
go test -v -race ./pkg/scanner/...
go test -v -race ./pkg/heuristic/...
```

### Single test function

```bash
go test -v -race -run TestParsePnpmLock ./pkg/lockfile/...
```

## Coverage

Generate an HTML coverage report:

```bash
make cover
```

This produces `dist/reports/coverage.out` and `dist/reports/coverage.html`.

For a quick terminal summary:

```bash
go test -race -cover ./...
```

All library packages under `pkg/` must maintain **100% statement coverage**.
Use `go test -coverprofile` to verify before submitting changes.

## Test Patterns

### Table-driven tests

Every test file in the project follows the table-driven style:

```go
func TestSplitPackageKey(t *testing.T) {
	tests := []struct {
		key     string
		name    string
		version string
	}{
		{"axios@1.7.8", "axios", "1.7.8"},
		{"@scope/pkg@1.0.0", "@scope/pkg", "1.0.0"},
		{"axios/1.7.8", "axios", "1.7.8"},
		{"", "", ""},
	}

	for _, tt := range tests {
		name, version := splitPackageKey(tt.key)
		if name != tt.name || version != tt.version {
			t.Errorf("splitPackageKey(%q) = (%q, %q), want (%q, %q)",
				tt.key, name, version, tt.name, tt.version)
		}
	}
}
```

### t.TempDir() for filesystem work

Never write to the working directory. Use `t.TempDir()` for any test that
creates files:

```go
func TestDetectAndParse(t *testing.T) {
	dir := t.TempDir()

	content := `lockfileVersion: '9.0'

packages:
  axios@1.7.9:
    resolution: {integrity: sha512-fake}
`
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	results, err := lockfile.DetectAndParse(dir)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// assert on results...
}
```

### Fixture files

Static test inputs live under `testdata/` at the project root:

```
testdata/
├── package-lock.json             # npm lockfile fixture
├── pnpm-lock.yaml                # pnpm lockfile fixture
└── rules/
    ├── valid/                    # 18 schema-valid rule fixtures
    ├── invalid/                  # 18 schema-invalid rule fixtures
    ├── incidents/                # Sample incident rules (axios, shai-hulud-2)
    └── integration/              # Rules used by Dockerfile.integration
```

Tests reference fixtures with relative paths from their package directory
(e.g., `../../testdata/rules/valid/*.json` from `pkg/rules/`).

### Example tests (testable examples)

Example functions serve double duty: they appear in `go doc` output **and**
run as tests:

```go
func ExampleVersionSet_Matches() {
	vs := &rules.VersionSet{
		Versions: map[string]bool{
			"1.7.8": true,
			"1.7.9": true,
		},
	}

	fmt.Println(vs.Matches("1.7.8"))
	fmt.Println(vs.Matches("1.8.0"))

	// Output:
	// true
	// false
}
```

The `// Output:` comment is mandatory -- without it the function is not
executed as a test.

## Schema Fidelity Tests

The `pkg/rules/` package includes a comprehensive suite that proves the JSON
Schema and Go structs stay in sync:

| Test | What it proves |
|------|----------------|
| `TestValidFixtures_SchemaValidation` | All 18 valid fixtures pass the JSON Schema. |
| `TestInvalidFixtures_SchemaValidation` | All 18 invalid fixtures are correctly rejected. |
| `TestValidFixtures_GoUnmarshal` | Every valid fixture deserializes into Go structs. |
| `TestFixtures_ParseMatchesExpectedStruct` | Parsed JSON matches hand-written Go struct expectations (field-by-field). |
| `TestFixtures_SerializeMatchesOriginalJSON` | Serialized Go structs produce the same JSON as the original fixture. |
| `TestFixtures_ExpectedStructsPassValidation` | Every expected struct passes `Validate()`. |
| `TestGoStruct_FullRoundTrip` | Go struct -> JSON -> schema validate -> Go struct. |
| `TestIncidentRules_SchemaValidation` | Production incident rules pass schema + Go parsing. |

To add a new fixture, create the JSON in `testdata/rules/valid/`, add a
corresponding `fixture*()` function in `schema_fidelity_test.go` with the
hand-written expected struct, and add it to the `allFixtures()` list.

## Validation Tests

`pkg/rules/validate_test.go` tests the Go-side `Validate()` method against
every constraint in the JSON Schema: required fields, enum values, minLength,
minItems, conditional logic (file indicators need path or file_name, hashes
only on files, hash length per algorithm), and multi-error collection.

## Race Detector

The `-race` flag is **always** passed by `make test`. If a test is flaky only
with `-race`, the test is exposing a real bug. Do not disable the detector --
fix the concurrency issue.

## Self-Assessment Checklist

- [ ] All new code has corresponding tests.
- [ ] Tests are table-driven with descriptive sub-test names.
- [ ] Filesystem tests use `t.TempDir()`, not hard-coded paths.
- [ ] Fixture data lives under `testdata/`.
- [ ] Example tests have `// Output:` comments.
- [ ] `make test` passes locally (race detector enabled).
- [ ] `make cover` shows no unexpected coverage gaps.

## Next Steps

- [Code Style](code-style.md) -- formatting and linting rules that apply to
  test files too.
- [Adding Parsers](adding-parsers.md) -- testing expectations specific to
  lockfile parsers.
- [Writing Rules](writing-rules.md) -- rule authoring and validation.
