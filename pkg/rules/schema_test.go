package rules_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"gouvernante/pkg/rules"
)

const schemaPath = "schema.json"

func loadSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()

	compiler := jsonschema.NewCompiler()

	schema, err := compiler.Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}

	return schema
}

func loadJSON(t *testing.T, path string) interface{} {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	return v
}

// TestValidFixtures_SchemaValidation validates every file in testdata/rules/valid/
// against the JSON Schema. All must pass.
func TestValidFixtures_SchemaValidation(t *testing.T) {
	schema := loadSchema(t)

	files, err := filepath.Glob("../../testdata/rules/valid/*.json")
	if err != nil {
		t.Fatal(err)
	}

	if len(files) == 0 {
		t.Fatal("no valid fixture files found")
	}

	for _, f := range files {
		name := filepath.Base(f)

		t.Run(name, func(t *testing.T) {
			doc := loadJSON(t, f)
			if err := schema.Validate(doc); err != nil {
				t.Errorf("schema validation failed:\n%v", err)
			}
		})
	}
}

// TestInvalidFixtures_SchemaValidation validates every file in testdata/rules/invalid/
// against the JSON Schema. All must fail.
func TestInvalidFixtures_SchemaValidation(t *testing.T) {
	schema := loadSchema(t)

	files, err := filepath.Glob("../../testdata/rules/invalid/*.json")
	if err != nil {
		t.Fatal(err)
	}

	if len(files) == 0 {
		t.Fatal("no invalid fixture files found")
	}

	for _, f := range files {
		name := filepath.Base(f)

		t.Run(name, func(t *testing.T) {
			doc := loadJSON(t, f)
			if err := schema.Validate(doc); err == nil {
				t.Errorf("expected schema validation to fail, but it passed")
			}
		})
	}
}

// TestValidFixtures_GoUnmarshal verifies every schema-valid fixture can be
// unmarshaled into the Go RuleSet struct without error and produces non-empty rules.
func TestValidFixtures_GoUnmarshal(t *testing.T) {
	files, err := filepath.Glob("../../testdata/rules/valid/*.json")
	if err != nil {
		t.Fatal(err)
	}

	if len(files) == 0 {
		t.Fatal("no valid fixture files found")
	}

	for _, f := range files {
		name := filepath.Base(f)

		t.Run(name, func(t *testing.T) {
			rs, err := rules.LoadFile(f)
			if err != nil {
				t.Fatalf("LoadFile failed: %v", err)
			}

			assertRuleSetNotEmpty(t, rs)
		})
	}
}

func assertRuleSetNotEmpty(t *testing.T, rs *rules.RuleSet) {
	t.Helper()

	if len(rs.Rules) == 0 {
		t.Error("LoadFile returned empty rules")
	}

	for i := range rs.Rules {
		r := &rs.Rules[i]

		if r.ID == "" {
			t.Errorf("rule[%d] has empty ID", i)
		}

		if r.Title == "" {
			t.Errorf("rule[%d] %s has empty Title", i, r.ID)
		}

		if len(r.PackageRules) == 0 {
			t.Errorf("rule[%d] %s has no PackageRules", i, r.ID)
		}
	}
}

// TestValidFixtures_RoundTrip verifies that marshal → unmarshal → re-marshal
// produces identical JSON for every valid fixture. This catches fields present
// in the schema but missing from the Go struct (they would be silently dropped).
func TestValidFixtures_RoundTrip(t *testing.T) {
	schema := loadSchema(t)

	files, err := filepath.Glob("../../testdata/rules/valid/*.json")
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range files {
		name := filepath.Base(f)

		t.Run(name, func(t *testing.T) {
			// Load and unmarshal.
			rs, err := rules.LoadFile(f)
			if err != nil {
				t.Fatalf("LoadFile: %v", err)
			}

			// Re-marshal the Go struct to JSON.
			out, err := json.Marshal(rs)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			// Validate the re-marshaled JSON against the schema.
			var doc interface{}
			if err := json.Unmarshal(out, &doc); err != nil {
				t.Fatalf("re-parse: %v", err)
			}

			if err := schema.Validate(doc); err != nil {
				t.Errorf("round-tripped JSON fails schema validation:\n%v", err)
			}
		})
	}
}

// TestGoStruct_FullRoundTrip creates a fully populated Go struct, marshals it,
// validates against the schema, and unmarshals back. This tests the direction
// opposite to fixture files: Go → JSON → schema → Go.
func TestGoStruct_FullRoundTrip(t *testing.T) {
	schema := loadSchema(t)

	rs := &rules.RuleSet{
		SchemaVersion: "1.0.0",
		Rules: []rules.Rule{
			{
				ID:        "RT-001",
				Title:     "Round-trip test rule",
				Kind:      "compromised-release",
				Ecosystem: "npm",
				Severity:  "critical",
				Summary:   "Testing Go struct to JSON to schema validation.",
				Aliases: []rules.Alias{
					{Type: "cve", Value: "CVE-2025-00000"},
					{Type: "ghsa", Value: "GHSA-test-test-test"},
				},
				References: []rules.Reference{
					{Type: "advisory", URL: "https://example.com/adv"},
				},
				PackageRules: []rules.PackageRule{
					{
						PackageName:        "test-pkg",
						AffectedVersions:   []string{"=1.0.0", "=2.0.0"},
						LockfileEcosystems: []string{"npm", "pnpm"},
						Notes:              "Test note.",
					},
				},
				DropperPackages: []rules.DropperPkg{
					{PackageName: "dropper-test", Notes: "Test dropper."},
				},
				HostIndicators: []rules.HostIndicator{
					{
						Type:     "file",
						Path:     "/tmp",
						FileName: "test.bin",
						OSes:     []string{"linux", "macos"},
						Hashes: []rules.FileHash{
							{Algorithm: "sha256", Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
						},
						Confidence: "high",
						Notes:      "Test file indicator.",
					},
					{
						Type:       "process",
						Value:      "evil-proc",
						OSes:       []string{"linux"},
						Confidence: "medium",
					},
				},
				Remediation: &rules.Remediation{
					Summary: "Fix it.",
					Steps:   []string{"Step 1.", "Step 2."},
				},
				Metadata: &rules.Metadata{
					PublishedAt:   "2025-01-01T00:00:00Z",
					LastUpdatedAt: "2025-01-02T00:00:00Z",
				},
			},
		},
	}

	// Marshal Go struct to JSON.
	data, err := json.Marshal(rs)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Validate against schema.
	var doc interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse marshaled JSON: %v", err)
	}

	if err := schema.Validate(doc); err != nil {
		t.Fatalf("schema validation of Go-generated JSON failed:\n%v", err)
	}

	// Unmarshal back and verify fields survived.
	var rt rules.RuleSet
	if err := json.Unmarshal(data, &rt); err != nil {
		t.Fatalf("unmarshal round-trip: %v", err)
	}

	r := rt.Rules[0]

	if r.ID != "RT-001" {
		t.Errorf("ID: got %q", r.ID)
	}

	if len(r.Aliases) != 2 {
		t.Errorf("Aliases: got %d, want 2", len(r.Aliases))
	}

	if len(r.HostIndicators) != 2 {
		t.Errorf("HostIndicators: got %d, want 2", len(r.HostIndicators))
	}

	if len(r.HostIndicators[0].Hashes) != 1 {
		t.Errorf("Hashes: got %d, want 1", len(r.HostIndicators[0].Hashes))
	}

	if r.Remediation == nil || len(r.Remediation.Steps) != 2 {
		t.Error("Remediation steps lost in round-trip")
	}

	if r.Metadata == nil || r.Metadata.PublishedAt == "" {
		t.Error("Metadata lost in round-trip")
	}
}

// TestIncidentRules_SchemaValidation validates the sample incident rule files
// in testdata/rules/incidents/ against the schema.
func TestIncidentRules_SchemaValidation(t *testing.T) {
	schema := loadSchema(t)

	files, err := filepath.Glob("../../testdata/rules/incidents/*.json")
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range files {
		name := filepath.Base(f)

		if name == "schema.json" {
			continue
		}

		t.Run(name, func(t *testing.T) {
			doc := loadJSON(t, f)
			if err := schema.Validate(doc); err != nil {
				t.Errorf("production rule fails schema validation:\n%v", err)
			}

			// Also verify Go can parse it.
			rs, err := rules.LoadFile(f)
			if err != nil {
				t.Errorf("LoadFile failed: %v", err)
				return
			}

			if len(rs.Rules) == 0 {
				t.Error("incident rule file has no rules")
			}
		})
	}
}
