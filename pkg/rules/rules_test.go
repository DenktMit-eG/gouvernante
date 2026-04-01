package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRuleFile(t *testing.T, dir, name, content string) {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const validRuleJSON = `{
  "schema_version": "1.0.0",
  "rules": [
    {
      "id": "SSC-2025-001",
      "title": "Test rule",
      "kind": "compromised-release",
      "ecosystem": "npm",
      "severity": "critical",
      "package_rules": [
        {
          "package_name": "axios",
          "affected_versions": ["=1.7.8", "=1.7.9"]
        }
      ],
      "dropper_packages": [
        { "package_name": "evil-pkg" }
      ]
    }
  ]
}`

func TestLoadFile_Valid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.json")
	if err := os.WriteFile(path, []byte(validRuleJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	rs, err := LoadFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rs.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rs.Rules))
	}

	r := rs.Rules[0]

	if r.ID != "SSC-2025-001" {
		t.Errorf("id: got %q, want SSC-2025-001", r.ID)
	}

	if r.Severity != "critical" {
		t.Errorf("severity: got %q, want critical", r.Severity)
	}

	if len(r.PackageRules) != 1 {
		t.Fatalf("expected 1 package rule, got %d", len(r.PackageRules))
	}

	if r.PackageRules[0].PackageName != "axios" {
		t.Errorf("package_name: got %q, want axios", r.PackageRules[0].PackageName)
	}
}

func TestLoadFile_MissingID(t *testing.T) {
	content := `{"schema_version": "1.0.0", "rules": [{"title": "No ID", "kind": "vulnerability", "ecosystem": "npm", "severity": "low", "package_rules": [{"package_name": "x", "affected_versions": ["*"]}]}]}`
	path := filepath.Join(t.TempDir(), "noid.json")

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error for missing ID")
	}
}

func TestLoadFile_InvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{invalid"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadFile_FileNotFound(t *testing.T) {
	_, err := LoadFile("/nonexistent/rule.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "rule1.json", validRuleJSON)
	writeRuleFile(t, dir, "rule2.json", `{
  "schema_version": "1.0.0",
  "rules": [
    {
      "id": "SSC-2025-002",
      "title": "Second rule",
      "kind": "malicious-package",
      "ecosystem": "npm",
      "severity": "high",
      "package_rules": [
        { "package_name": "evil", "affected_versions": ["*"] }
      ]
    }
  ]
}`)

	rules, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}
}

func TestLoadDir_Empty(t *testing.T) {
	dir := t.TempDir()

	rules, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

func TestBuildPackageIndex_ExactVersions(t *testing.T) {
	ruleList := []Rule{
		{
			ID:       "R1",
			Title:    "Test",
			Severity: "critical",
			PackageRules: []PackageRule{
				{
					PackageName:      "axios",
					AffectedVersions: []string{"=1.7.8", "=1.7.9"},
				},
			},
		},
	}

	idx := BuildPackageIndex(ruleList)

	vs := idx.Packages["axios"]
	if vs == nil {
		t.Fatal("expected axios in index")
	}

	if !vs.Matches("1.7.8") {
		t.Error("expected 1.7.8 to match")
	}

	if !vs.Matches("1.7.9") {
		t.Error("expected 1.7.9 to match")
	}

	if vs.Matches("1.7.7") {
		t.Error("expected 1.7.7 to NOT match")
	}
}

func TestBuildPackageIndex_BareVersions(t *testing.T) {
	ruleList := []Rule{
		{
			ID:       "R1",
			Title:    "Test",
			Severity: "high",
			PackageRules: []PackageRule{
				{
					PackageName:      "lodash",
					AffectedVersions: []string{"4.17.20"},
				},
			},
		},
	}

	idx := BuildPackageIndex(ruleList)

	vs := idx.Packages["lodash"]
	if vs == nil {
		t.Fatal("expected lodash in index")
	}

	if !vs.Matches("4.17.20") {
		t.Error("expected 4.17.20 to match")
	}
}

func TestBuildPackageIndex_Wildcard(t *testing.T) {
	ruleList := []Rule{
		{
			ID:       "R1",
			Title:    "Test",
			Severity: "critical",
			PackageRules: []PackageRule{
				{
					PackageName:      "evil-pkg",
					AffectedVersions: []string{"*"},
				},
			},
		},
	}

	idx := BuildPackageIndex(ruleList)

	vs := idx.Packages["evil-pkg"]
	if vs == nil {
		t.Fatal("expected evil-pkg in index")
	}

	if !vs.Matches("0.0.1") {
		t.Error("wildcard should match any version")
	}

	if !vs.Matches("99.99.99") {
		t.Error("wildcard should match any version")
	}
}

func TestBuildPackageIndex_DropperPackages(t *testing.T) {
	ruleList := []Rule{
		{
			ID:       "R1",
			Title:    "Test",
			Severity: "critical",
			DropperPackages: []DropperPkg{
				{PackageName: "plain-crypto-js"},
			},
			PackageRules: []PackageRule{
				{PackageName: "axios", AffectedVersions: []string{"=1.7.8"}},
			},
		},
	}

	idx := BuildPackageIndex(ruleList)

	dropper := idx.Packages["plain-crypto-js"]
	if dropper == nil {
		t.Fatal("expected plain-crypto-js in index")
	}

	if !dropper.AnyVersion {
		t.Error("dropper packages should match any version")
	}

	if !dropper.Matches("1.0.0") {
		t.Error("dropper should match any version")
	}
}

func TestVersionSet_Matches(t *testing.T) {
	tests := []struct {
		name    string
		vs      VersionSet
		version string
		want    bool
	}{
		{
			name:    "exact match",
			vs:      VersionSet{Versions: map[string]bool{"1.0.0": true}},
			version: "1.0.0",
			want:    true,
		},
		{
			name:    "no match",
			vs:      VersionSet{Versions: map[string]bool{"1.0.0": true}},
			version: "2.0.0",
			want:    false,
		},
		{
			name:    "any version",
			vs:      VersionSet{AnyVersion: true},
			version: "anything",
			want:    true,
		},
		{
			name:    "empty set",
			vs:      VersionSet{Versions: map[string]bool{}},
			version: "1.0.0",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.vs.Matches(tt.version)
			if got != tt.want {
				t.Errorf("Matches(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}
