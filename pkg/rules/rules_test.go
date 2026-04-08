package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Masterminds/semver/v3"
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

// firstVS returns the first VersionSet for a package in the index, or nil if none.
func firstVS(idx *PackageIndex, pkgName string) *VersionSet {
	vsList := idx.Packages[pkgName]
	if len(vsList) == 0 {
		return nil
	}

	return vsList[0]
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

	vs := firstVS(idx, "axios")
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

	vs := firstVS(idx, "lodash")
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

	vs := firstVS(idx, "evil-pkg")
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

	dropper := firstVS(idx, "plain-crypto-js")
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

// Matches with semver constraints.

func TestMatches_SemverConstraintMatch(t *testing.T) {
	// Build an index with a range constraint >=1.0.0 <2.0.0
	ruleList := []Rule{
		{
			ID: "R-RANGE", Title: "Range", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "rangepkg", AffectedVersions: []string{">=1.0.0 <2.0.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "rangepkg")
	if vs == nil {
		t.Fatal("expected rangepkg in index")
	}

	if !vs.Matches("1.5.0") {
		t.Error("expected 1.5.0 to match constraint >=1.0.0 <2.0.0")
	}
}

func TestMatches_SemverConstraintNoMatch(t *testing.T) {
	ruleList := []Rule{
		{
			ID: "R-RANGE2", Title: "Range2", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "rangepkg2", AffectedVersions: []string{">=1.0.0 <2.0.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "rangepkg2")
	if vs == nil {
		t.Fatal("expected rangepkg2 in index")
	}

	if vs.Matches("2.5.0") {
		t.Error("expected 2.5.0 to NOT match constraint >=1.0.0 <2.0.0")
	}
}

func TestMatches_InvalidVersionString(t *testing.T) {
	ruleList := []Rule{
		{
			ID: "R-RANGE3", Title: "Range3", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "rangepkg3", AffectedVersions: []string{">=1.0.0 <2.0.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "rangepkg3")
	if vs == nil {
		t.Fatal("expected rangepkg3 in index")
	}

	// Non-semver version string should return false gracefully
	if vs.Matches("not-a-version") {
		t.Error("expected non-semver version to NOT match")
	}
}

func TestMatches_NoConstraintsNoExactMatch(t *testing.T) {
	vs := &VersionSet{
		Versions: map[string]bool{"1.0.0": true},
	}

	if vs.Matches("2.0.0") {
		t.Error("expected no match when no constraints and no exact match")
	}
}

func TestMatches_ExactMatchWinsOverConstraints(t *testing.T) {
	// Build index with both exact versions and a range constraint
	ruleList := []Rule{
		{
			ID: "R-BOTH", Title: "Both", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "bothpkg", AffectedVersions: []string{"1.5.0", ">=2.0.0 <3.0.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "bothpkg")
	if vs == nil {
		t.Fatal("expected bothpkg in index")
	}

	// Exact match path
	if !vs.Matches("1.5.0") {
		t.Error("expected exact match for 1.5.0")
	}

	// Constraint match path
	if !vs.Matches("2.5.0") {
		t.Error("expected constraint match for 2.5.0")
	}

	// Neither
	if vs.Matches("3.5.0") {
		t.Error("expected no match for 3.5.0")
	}
}

// RangeCoversVersion tests.

func TestRangeCoversVersion_Covers(t *testing.T) {
	ruleList := []Rule{
		{
			ID: "R-RCV1", Title: "RCV1", Severity: "critical",
			PackageRules: []PackageRule{
				{PackageName: "rcvpkg", AffectedVersions: []string{"1.14.1"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "rcvpkg")
	if vs == nil {
		t.Fatal("expected rcvpkg in index")
	}

	covers, matched := vs.RangeCoversVersion("^1.14.0")
	if !covers {
		t.Error("expected ^1.14.0 to cover 1.14.1")
	}
	if matched != "1.14.1" {
		t.Errorf("expected matched version 1.14.1, got %q", matched)
	}
}

func TestRangeCoversVersion_DoesNotCover(t *testing.T) {
	ruleList := []Rule{
		{
			ID: "R-RCV2", Title: "RCV2", Severity: "critical",
			PackageRules: []PackageRule{
				{PackageName: "rcvpkg2", AffectedVersions: []string{"1.14.1"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "rcvpkg2")
	if vs == nil {
		t.Fatal("expected rcvpkg2 in index")
	}

	covers, matched := vs.RangeCoversVersion("^2.0.0")
	if covers {
		t.Error("expected ^2.0.0 to NOT cover 1.14.1")
	}
	if matched != "" {
		t.Errorf("expected empty matched version, got %q", matched)
	}
}

func TestRangeCoversVersion_AnyVersion(t *testing.T) {
	vs := &VersionSet{
		AnyVersion: true,
		Versions:   map[string]bool{},
	}

	covers, matched := vs.RangeCoversVersion("^1.0.0")
	if !covers {
		t.Error("expected AnyVersion to cover any range")
	}
	if matched != "*" {
		t.Errorf("expected matched version *, got %q", matched)
	}
}

func TestRangeCoversVersion_InvalidRangeExpression(t *testing.T) {
	vs := &VersionSet{
		Versions: map[string]bool{"1.0.0": true},
	}

	covers, matched := vs.RangeCoversVersion("not-a-range[[[")
	if covers {
		t.Error("expected invalid range to return false")
	}
	if matched != "" {
		t.Errorf("expected empty matched version, got %q", matched)
	}
}

func TestRangeCoversVersion_ConstraintOverlap(t *testing.T) {
	// Rule uses a range constraint, dep uses a caret range — they overlap.
	ruleList := []Rule{
		{
			ID: "R-CON", Title: "Constraint", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "axios", AffectedVersions: []string{">=1.0.0 <2.0.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "axios")
	if vs == nil {
		t.Fatal("expected axios in index")
	}

	covers, matched := vs.RangeCoversVersion("^1.5.0")
	if !covers {
		t.Error("expected ^1.5.0 to overlap with >=1.0.0 <2.0.0")
	}
	if matched == "" {
		t.Error("expected non-empty matched description")
	}
}

func TestRangeCoversVersion_ConstraintNoOverlap(t *testing.T) {
	// ^3.0.0 = [3.0.0, 4.0.0) does not overlap with [1.0.0, 2.0.0).
	// Lower bound 3.0.0 is not in [1.0.0, 2.0.0), and 1.0.0 is not in [3.0.0, 4.0.0).
	ruleList := []Rule{
		{
			ID: "R-CON2", Title: "Constraint2", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "axios", AffectedVersions: []string{">=1.0.0 <2.0.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "axios")
	if vs == nil {
		t.Fatal("expected axios in index")
	}

	covers, _ := vs.RangeCoversVersion("^3.0.0")
	if covers {
		t.Error("expected ^3.0.0 to NOT overlap with >=1.0.0 <2.0.0")
	}
}

func TestRangeCoversVersion_ConstraintOverlapViaRuleLowerBound(t *testing.T) {
	// dep ^1.0.0 = [1.0.0, 2.0.0), rule >=1.8.0 <1.9.0 = [1.8.0, 1.9.0).
	// dep lower bound 1.0.0 is NOT in [1.8.0, 1.9.0) — direction 1 misses.
	// rule lower bound 1.8.0 IS in [1.0.0, 2.0.0) — direction 2 catches it.
	ruleList := []Rule{
		{
			ID: "R-CON3", Title: "Constraint3", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "pkg", AffectedVersions: []string{">=1.8.0 <1.9.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "pkg")
	if vs == nil {
		t.Fatal("expected pkg in index")
	}

	covers, _ := vs.RangeCoversVersion("^1.0.0")
	if !covers {
		t.Error("expected ^1.0.0 to overlap with >=1.8.0 <1.9.0 (rule lower bound 1.8.0 is in dep range)")
	}
}

func TestRangeCoversVersion_ExclusiveLowerBound(t *testing.T) {
	// Both sides use strict >: rule >1.5.0 <2.0.0, dep >1.5.0 <1.6.0.
	// They clearly overlap (e.g., 1.5.1 satisfies both), but the raw
	// lower bound 1.5.0 would fail both Check() calls without the patch bump.
	ruleList := []Rule{
		{
			ID: "R-EX", Title: "Exclusive", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "pkg", AffectedVersions: []string{">1.5.0 <2.0.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "pkg")
	if vs == nil {
		t.Fatal("expected pkg in index")
	}

	covers, _ := vs.RangeCoversVersion(">1.5.0 <1.6.0")
	if !covers {
		t.Error("expected >1.5.0 <1.6.0 to overlap with >1.5.0 <2.0.0")
	}
}

func TestRangeCoversVersion_UpperBoundOnlyNoFalsePositive(t *testing.T) {
	// dep <1.0.0 has no lower bound. Rule >=1.0.0 <2.0.0 starts at 1.0.0.
	// No overlap — <1.0.0 is entirely below >=1.0.0.
	ruleList := []Rule{
		{
			ID: "R-UB", Title: "UpperBound", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "pkg", AffectedVersions: []string{">=1.0.0 <2.0.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "pkg")
	if vs == nil {
		t.Fatal("expected pkg in index")
	}

	covers, _ := vs.RangeCoversVersion("<1.0.0")
	if covers {
		t.Error("expected <1.0.0 to NOT overlap with >=1.0.0 <2.0.0")
	}
}

func TestRangeCoversVersion_BothUpperBoundOnly(t *testing.T) {
	// dep <1.0.0 and rule <2.0.0 — they overlap (everything below 1.0.0).
	ruleList := []Rule{
		{
			ID: "R-UB2", Title: "UpperBound2", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "pkg", AffectedVersions: []string{"<2.0.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "pkg")
	if vs == nil {
		t.Fatal("expected pkg in index")
	}

	covers, _ := vs.RangeCoversVersion("<1.0.0")
	if !covers {
		t.Error("expected <1.0.0 to overlap with <2.0.0")
	}
}

func TestRangeCoversVersion_UpperBoundOverlap(t *testing.T) {
	// dep <2.0.0 overlaps with rule >=0.5.0 <0.9.0 (rule is entirely inside dep).
	ruleList := []Rule{
		{
			ID: "R-UB3", Title: "UpperBound3", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "pkg", AffectedVersions: []string{">=0.5.0 <0.9.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "pkg")
	if vs == nil {
		t.Fatal("expected pkg in index")
	}

	covers, _ := vs.RangeCoversVersion("<2.0.0")
	if !covers {
		t.Error("expected <2.0.0 to overlap with >=0.5.0 <0.9.0")
	}
}

func TestRangeCoversVersion_DisjunctiveRuleOverlap(t *testing.T) {
	// Rule: <1.0.0 || >=2.5.0 <2.6.0 — the second branch overlaps with dep >=2.0.0 <3.0.0.
	ruleList := []Rule{
		{
			ID: "R-DISJ", Title: "Disjunctive", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "pkg", AffectedVersions: []string{"<1.0.0 || >=2.5.0 <2.6.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "pkg")
	if vs == nil {
		t.Fatal("expected pkg in index")
	}

	covers, _ := vs.RangeCoversVersion(">=2.0.0 <3.0.0")
	if !covers {
		t.Error("expected >=2.0.0 <3.0.0 to overlap with <1.0.0 || >=2.5.0 <2.6.0 via second branch")
	}
}

func TestRangeCoversVersion_DisjunctiveNoOverlap(t *testing.T) {
	// Rule: <1.0.0 || >=5.0.0 — neither branch overlaps with dep >=2.0.0 <3.0.0.
	ruleList := []Rule{
		{
			ID: "R-DISJ2", Title: "Disjunctive2", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "pkg", AffectedVersions: []string{"<1.0.0 || >=5.0.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "pkg")
	if vs == nil {
		t.Fatal("expected pkg in index")
	}

	covers, _ := vs.RangeCoversVersion(">=2.0.0 <3.0.0")
	if covers {
		t.Error("expected >=2.0.0 <3.0.0 to NOT overlap with <1.0.0 || >=5.0.0")
	}
}

func TestRangeCoversVersion_NonSemverInVersionsMap(t *testing.T) {
	vs := &VersionSet{
		Versions: map[string]bool{
			"not-semver": true,
			"also-bad":   true,
		},
	}

	covers, matched := vs.RangeCoversVersion("^1.0.0")
	if covers {
		t.Error("expected non-semver versions to be skipped, returning false")
	}
	if matched != "" {
		t.Errorf("expected empty matched version, got %q", matched)
	}
}

// indexPackageRules tests.

func TestIndexPackageRules_RangeExpression(t *testing.T) {
	ruleList := []Rule{
		{
			ID: "R-IDX1", Title: "Idx1", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "idxpkg", AffectedVersions: []string{">=1.0.0 <2.0.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "idxpkg")
	if vs == nil {
		t.Fatal("expected idxpkg in index")
	}

	if len(vs.Constraints) != 1 {
		t.Fatalf("expected 1 constraint, got %d", len(vs.Constraints))
	}

	// Should not be stored as exact match
	if len(vs.Versions) != 0 {
		t.Errorf("expected no exact versions, got %d", len(vs.Versions))
	}
}

func TestIndexPackageRules_UnparseableVersion(t *testing.T) {
	ruleList := []Rule{
		{
			ID: "R-IDX2", Title: "Idx2", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "idxpkg2", AffectedVersions: []string{"this-is-not-valid"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "idxpkg2")
	if vs == nil {
		t.Fatal("expected idxpkg2 in index")
	}

	// Should be stored as exact match fallback
	if !vs.Versions["this-is-not-valid"] {
		t.Error("expected unparseable string to be stored as exact match")
	}

	if len(vs.Constraints) != 0 {
		t.Errorf("expected no constraints, got %d", len(vs.Constraints))
	}
}

func TestIndexPackageRules_MixedVersionsAndRanges(t *testing.T) {
	ruleList := []Rule{
		{
			ID: "R-IDX3", Title: "Idx3", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "mixpkg", AffectedVersions: []string{"1.0.0", ">=2.0.0 <3.0.0", "garbage!!!"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "mixpkg")
	if vs == nil {
		t.Fatal("expected mixpkg in index")
	}

	// "1.0.0" -> exact version
	if !vs.Versions["1.0.0"] {
		t.Error("expected 1.0.0 as exact version")
	}

	// ">=2.0.0 <3.0.0" -> constraint
	if len(vs.Constraints) != 1 {
		t.Fatalf("expected 1 constraint, got %d", len(vs.Constraints))
	}

	// "garbage!!!" -> exact match fallback
	if !vs.Versions["garbage!!!"] {
		t.Error("expected garbage!!! as exact match fallback")
	}
}

func TestBuildPackageIndex_MultiRuleSamePackage(t *testing.T) {
	ruleList := []Rule{
		{
			ID: "R1", Title: "First rule", Severity: "critical",
			PackageRules: []PackageRule{
				{PackageName: "axios", AffectedVersions: []string{"1.7.8"}},
			},
		},
		{
			ID: "R2", Title: "Second rule", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "axios", AffectedVersions: []string{"2.0.0"}},
			},
		},
	}

	idx := BuildPackageIndex(ruleList)

	vsList := idx.Packages["axios"]
	if len(vsList) != 2 {
		t.Fatalf("expected 2 VersionSets for axios, got %d", len(vsList))
	}

	// Each VersionSet should have its own rule identity.
	ids := map[string]bool{}
	for _, vs := range vsList {
		ids[vs.RuleID] = true
	}

	if !ids["R1"] || !ids["R2"] {
		t.Errorf("expected both R1 and R2 in index, got %v", ids)
	}

	// Verify correct version attribution.
	for _, vs := range vsList {
		switch vs.RuleID {
		case "R1":
			if !vs.Matches("1.7.8") {
				t.Error("R1 should match 1.7.8")
			}
			if vs.Matches("2.0.0") {
				t.Error("R1 should NOT match 2.0.0")
			}
		case "R2":
			if !vs.Matches("2.0.0") {
				t.Error("R2 should match 2.0.0")
			}
			if vs.Matches("1.7.8") {
				t.Error("R2 should NOT match 1.7.8")
			}
		}
	}
}

func TestBuildPackageIndex_SameRuleSamePackageDifferentEcosystems(t *testing.T) {
	ruleList := []Rule{
		{
			ID: "R1", Title: "Test", Severity: "critical",
			PackageRules: []PackageRule{
				{
					PackageName:        "axios",
					AffectedVersions:   []string{"1.0.0"},
					LockfileEcosystems: []string{"npm"},
				},
				{
					PackageName:        "axios",
					AffectedVersions:   []string{"2.0.0"},
					LockfileEcosystems: []string{"yarn"},
				},
			},
		},
	}

	idx := BuildPackageIndex(ruleList)

	vsList := idx.Packages["axios"]
	if len(vsList) != 2 {
		t.Fatalf("expected 2 VersionSets for axios (one per package_rules entry), got %d", len(vsList))
	}

	// Find the npm one and the yarn one.
	var npmVS, yarnVS *VersionSet
	for _, vs := range vsList {
		if len(vs.LockfileEcosystems) > 0 && vs.LockfileEcosystems[0] == "npm" {
			npmVS = vs
		}
		if len(vs.LockfileEcosystems) > 0 && vs.LockfileEcosystems[0] == "yarn" {
			yarnVS = vs
		}
	}

	if npmVS == nil || yarnVS == nil {
		t.Fatal("expected both npm and yarn VersionSets")
	}

	if !npmVS.Matches("1.0.0") {
		t.Error("npm VersionSet should match 1.0.0")
	}
	if npmVS.Matches("2.0.0") {
		t.Error("npm VersionSet should NOT match 2.0.0")
	}
	if !yarnVS.Matches("2.0.0") {
		t.Error("yarn VersionSet should match 2.0.0")
	}
	if yarnVS.Matches("1.0.0") {
		t.Error("yarn VersionSet should NOT match 1.0.0")
	}

	// Verify ecosystem filtering works correctly.
	if !npmVS.AppliesToLockfile("package-lock.json") {
		t.Error("npm VersionSet should apply to package-lock.json")
	}
	if npmVS.AppliesToLockfile("yarn.lock") {
		t.Error("npm VersionSet should NOT apply to yarn.lock")
	}
}

func TestLoadFile_InvalidSeverity(t *testing.T) {
	content := `{
	  "schema_version": "1.0.0",
	  "rules": [{
	    "id": "SSC-BAD-001",
	    "title": "Bad severity",
	    "kind": "vulnerability",
	    "ecosystem": "npm",
	    "severity": "severe",
	    "package_rules": [{"package_name": "x", "affected_versions": ["*"]}]
	  }]
	}`
	path := filepath.Join(t.TempDir(), "bad-severity.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

// LoadDir with invalid JSON alongside valid files.

func TestLoadDir_GlobError(t *testing.T) {
	// A directory name with "[" produces a malformed glob pattern.
	_, err := LoadDir("[invalid")
	if err == nil {
		t.Fatal("expected error for malformed glob pattern")
	}
}

func TestLoadDir_InvalidJSONFile(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "valid.json", validRuleJSON)
	writeRuleFile(t, dir, "invalid.json", "{bad json}")

	_, err := LoadDir(dir)
	if err == nil {
		t.Fatal("expected error when directory contains invalid JSON file")
	}
}

// Interval arithmetic tests.

func TestParseIntervals_Tilde(t *testing.T) {
	// ~1.2.3 should produce [1.2.3, 1.3.0).
	ivs := parseIntervals("~1.2.3")
	if len(ivs) != 1 {
		t.Fatalf("expected 1 interval, got %d", len(ivs))
	}

	iv := ivs[0]
	if iv.lower == nil || iv.lower.version.Original() != "1.2.3" || !iv.lower.inclusive {
		t.Errorf("lower bound: got %+v, want {1.2.3, inclusive}", iv.lower)
	}

	if iv.upper == nil || iv.upper.version.Original() != "1.3.0" || iv.upper.inclusive {
		t.Errorf("upper bound: got %+v, want {1.3.0, exclusive}", iv.upper)
	}
}

func TestParseIntervals_Caret_ZeroMinor(t *testing.T) {
	// ^0.2.3 should produce [0.2.3, 0.3.0).
	ivs := parseIntervals("^0.2.3")
	if len(ivs) != 1 {
		t.Fatalf("expected 1 interval, got %d", len(ivs))
	}

	iv := ivs[0]
	if iv.lower == nil || iv.lower.version.Original() != "0.2.3" {
		t.Errorf("lower: got %+v, want 0.2.3", iv.lower)
	}

	if iv.upper == nil || iv.upper.version.Original() != "0.3.0" {
		t.Errorf("upper: got %+v, want 0.3.0", iv.upper)
	}
}

func TestParseIntervals_Caret_ZeroMajorZeroMinor(t *testing.T) {
	// ^0.0.3 should produce [0.0.3, 0.0.4).
	ivs := parseIntervals("^0.0.3")
	if len(ivs) != 1 {
		t.Fatalf("expected 1 interval, got %d", len(ivs))
	}

	iv := ivs[0]
	if iv.upper == nil || iv.upper.version.Original() != "0.0.4" {
		t.Errorf("upper: got %+v, want 0.0.4", iv.upper)
	}
}

func TestParseIntervals_ExactVersion(t *testing.T) {
	// Bare version "1.5.0" → point interval [1.5.0, 1.5.0].
	ivs := parseIntervals("1.5.0")
	if len(ivs) != 1 {
		t.Fatalf("expected 1 interval, got %d", len(ivs))
	}

	iv := ivs[0]
	if iv.lower == nil || !iv.lower.inclusive {
		t.Error("expected inclusive lower bound")
	}

	if iv.upper == nil || !iv.upper.inclusive {
		t.Error("expected inclusive upper bound")
	}
}

func TestParseIntervals_StrictGreaterThan(t *testing.T) {
	// >1.0.0 → (1.0.0, +∞).
	ivs := parseIntervals(">1.0.0")
	if len(ivs) != 1 {
		t.Fatalf("expected 1 interval, got %d", len(ivs))
	}

	iv := ivs[0]
	if iv.lower == nil || iv.lower.inclusive {
		t.Error("expected exclusive lower bound")
	}

	if iv.upper != nil {
		t.Error("expected unbounded upper")
	}
}

func TestParseIntervals_LessThanOrEqual(t *testing.T) {
	// <=2.0.0 → (-∞, 2.0.0].
	ivs := parseIntervals("<=2.0.0")
	if len(ivs) != 1 {
		t.Fatalf("expected 1 interval, got %d", len(ivs))
	}

	iv := ivs[0]
	if iv.lower != nil {
		t.Error("expected unbounded lower")
	}

	if iv.upper == nil || !iv.upper.inclusive {
		t.Error("expected inclusive upper bound")
	}
}

func TestParseIntervals_Empty(t *testing.T) {
	ivs := parseIntervals("")
	if len(ivs) != 0 {
		t.Errorf("expected 0 intervals for empty string, got %d", len(ivs))
	}
}

func TestTightenLower_NarrowsExclusive(t *testing.T) {
	// Starting with >=1.0.0, tightening with >1.0.0 should switch to exclusive.
	v1, _ := semver.NewVersion("1.0.0")
	iv := interval{lower: &bound{version: v1, inclusive: true}}
	tightenLower(&iv, &bound{version: v1, inclusive: false})

	if iv.lower.inclusive {
		t.Error("expected exclusive lower after tightening with >1.0.0")
	}
}

func TestTightenLower_KeepsHigher(t *testing.T) {
	v1, _ := semver.NewVersion("1.0.0")
	v2, _ := semver.NewVersion("2.0.0")
	iv := interval{lower: &bound{version: v2, inclusive: true}}
	tightenLower(&iv, &bound{version: v1, inclusive: true})

	if iv.lower.version.Original() != "2.0.0" {
		t.Error("expected lower bound to stay at 2.0.0")
	}
}

func TestTightenUpper_NarrowsExclusive(t *testing.T) {
	v1, _ := semver.NewVersion("1.0.0")
	iv := interval{upper: &bound{version: v1, inclusive: true}}
	tightenUpper(&iv, &bound{version: v1, inclusive: false})

	if iv.upper.inclusive {
		t.Error("expected exclusive upper after tightening with <1.0.0")
	}
}

func TestTightenUpper_KeepsLower(t *testing.T) {
	v1, _ := semver.NewVersion("1.0.0")
	v2, _ := semver.NewVersion("2.0.0")
	iv := interval{upper: &bound{version: v1, inclusive: true}}
	tightenUpper(&iv, &bound{version: v2, inclusive: true})

	if iv.upper.version.Original() != "1.0.0" {
		t.Error("expected upper bound to stay at 1.0.0")
	}
}

func TestRangeCoversVersion_TildeOverlap(t *testing.T) {
	// Rule ~1.2.0 = [1.2.0, 1.3.0), dep ^1.0.0 = [1.0.0, 2.0.0) — overlaps.
	ruleList := []Rule{
		{
			ID: "R-TILDE", Title: "Tilde", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "pkg", AffectedVersions: []string{"~1.2.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "pkg")

	covers, _ := vs.RangeCoversVersion("^1.0.0")
	if !covers {
		t.Error("expected ^1.0.0 to overlap with ~1.2.0")
	}
}

func TestRangeCoversVersion_TildeNoOverlap(t *testing.T) {
	// Rule ~1.2.0 = [1.2.0, 1.3.0), dep ~1.4.0 = [1.4.0, 1.5.0) — no overlap.
	ruleList := []Rule{
		{
			ID: "R-TILDE2", Title: "Tilde2", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "pkg", AffectedVersions: []string{"~1.2.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "pkg")

	covers, _ := vs.RangeCoversVersion("~1.4.0")
	if covers {
		t.Error("expected ~1.4.0 to NOT overlap with ~1.2.0")
	}
}

func TestParseIntervals_NotEqual(t *testing.T) {
	// !=1.0.0 should not narrow the interval to a point. It should produce
	// an unbounded interval (since != can't be represented as a single interval).
	ivs := parseIntervals("!=1.0.0")
	if len(ivs) != 1 {
		t.Fatalf("expected 1 interval, got %d", len(ivs))
	}

	// The interval should remain fully unbounded (nil lower, nil upper)
	// because != is skipped in interval construction.
	if ivs[0].lower != nil || ivs[0].upper != nil {
		t.Error("expected unbounded interval for !=, got bounds")
	}
}

func TestRangeCoversVersion_NotEqualDoesNotFalsePositive(t *testing.T) {
	// Rule !=3.0.0 should not collapse to [3.0.0, 3.0.0] and falsely
	// overlap with dep ^3.0.0. Instead, != is skipped in interval logic,
	// making the rule interval unbounded — which overlaps with everything
	// (conservative but correct for a security scanner).
	ruleList := []Rule{
		{
			ID: "R-NE", Title: "NotEqual", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "pkg", AffectedVersions: []string{"!=3.0.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "pkg")

	// !=3.0.0 as an interval is fully unbounded — it overlaps with any range.
	covers, _ := vs.RangeCoversVersion("^1.0.0")
	if !covers {
		t.Error("expected unbounded != interval to overlap (conservative)")
	}
}

func TestParseIntervals_Contradictory(t *testing.T) {
	// >2.0.0 <1.0.0 is an empty/contradictory interval — should produce 0 intervals.
	ivs := parseIntervals(">2.0.0 <1.0.0")
	if len(ivs) != 0 {
		t.Errorf("expected 0 intervals for contradictory range, got %d", len(ivs))
	}
}

func TestParseIntervals_ContradictoryExclusive(t *testing.T) {
	// >1.0.0 <1.0.0 is empty (exclusive bounds, same version).
	ivs := parseIntervals(">1.0.0 <1.0.0")
	if len(ivs) != 0 {
		t.Errorf("expected 0 intervals for >1.0.0 <1.0.0, got %d", len(ivs))
	}
}

func TestParseIntervals_PointIntervalValid(t *testing.T) {
	// =1.0.0 should produce a valid point interval [1.0.0, 1.0.0].
	ivs := parseIntervals("1.0.0")
	if len(ivs) != 1 {
		t.Fatalf("expected 1 interval, got %d", len(ivs))
	}

	if ivs[0].isEmpty() {
		t.Error("point interval should not be empty")
	}
}

func TestRangeCoversVersion_ContradictoryRuleNoFalsePositive(t *testing.T) {
	// A rule with a contradictory constraint should not match anything.
	ruleList := []Rule{
		{
			ID: "R-CONTRA", Title: "Contradictory", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "pkg", AffectedVersions: []string{">2.0.0 <1.0.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "pkg")

	covers, _ := vs.RangeCoversVersion("^1.5.0")
	if covers {
		t.Error("expected contradictory rule range to NOT produce a finding")
	}
}

func TestSplitOperator(t *testing.T) {
	tests := []struct {
		input   string
		wantOp  string
		wantVer string
	}{
		{">=1.0.0", ">=", "1.0.0"},
		{"<=2.0.0", "<=", "2.0.0"},
		{">1.0.0", ">", "1.0.0"},
		{"<1.0.0", "<", "1.0.0"},
		{"=1.0.0", "=", "1.0.0"},
		{"!=1.0.0", "!=", "1.0.0"},
		{"^1.5.0", "^", "1.5.0"},
		{"~1.5.0", "~", "1.5.0"},
		{"1.5.0", "=", "1.5.0"},
	}

	for _, tt := range tests {
		op, ver := splitOperator(tt.input)
		if op != tt.wantOp || ver != tt.wantVer {
			t.Errorf("splitOperator(%q) = (%q, %q), want (%q, %q)", tt.input, op, ver, tt.wantOp, tt.wantVer)
		}
	}
}

func TestRangeCoversVersion_UnparseableDepRange(t *testing.T) {
	// When the dep range is completely unparseable, constraintOverlap returns false.
	ruleList := []Rule{
		{
			ID: "R-UP", Title: "Unparseable", Severity: "high",
			PackageRules: []PackageRule{
				{PackageName: "pkg", AffectedVersions: []string{">=1.0.0 <2.0.0"}},
			},
		},
	}
	idx := BuildPackageIndex(ruleList)
	vs := firstVS(idx, "pkg")

	// "!!!" can't be parsed as intervals.
	covers, _ := vs.RangeCoversVersion("!!!")
	if covers {
		t.Error("expected no overlap for unparseable dep range")
	}
}

func TestParseIntervals_InvalidVersion(t *testing.T) {
	ivs := parseIntervals(">=not-a-version")
	if len(ivs) != 0 {
		t.Errorf("expected 0 intervals for unparseable version, got %d", len(ivs))
	}
}

func TestParseIntervals_CommaSeperatedComparators(t *testing.T) {
	// Some constraint outputs use commas: ">=1.0.0, <2.0.0".
	ivs := parseIntervals(">=1.0.0, <2.0.0")
	if len(ivs) != 1 {
		t.Fatalf("expected 1 interval, got %d", len(ivs))
	}

	iv := ivs[0]
	if iv.lower == nil || iv.lower.version.Original() != "1.0.0" {
		t.Errorf("lower: got %+v, want 1.0.0", iv.lower)
	}

	if iv.upper == nil || iv.upper.version.Original() != "2.0.0" {
		t.Errorf("upper: got %+v, want 2.0.0", iv.upper)
	}
}

func TestAppliesToLockfile_EmptyEcosystems(t *testing.T) {
	vs := &VersionSet{
		LockfileEcosystems: nil,
	}

	if !vs.AppliesToLockfile("package-lock.json") {
		t.Error("empty ecosystems should match all lockfiles")
	}

	if !vs.AppliesToLockfile("yarn.lock") {
		t.Error("empty ecosystems should match all lockfiles")
	}
}

func TestAppliesToLockfile_UnknownFormat(t *testing.T) {
	vs := &VersionSet{
		LockfileEcosystems: []string{"npm"},
	}

	// Unknown lockfile format should not be filtered.
	if !vs.AppliesToLockfile("Gemfile.lock") {
		t.Error("expected unknown lockfile format to not be filtered")
	}
}

func TestAppliesToLockfile_RecursivePath(t *testing.T) {
	vs := &VersionSet{
		LockfileEcosystems: []string{"npm"},
	}

	// Relative paths from recursive scans should be handled via filepath.Base.
	if !vs.AppliesToLockfile("subdir/package-lock.json") {
		t.Error("expected subdir/package-lock.json to match npm ecosystem")
	}
}

func TestGetOrCreateVersionSet_Reuse(t *testing.T) {
	// getOrCreateVersionSet should return an existing VersionSet for the same rule ID.
	idx := &PackageIndex{Packages: make(map[string][]*VersionSet)}
	r := &Rule{ID: "R1", Title: "Test", Severity: "high"}

	vs1 := getOrCreateVersionSet(idx, "pkg", r)
	vs2 := getOrCreateVersionSet(idx, "pkg", r)

	if vs1 != vs2 {
		t.Error("expected same VersionSet for same rule ID")
	}

	if len(idx.Packages["pkg"]) != 1 {
		t.Errorf("expected 1 VersionSet, got %d", len(idx.Packages["pkg"]))
	}
}
