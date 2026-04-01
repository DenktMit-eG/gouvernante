package rules

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// RuleSet is the top-level JSON document containing a schema version and rules.
type RuleSet struct {
	SchemaVersion string `json:"schema_version"`
	Rules         []Rule `json:"rules"`
}

// Rule represents a single supply chain incident with package detection
// rules, dropper packages, host indicators, and remediation guidance.
type Rule struct {
	ID              string          `json:"id"`
	Title           string          `json:"title"`
	Kind            string          `json:"kind"`
	Ecosystem       string          `json:"ecosystem"`
	Severity        string          `json:"severity"`
	Summary         string          `json:"summary,omitempty"`
	Aliases         []Alias         `json:"aliases,omitempty"`
	References      []Reference     `json:"references,omitempty"`
	PackageRules    []PackageRule   `json:"package_rules"`
	DropperPackages []DropperPkg    `json:"dropper_packages,omitempty"`
	HostIndicators  []HostIndicator `json:"host_indicators,omitempty"`
	Remediation     *Remediation    `json:"remediation,omitempty"`
	Metadata        *Metadata       `json:"metadata,omitempty"`
}

// Alias represents an alternative identifier for a rule (CVE, GHSA, etc.).
type Alias struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Reference is a URL pointing to an advisory, article, or other resource.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// PackageRule defines which package+version combinations are affected.
type PackageRule struct {
	PackageName        string   `json:"package_name"`
	AffectedVersions   []string `json:"affected_versions"`
	LockfileEcosystems []string `json:"lockfile_ecosystems,omitempty"`
	Notes              string   `json:"notes,omitempty"`
}

// DropperPkg identifies an auxiliary package used as a payload delivery mechanism.
type DropperPkg struct {
	PackageName string `json:"package_name"`
	Notes       string `json:"notes,omitempty"`
}

// HostIndicator describes a filesystem artifact left by a compromise.
type HostIndicator struct {
	Type       string     `json:"type"`
	Path       string     `json:"path,omitempty"`
	FileName   string     `json:"file_name,omitempty"`
	Value      string     `json:"value,omitempty"`
	OSes       []string   `json:"oses"`
	Hashes     []FileHash `json:"hashes,omitempty"`
	Confidence string     `json:"confidence,omitempty"`
	Notes      string     `json:"notes,omitempty"`
}

// FileHash represents a cryptographic hash of a known malicious file.
type FileHash struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// Remediation provides guidance on how to respond to a finding.
type Remediation struct {
	Summary string   `json:"summary,omitempty"`
	Steps   []string `json:"steps,omitempty"`
}

// Metadata holds timestamps for rule publication and updates.
type Metadata struct {
	PublishedAt   string `json:"published_at,omitempty"`
	LastUpdatedAt string `json:"last_updated_at,omitempty"`
}

// LoadFile loads a rule set from a single JSON file.
func LoadFile(path string) (*RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rule %s: %w", path, err)
	}

	var rs RuleSet
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("parse rule %s: %w", path, err)
	}

	// Early exit on missing ID. Full validation is available via RuleSet.Validate()
	// for programmatic construction; this check ensures LoadFile fails fast on
	// clearly broken files without requiring Validate() at every call site.
	for i := range rs.Rules {
		if rs.Rules[i].ID == "" {
			return nil, fmt.Errorf("rule %s: rules[%d] missing id", path, i)
		}
	}

	return &rs, nil
}

// LoadDir loads all .json rule files from a directory and merges them.
func LoadDir(dir string) ([]Rule, error) {
	entries, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("glob rules dir: %w", err)
	}

	var all []Rule

	for _, e := range entries {
		rs, err := LoadFile(e)
		if err != nil {
			return nil, err
		}

		all = append(all, rs.Rules...)
	}

	return all, nil
}

// VersionSet is a fast lookup for affected versions of a specific package.
type VersionSet struct {
	RuleID      string
	RuleTitle   string
	Severity    string
	AnyVersion  bool
	Versions    map[string]bool
	Constraints []*semver.Constraints
}

// Matches reports whether the given version is in the affected set.
// Checks exact match first (fast path), then semver constraints.
func (vs *VersionSet) Matches(version string) bool {
	if vs.AnyVersion {
		return true
	}

	if vs.Versions[version] {
		return true
	}

	if len(vs.Constraints) == 0 {
		return false
	}

	v, err := semver.NewVersion(version)
	if err != nil {
		return false
	}

	for _, c := range vs.Constraints {
		if c.Check(v) {
			return true
		}
	}

	return false
}

// RangeCoversVersion checks whether a dependency range expression (e.g., "^1.14.0")
// could resolve to any of the affected versions. Used for package.json scanning
// where the declared version is a range, not a resolved version.
func (vs *VersionSet) RangeCoversVersion(rangeExpr string) (covers bool, matchedVersion string) {
	if vs.AnyVersion {
		return true, "*"
	}

	constraint, err := semver.NewConstraint(rangeExpr)
	if err != nil {
		return false, ""
	}

	for ver := range vs.Versions {
		v, parseErr := semver.NewVersion(ver)
		if parseErr != nil {
			continue
		}

		if constraint.Check(v) {
			return true, ver
		}
	}

	return false, ""
}

// PackageIndex maps package names to VersionSets for fast lockfile scanning.
type PackageIndex struct {
	Packages map[string]*VersionSet
}

// BuildPackageIndex creates a lookup index from loaded rules.
// Currently supports exact version matching (=1.2.3 or bare 1.2.3) and wildcards (*).
func BuildPackageIndex(ruleList []Rule) *PackageIndex {
	idx := &PackageIndex{Packages: make(map[string]*VersionSet)}

	for i := range ruleList {
		r := &ruleList[i]
		indexPackageRules(idx, r)
		indexDropperPackages(idx, r)
	}

	return idx
}

func indexPackageRules(idx *PackageIndex, r *Rule) {
	for _, pr := range r.PackageRules {
		vs := getOrCreateVersionSet(idx, pr.PackageName, r)

		for _, v := range pr.AffectedVersions {
			if v == "*" {
				vs.AnyVersion = true

				continue
			}

			clean := strings.TrimPrefix(v, "=")

			// Try parsing as semver constraint (range expression).
			// If it's a simple version like "1.14.1", store as exact match (fast path).
			// If it's a range like ">=1.0.0 <2.0.0", store as constraint.
			if _, err := semver.NewVersion(clean); err == nil {
				vs.Versions[clean] = true
			} else if c, err := semver.NewConstraint(v); err == nil {
				vs.Constraints = append(vs.Constraints, c)
			} else {
				// Neither a valid version nor a valid constraint — store as exact string.
				slog.Debug("unparseable version expression, storing as exact match", "package", pr.PackageName, "version", v)
				vs.Versions[clean] = true
			}
		}
	}
}

func indexDropperPackages(idx *PackageIndex, r *Rule) {
	for _, dp := range r.DropperPackages {
		vs := getOrCreateVersionSet(idx, dp.PackageName, r)
		vs.AnyVersion = true
	}
}

func getOrCreateVersionSet(idx *PackageIndex, pkgName string, r *Rule) *VersionSet {
	vs := idx.Packages[pkgName]
	if vs == nil {
		vs = &VersionSet{
			RuleID:    r.ID,
			RuleTitle: r.Title,
			Severity:  r.Severity,
			Versions:  make(map[string]bool),
		}
		idx.Packages[pkgName] = vs
	}

	return vs
}
