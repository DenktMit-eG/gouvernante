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

	if err := rs.Validate(); err != nil {
		return nil, fmt.Errorf("validate %s: %w", path, err)
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
	RuleID             string
	RuleTitle          string
	Severity           string
	AnyVersion         bool
	Versions           map[string]bool
	Constraints        []*semver.Constraints
	LockfileEcosystems []string
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
//
// The second return value is the matched exact version for point-in-range hits,
// or the overlapping rule constraint expression for range-vs-range matches.
//
// When the rule uses semver range constraints, both sides are compiled into interval
// sets and tested for intersection. Disjunctions (||) produce multiple intervals;
// overlap is determined structurally — two intervals overlap unless one ends strictly
// before the other starts.
func (vs *VersionSet) RangeCoversVersion(rangeExpr string) (covers bool, matched string) {
	if vs.AnyVersion {
		return true, "*"
	}

	depConstraint, err := semver.NewConstraint(rangeExpr)
	if err != nil {
		return false, ""
	}

	if ver, ok := vs.exactVersionInRange(depConstraint); ok {
		return true, ver
	}

	return vs.constraintOverlap(rangeExpr)
}

// exactVersionInRange checks whether any exact affected version satisfies depConstraint.
func (vs *VersionSet) exactVersionInRange(depConstraint *semver.Constraints) (string, bool) {
	for ver := range vs.Versions {
		v, parseErr := semver.NewVersion(ver)
		if parseErr != nil {
			continue
		}

		if depConstraint.Check(v) {
			return ver, true
		}
	}

	return "", false
}

// constraintOverlap checks whether any rule-side constraint range overlaps with
// the dependency range by compiling both into interval sets and testing for
// intersection. Returns early on the first overlap found.
func (vs *VersionSet) constraintOverlap(rangeExpr string) (covers bool, matchedVersion string) {
	if len(vs.Constraints) == 0 {
		return false, ""
	}

	depIntervals := parseIntervals(rangeExpr)

	for _, rc := range vs.Constraints {
		ruleIntervals := parseIntervals(rc.String())

		for di := range depIntervals {
			for ri := range ruleIntervals {
				if depIntervals[di].overlaps(&ruleIntervals[ri]) {
					return true, rc.String()
				}
			}
		}
	}

	return false, ""
}

// bound represents one end of a semver interval.
type bound struct {
	version   *semver.Version
	inclusive bool
}

// interval represents a contiguous range of semver versions.
// A nil lower or upper bound means unbounded in that direction.
type interval struct {
	lower *bound
	upper *bound
}

// isEmpty reports whether this interval is contradictory (lower > upper, or
// equal bounds where at least one is exclusive). For example, >2.0.0 <1.0.0
// or >1.0.0 <1.0.0 are empty.
func (a *interval) isEmpty() bool {
	if a.lower == nil || a.upper == nil {
		return false // unbounded on at least one side
	}

	cmp := a.lower.version.Compare(a.upper.version)
	if cmp > 0 {
		return true // lower > upper
	}

	if cmp == 0 {
		return !a.lower.inclusive || !a.upper.inclusive // equal but not both inclusive
	}

	return false
}

// overlaps reports whether two intervals share at least one common version.
// Two intervals overlap unless one ends strictly before the other starts.
func (a *interval) overlaps(b *interval) bool {
	return !isStrictlyBefore(a, b) && !isStrictlyBefore(b, a)
}

// isStrictlyBefore reports whether interval a ends entirely before interval b starts.
func isStrictlyBefore(a, b *interval) bool {
	if a.upper == nil || b.lower == nil {
		return false // unbounded — cannot be strictly before
	}

	cmp := a.upper.version.Compare(b.lower.version)
	if cmp < 0 {
		return true
	}

	if cmp > 0 {
		return false
	}

	// Same boundary value: only overlaps if both sides include it.
	return !a.upper.inclusive || !b.lower.inclusive
}

// parseIntervals compiles a semver constraint expression into a union of intervals.
// Disjunctions (||) produce separate intervals; conjunctions (space/comma-separated
// comparators within one branch) are intersected into a single interval.
func parseIntervals(expr string) []interval {
	branches := strings.Split(expr, "||")
	intervals := make([]interval, 0, len(branches))

	for _, branch := range branches {
		branch = strings.TrimSpace(branch)
		if branch == "" {
			continue
		}

		if iv, ok := parseBranch(branch); ok {
			intervals = append(intervals, iv)
		}
	}

	return intervals
}

// parseBranch compiles a single AND-branch (no ||) into an interval by intersecting
// all comparators. Supports >=, >, <=, <, =, ^, ~, and bare versions.
// Returns ok=false if the branch has no valid tokens or the resulting interval is empty
// (contradictory, e.g. >2.0.0 <1.0.0).
func parseBranch(branch string) (interval, bool) {
	iv := interval{} // starts fully unbounded

	tokens := tokenizeComparators(branch)
	if len(tokens) == 0 {
		return iv, false
	}

	for _, tok := range tokens {
		applyComparator(&iv, tok)
	}

	if iv.isEmpty() {
		return iv, false
	}

	return iv, true
}

// comparatorToken holds a parsed operator and version from a constraint expression.
type comparatorToken struct {
	op      string
	version *semver.Version
}

// tokenizeComparators splits a branch like ">=1.0.0 <2.0.0" or "^1.5.0" into
// individual operator+version pairs.
func tokenizeComparators(branch string) []comparatorToken {
	// The semver library's String() output uses space-separated comparators
	// within a branch, e.g. ">=1.0.0 <2.0.0".
	parts := strings.Fields(branch)
	tokens := make([]comparatorToken, 0, len(parts))

	for _, p := range parts {
		// Also handle comma-separated (>=1.0.0, <2.0.0).
		p = strings.TrimRight(p, ",")

		op, verStr := splitOperator(p)

		v, err := semver.NewVersion(verStr)
		if err != nil {
			continue
		}

		tokens = append(tokens, comparatorToken{op: op, version: v})
	}

	return tokens
}

// splitOperator separates the leading operator from the version string.
// ">=1.0.0" → (">=", "1.0.0"), "^1.5.0" → ("^", "1.5.0"), "1.0.0" → ("=", "1.0.0").
func splitOperator(s string) (op, version string) {
	for _, prefix := range []string{">=", "<=", "!=", ">", "<", "=", "^", "~"} {
		if strings.HasPrefix(s, prefix) {
			return prefix, strings.TrimSpace(s[len(prefix):])
		}
	}

	return "=", s // bare version
}

// applyComparator narrows an interval by a single comparator.
// ^ and ~ are expanded into their equivalent >= / < bounds.
func applyComparator(iv *interval, tok comparatorToken) {
	v := tok.version

	switch tok.op {
	case ">=":
		tightenLower(iv, &bound{version: v, inclusive: true})
	case ">":
		tightenLower(iv, &bound{version: v, inclusive: false})
	case "<=":
		tightenUpper(iv, &bound{version: v, inclusive: true})
	case "<":
		tightenUpper(iv, &bound{version: v, inclusive: false})
	case "=":
		// Exact match: point interval [v, v].
		tightenLower(iv, &bound{version: v, inclusive: true})
		tightenUpper(iv, &bound{version: v, inclusive: true})
	case "!=":
		// Negation cannot be represented as a single interval. Skip it here;
		// the semver library's Constraints.Check handles != correctly for
		// point-in-range queries via Matches().
	case "^":
		applyCaretBounds(iv, v)
	case "~":
		applyTildeBounds(iv, v)
	}
}

// applyCaretBounds expands ^M.m.p into >= M.m.p, < (next breaking version).
// ^1.2.3 → [1.2.3, 2.0.0), ^0.2.3 → [0.2.3, 0.3.0), ^0.0.3 → [0.0.3, 0.0.4).
func applyCaretBounds(iv *interval, v *semver.Version) {
	tightenLower(iv, &bound{version: v, inclusive: true})

	var upper *semver.Version

	switch {
	case v.Major() > 0:
		upper, _ = semver.NewVersion(fmt.Sprintf("%d.0.0", v.Major()+1)) // uint64 components — cannot produce invalid semver
	case v.Minor() > 0:
		upper, _ = semver.NewVersion(fmt.Sprintf("0.%d.0", v.Minor()+1)) // uint64 components — cannot produce invalid semver
	default:
		upper, _ = semver.NewVersion(fmt.Sprintf("0.0.%d", v.Patch()+1)) // uint64 components — cannot produce invalid semver
	}

	if upper != nil {
		tightenUpper(iv, &bound{version: upper, inclusive: false})
	}
}

// applyTildeBounds expands ~M.m.p into >= M.m.p, < M.(m+1).0.
func applyTildeBounds(iv *interval, v *semver.Version) {
	tightenLower(iv, &bound{version: v, inclusive: true})

	upper, _ := semver.NewVersion(fmt.Sprintf("%d.%d.0", v.Major(), v.Minor()+1)) // uint64 components — cannot produce invalid semver
	if upper != nil {
		tightenUpper(iv, &bound{version: upper, inclusive: false})
	}
}

// tightenLower narrows an interval's lower bound to the higher of the two.
func tightenLower(iv *interval, b *bound) {
	if iv.lower == nil {
		iv.lower = b
		return
	}

	cmp := b.version.Compare(iv.lower.version)
	if cmp > 0 || (cmp == 0 && !b.inclusive) {
		iv.lower = b
	}
}

// tightenUpper narrows an interval's upper bound to the lower of the two.
func tightenUpper(iv *interval, b *bound) {
	if iv.upper == nil {
		iv.upper = b
		return
	}

	cmp := b.version.Compare(iv.upper.version)
	if cmp < 0 || (cmp == 0 && !b.inclusive) {
		iv.upper = b
	}
}

// lockfileEcosystem maps a lockfile filename to its ecosystem name.
// Entries here should cover all ecosystems accepted by the schema.
// Parsers exist for npm, pnpm, yarn, and package.json (see pkg/lockfile/detect.go).
// Bun entries are included so that lockfile_ecosystems filtering works correctly
// once a bun parser is added; until then, bun lockfiles are not detected.
var lockfileEcosystem = map[string]string{
	"package-lock.json": "npm",
	"pnpm-lock.yaml":    "pnpm",
	"yarn.lock":         "yarn",
	"bun.lockb":         "bun",
	"bun.lock":          "bun",
	"package.json":      "npm",
}

// AppliesToLockfile reports whether this VersionSet should be checked
// against the given lockfile. If LockfileEcosystems is empty, the rule
// applies to all lockfiles.
func (vs *VersionSet) AppliesToLockfile(lockfileName string) bool {
	if len(vs.LockfileEcosystems) == 0 {
		return true
	}

	// Extract the base filename in case lockfileName is a relative path
	// (e.g., "subdir/package-lock.json" from recursive scans).
	base := filepath.Base(lockfileName)
	eco, ok := lockfileEcosystem[base]

	if !ok {
		return true // unknown lockfile format — don't filter
	}

	for _, allowed := range vs.LockfileEcosystems {
		if allowed == eco {
			return true
		}
	}

	return false
}

// PackageIndex maps package names to VersionSets for fast lockfile scanning.
// Each package may have multiple VersionSets when multiple rules target the
// same package, ensuring correct rule attribution.
type PackageIndex struct {
	Packages map[string][]*VersionSet
}

// BuildPackageIndex creates a lookup index from loaded rules.
// Supports exact version matching (=1.2.3 or bare 1.2.3), semver ranges, and wildcards (*).
func BuildPackageIndex(ruleList []Rule) *PackageIndex {
	idx := &PackageIndex{Packages: make(map[string][]*VersionSet)}

	for i := range ruleList {
		r := &ruleList[i]
		indexPackageRules(idx, r)
		indexDropperPackages(idx, r)
	}

	return idx
}

// indexPackageRules adds one VersionSet per package_rules entry to the index.
// Each entry gets its own VersionSet to preserve per-entry lockfile_ecosystems.
func indexPackageRules(idx *PackageIndex, r *Rule) {
	for _, pr := range r.PackageRules {
		// Each package_rules entry gets its own VersionSet to preserve
		// per-entry lockfile_ecosystems filtering.
		vs := &VersionSet{
			RuleID:             r.ID,
			RuleTitle:          r.Title,
			Severity:           r.Severity,
			Versions:           make(map[string]bool),
			LockfileEcosystems: pr.LockfileEcosystems,
		}
		idx.Packages[pr.PackageName] = append(idx.Packages[pr.PackageName], vs)

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

// indexDropperPackages adds AnyVersion VersionSets for each dropper package in a rule.
func indexDropperPackages(idx *PackageIndex, r *Rule) {
	for _, dp := range r.DropperPackages {
		vs := getOrCreateVersionSet(idx, dp.PackageName, r)
		vs.AnyVersion = true
	}
}

// getOrCreateVersionSet finds the VersionSet for the given package and rule ID,
// or creates a new one if none exists. Used by dropper packages which share a
// single VersionSet per (package, rule) pair.
func getOrCreateVersionSet(idx *PackageIndex, pkgName string, r *Rule) *VersionSet {
	for _, vs := range idx.Packages[pkgName] {
		if vs.RuleID == r.ID {
			return vs
		}
	}

	vs := &VersionSet{
		RuleID:    r.ID,
		RuleTitle: r.Title,
		Severity:  r.Severity,
		Versions:  make(map[string]bool),
	}
	idx.Packages[pkgName] = append(idx.Packages[pkgName], vs)

	return vs
}
