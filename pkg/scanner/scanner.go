package scanner

import (
	"crypto/md5"  //nolint:gosec // MD5 is used for matching known-bad file hashes from rules, not for security
	"crypto/sha1" //nolint:gosec // SHA1 is used for matching known-bad file hashes from rules, not for security
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gouvernante/pkg/lockfile"
	"gouvernante/pkg/rules"
)

// Finding represents a single detection result.
type Finding struct {
	RuleID      string `json:"rule_id"`
	RuleTitle   string `json:"rule_title"`
	Severity    string `json:"severity"`
	Type        string `json:"type"` // TypePackage, TypeInstalledPackage, TypeCachedPackage, or TypeHostIndicator
	Package     string `json:"package,omitempty"`
	Version     string `json:"version,omitempty"`
	Lockfile    string `json:"lockfile,omitempty"`
	Description string `json:"description,omitempty"`
	Path        string `json:"path,omitempty"`
}

// Status constants for check results.
const (
	StatusFound        = "found"
	StatusClean        = "clean"
	StatusSkipped      = "skipped"
	StatusNotInstalled = "not_installed"
)

// Finding type constants.
const (
	TypePackage          = "package"
	TypeInstalledPackage = "installed_package"
	TypeCachedPackage    = "cached_package"
	TypeHostIndicator    = "host_indicator"
	TypeHeuristic        = "heuristic"
)

// IndicatorTypeFile is the host indicator type handled by the scanner.
// Other indicator types (process, registry, network, environment) are
// schema-validated but not yet checked at runtime.
const IndicatorTypeFile = "file"

// HostCheck records the result of checking a single host indicator.
type HostCheck struct {
	// Path is the filesystem path that was checked.
	Path string
	// Status is the check outcome: StatusFound, StatusClean, or StatusSkipped.
	Status string
	// Reason explains why the check was skipped (empty when Status is not StatusSkipped).
	Reason string
	// RuleID identifies the rule that defined this indicator.
	RuleID string
	// Notes contains the human-readable description from the rule's host_indicator entry.
	Notes string
}

// Result holds the complete scan output.
type Result struct {
	// Findings contains detected supply chain compromises across all scan sources.
	Findings []Finding
	// PackagesTotal is the total dependency entries across all parsed lockfiles.
	PackagesTotal int
	// LockfilesUsed lists the names of lockfiles that were scanned (basenames for single-dir scans, relative paths for recursive scans).
	LockfilesUsed []string
	// HostChecks records the results of host-indicator file checks.
	HostChecks []HostCheck
	// NodeModuleChecks records the results of installed and cached package checks.
	NodeModuleChecks []NodeModulesCheck
	// Heuristic indicates that the result comes from a heuristic scan rather than rule-based scanning.
	Heuristic bool
}

// ScanPackages checks parsed lockfile entries against the package index.
// For exact versions (from lockfiles), uses direct matching.
// For range expressions (from package.json), checks if the range could
// resolve to any compromised version.
func ScanPackages(entries []lockfile.PackageEntry, idx *rules.PackageIndex, lockfileName string) []Finding {
	var findings []Finding

	for _, e := range entries {
		vsList := idx.Packages[e.Name]
		if len(vsList) == 0 {
			continue
		}

		for _, vs := range vsList {
			if !vs.AppliesToLockfile(lockfileName) {
				continue
			}

			// Direct match: exact version or wildcard.
			if vs.Matches(e.Version) {
				findings = append(findings, Finding{
					RuleID:    vs.RuleID,
					RuleTitle: vs.RuleTitle,
					Severity:  vs.Severity,
					Type:      TypePackage,
					Package:   e.Name,
					Version:   e.Version,
					Lockfile:  lockfileName,
				})

				continue
			}

			// Range match: check if the declared range could resolve to a compromised version.
			if covers, matched := vs.RangeCoversVersion(e.Version); covers {
				desc := "range covers compromised version " + matched
				if matched == "*" || strings.ContainsAny(matched, "><=!^~| ") {
					desc = "range overlaps with rule constraint " + matched
				}

				findings = append(findings, Finding{
					RuleID:      vs.RuleID,
					RuleTitle:   vs.RuleTitle,
					Severity:    vs.Severity,
					Type:        TypePackage,
					Package:     e.Name,
					Version:     e.Version,
					Lockfile:    lockfileName,
					Description: desc,
				})
			}
		}
	}

	return findings
}

// ScanHostIndicators checks the filesystem for IOCs defined in rules.
// Returns findings for detected IOCs and a log of all checks performed.
func ScanHostIndicators(ruleList []rules.Rule) ([]Finding, []HostCheck) {
	osName := mapOSName(runtime.GOOS)

	var findings []Finding
	var checks []HostCheck

	for i := range ruleList {
		r := &ruleList[i]
		for j := range r.HostIndicators {
			hi := &r.HostIndicators[j]

			if !osMatch(hi.OSes, osName) {
				desc := indicatorDescription(hi)
				slog.Info("host indicator skipped", "rule", r.ID, "type", hi.Type, "value", desc, "reason", "os mismatch", "requires", hi.OSes, "current", osName)

				continue
			}

			if hi.Type != IndicatorTypeFile {
				desc := indicatorDescription(hi)
				slog.Info("host indicator skipped", "rule", r.ID, "type", hi.Type, "value", desc, "reason", "not implemented")
				checks = append(checks, HostCheck{Path: desc, Status: StatusSkipped, Reason: hi.Type + " check not implemented", RuleID: r.ID, Notes: hi.Notes})

				continue
			}

			finding, check := checkFileIndicator(r, hi)
			checks = append(checks, check)

			if finding != nil {
				findings = append(findings, *finding)
			}
		}
	}

	return findings, checks
}

// checkFileIndicator checks a single file-type host indicator for existence
// and optional hash verification. Returns a finding (nil if clean) and a check log entry.
func checkFileIndicator(r *rules.Rule, hi *rules.HostIndicator) (*Finding, HostCheck) {
	if hi.Path == "" && hi.FileName != "" {
		slog.Warn("file indicator has file_name but no path; will resolve relative to CWD",
			"rule", r.ID, "file_name", hi.FileName)
	}

	fullPath := buildIndicatorPath(hi)

	if _, err := os.Stat(fullPath); err != nil {
		slog.Info("host indicator clean", "rule", r.ID, "path", fullPath)

		return nil, HostCheck{Path: fullPath, Status: StatusClean, RuleID: r.ID, Notes: hi.Notes}
	}

	desc := hi.Notes
	if len(hi.Hashes) > 0 {
		desc = hashCheckDescription(fullPath, hi.Hashes, hi.Notes)
	}

	slog.Warn("host indicator FOUND", "rule", r.ID, "path", fullPath, "notes", desc)

	finding := Finding{
		RuleID:      r.ID,
		RuleTitle:   r.Title,
		Severity:    r.Severity,
		Type:        TypeHostIndicator,
		Description: desc,
		Path:        fullPath,
	}

	return &finding, HostCheck{Path: fullPath, Status: StatusFound, RuleID: r.ID, Notes: hi.Notes}
}

// buildIndicatorPath constructs the full filesystem path for a host indicator
// by expanding environment variables in hi.Path and joining with hi.FileName.
func buildIndicatorPath(hi *rules.HostIndicator) string {
	path := expandPath(hi.Path)
	if hi.FileName != "" {
		return filepath.Join(path, hi.FileName)
	}

	return path
}

// mapOSName converts Go's runtime.GOOS to the schema's OS name.
func mapOSName(goos string) string {
	if goos == "darwin" {
		return "macos"
	}

	return goos
}

// osMatch reports whether current matches any OS in the list.
// An empty list matches all operating systems.
func osMatch(oses []string, current string) bool {
	if len(oses) == 0 {
		return true
	}

	for _, o := range oses {
		if o == current {
			return true
		}
	}

	return false
}

// expandPath replaces Windows environment variable placeholders (%PROGRAMDATA%,
// %APPDATA%, %TEMP%) and Unix home directory shorthand (~) with their actual values.
func expandPath(path string) string {
	if strings.Contains(path, "%PROGRAMDATA%") {
		pd := os.Getenv("PROGRAMDATA")
		if pd == "" {
			pd = `C:\ProgramData`
		}

		path = strings.ReplaceAll(path, "%PROGRAMDATA%", pd)
	}

	if strings.Contains(path, "%APPDATA%") {
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			home, _ := os.UserHomeDir()
			appdata = filepath.Join(home, "AppData", "Roaming")
		}

		path = strings.ReplaceAll(path, "%APPDATA%", appdata)
	}

	if strings.Contains(path, "%TEMP%") {
		tmp := os.Getenv("TEMP")
		if tmp == "" {
			tmp = os.TempDir()
		}

		path = strings.ReplaceAll(path, "%TEMP%", tmp)
	}

	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, path[1:])
		}
	}

	return path
}

// hashCheckDescription computes file hashes and returns a description indicating
// whether any rule hash matched or whether the file is an unknown variant at a
// known-bad path. When the file cannot be read, the description notes the error.
func hashCheckDescription(path string, ruleHashes []rules.FileHash, notes string) string {
	computed, err := computeFileHashes(path, ruleHashes)
	if err != nil {
		if notes != "" {
			return notes + "; hash verification failed: " + err.Error()
		}

		return "hash verification failed: " + err.Error()
	}

	var matched []string

	for _, rh := range ruleHashes {
		if computed[rh.Algorithm] == rh.Value {
			matched = append(matched, rh.Algorithm)
		}
	}

	if len(matched) > 0 {
		suffix := "hash confirmed (" + strings.Join(matched, ", ") + ")"
		if notes != "" {
			return notes + "; " + suffix
		}

		return suffix
	}

	suffix := "file exists but hash does not match any known variant"
	if notes != "" {
		return notes + "; " + suffix
	}

	return suffix
}

// computeFileHashes reads the file at path once and computes all hash algorithms
// referenced by the rule's hashes slice. Returns a map from algorithm name to hex digest.
func computeFileHashes(path string, ruleHashes []rules.FileHash) (map[string]string, error) {
	needed := make(map[string]hash.Hash)

	for _, rh := range ruleHashes {
		if _, ok := needed[rh.Algorithm]; ok {
			continue
		}

		h, ok := newHashFunc(rh.Algorithm)
		if !ok {
			continue // unknown algorithm — skip (validated at load time)
		}

		needed[rh.Algorithm] = h
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}

	defer func() {
		_ = f.Close()
	}()

	writers := make([]io.Writer, 0, len(needed))
	for _, h := range needed {
		writers = append(writers, h)
	}

	if _, err := io.Copy(io.MultiWriter(writers...), f); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	result := make(map[string]string, len(needed))
	for algo, h := range needed {
		result[algo] = hex.EncodeToString(h.Sum(nil))
	}

	return result, nil
}

// newHashFunc returns a new hash.Hash for the given algorithm name.
// Supported algorithms: md5, sha1, sha256, sha512.
func newHashFunc(algorithm string) (hash.Hash, bool) {
	switch algorithm {
	case "md5":
		return md5.New(), true //nolint:gosec // matching known-bad file hashes, not security use
	case "sha1":
		return sha1.New(), true //nolint:gosec // matching known-bad file hashes, not security use
	case "sha256":
		return sha256.New(), true
	case "sha512":
		return sha512.New(), true
	default:
		return nil, false
	}
}

// FormatReport produces a human-readable text report.
func FormatReport(result *Result) string {
	var b strings.Builder

	if result.Heuristic {
		fmt.Fprintf(&b, "=== Heuristic Scan Report ===\n\n")
		fmt.Fprintf(&b, "Findings: %d\n\n", len(result.Findings))
	} else {
		fmt.Fprintf(&b, "=== Supply Chain Scan Report ===\n\n")
		fmt.Fprintf(&b, "Files scanned: %d\n", len(result.LockfilesUsed))
		fmt.Fprintf(&b, "Total packages analyzed: %d\n", result.PackagesTotal)
		fmt.Fprintf(&b, "Findings: %d\n\n", len(result.Findings))
	}

	if len(result.Findings) == 0 {
		if result.Heuristic {
			b.WriteString("No suspicious patterns found.\n")
		} else {
			b.WriteString("No compromised packages or host indicators found.\n")
		}
	} else {
		for i := range result.Findings {
			f := &result.Findings[i]
			formatFinding(&b, i+1, f)
		}
	}

	if len(result.HostChecks) > 0 {
		formatHostChecks(&b, result.HostChecks)
	}

	if len(result.NodeModuleChecks) > 0 {
		formatNodeModulesChecks(&b, result.NodeModuleChecks)
	}

	if result.Heuristic {
		fmt.Fprintf(&b, "Heuristic scan complete: %d findings.\n", len(result.Findings))
	} else {
		fmt.Fprintf(&b, "Scan complete: %d findings in %d lockfiles.\n", len(result.Findings), len(result.LockfilesUsed))
	}

	return b.String()
}

// formatHostChecks writes the host indicator check results (FOUND/CLEAN/SKIP) to b.
func formatHostChecks(b *strings.Builder, checks []HostCheck) {
	b.WriteString("=== Host Indicator Checks ===\n\n")

	for i := range checks {
		c := &checks[i]

		switch c.Status {
		case StatusFound:
			fmt.Fprintf(b, "  [FOUND]   %s  (%s)\n", c.Path, c.RuleID)
		case StatusClean:
			fmt.Fprintf(b, "  [CLEAN]   %s  (%s)\n", c.Path, c.RuleID)
		case StatusSkipped:
			fmt.Fprintf(b, "  [SKIP]    %s — %s  (%s)\n", c.Path, c.Reason, c.RuleID)
		}
	}

	b.WriteString("\n")
}

// indicatorDescription returns a human-readable description of what an indicator points to.
func indicatorDescription(hi *rules.HostIndicator) string {
	if hi.Path != "" && hi.FileName != "" {
		return hi.Path + "/" + hi.FileName
	}

	if hi.Path != "" {
		return hi.Path
	}

	if hi.FileName != "" {
		return hi.FileName
	}

	if hi.Value != "" {
		return hi.Value
	}

	return hi.Notes
}

// formatNodeModulesChecks writes node_modules check results to b.
// Packages with status "not_installed" are omitted for brevity.
func formatNodeModulesChecks(b *strings.Builder, checks []NodeModulesCheck) {
	b.WriteString("=== Node Modules Checks ===\n\n")

	for i := range checks {
		c := &checks[i]

		switch c.Status {
		case StatusFound:
			fmt.Fprintf(b, "  [FOUND]   %s@%s in %s\n", c.Package, c.Version, c.Dir)
		case StatusClean:
			fmt.Fprintf(b, "  [CLEAN]   %s@%s in %s\n", c.Package, c.Version, c.Dir)
		}
		// not_installed is omitted — too many entries, no value in the report.
	}

	b.WriteString("\n")
}

// formatFinding writes a single numbered finding to b, adapting the output
// format based on the finding type (package, installed_package, cached_package, host_indicator).
func formatFinding(b *strings.Builder, num int, f *Finding) {
	fmt.Fprintf(b, "--- Finding %d ---\n", num)
	fmt.Fprintf(b, "  Rule:     %s\n", f.RuleID)
	fmt.Fprintf(b, "  Title:    %s\n", f.RuleTitle)
	fmt.Fprintf(b, "  Severity: %s\n", f.Severity)

	switch f.Type {
	case TypePackage:
		fmt.Fprintf(b, "  Type:     %s\n", f.Type)
		fmt.Fprintf(b, "  Package:  %s@%s\n", f.Package, f.Version)
		fmt.Fprintf(b, "  Lockfile: %s\n", f.Lockfile)

		if f.Description != "" {
			fmt.Fprintf(b, "  Note:     %s\n", f.Description)
		}
	case TypeInstalledPackage:
		b.WriteString("  Type:     installed package\n")
		fmt.Fprintf(b, "  Package:  %s@%s\n", f.Package, f.Version)
		fmt.Fprintf(b, "  Path:     %s\n", f.Path)

		if f.Description != "" {
			fmt.Fprintf(b, "  Source:   %s\n", f.Description)
		}
	case TypeCachedPackage:
		b.WriteString("  Type:     cached package\n")
		fmt.Fprintf(b, "  Package:  %s@%s\n", f.Package, f.Version)
		fmt.Fprintf(b, "  Cache:    %s\n", f.Path)

		if f.Description != "" {
			fmt.Fprintf(b, "  Source:   %s\n", f.Description)
		}
	case TypeHostIndicator:
		b.WriteString("  Type:     host indicator\n")

		if f.Description != "" {
			fmt.Fprintf(b, "  Detail:   %s\n", f.Description)
		}

		fmt.Fprintf(b, "  Path:     %s\n", f.Path)
	case TypeHeuristic:
		b.WriteString("  Type:     heuristic\n")
		fmt.Fprintf(b, "  Package:  %s\n", f.Package)
		fmt.Fprintf(b, "  Path:     %s\n", f.Path)

		if f.Description != "" {
			fmt.Fprintf(b, "  Match:    %s\n", f.Description)
		}
	}

	b.WriteString("\n")
}
