package scanner

import (
	"fmt"
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
	Type        string `json:"type"` // "package" or "host_indicator"
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

// HostCheck records the result of checking a single host indicator.
type HostCheck struct {
	Path   string
	Status string
	Reason string
	RuleID string
	Notes  string
}

// Result holds the complete scan output.
type Result struct {
	Findings         []Finding
	PackagesTotal    int
	LockfilesUsed    []string
	HostChecks       []HostCheck
	NodeModuleChecks []NodeModulesCheck
}

// ScanPackages checks parsed lockfile entries against the package index.
// For exact versions (from lockfiles), uses direct matching.
// For range expressions (from package.json), checks if the range could
// resolve to any compromised version.
func ScanPackages(entries []lockfile.PackageEntry, idx *rules.PackageIndex, lockfileName string) []Finding {
	var findings []Finding

	for _, e := range entries {
		vs := idx.Packages[e.Name]
		if vs == nil {
			continue
		}

		// Direct match: exact version or wildcard.
		if vs.Matches(e.Version) {
			findings = append(findings, Finding{
				RuleID:    vs.RuleID,
				RuleTitle: vs.RuleTitle,
				Severity:  vs.Severity,
				Type:      "package",
				Package:   e.Name,
				Version:   e.Version,
				Lockfile:  lockfileName,
			})

			continue
		}

		// Range match: check if the declared range could resolve to a compromised version.
		if covers, matched := vs.RangeCoversVersion(e.Version); covers {
			findings = append(findings, Finding{
				RuleID:      vs.RuleID,
				RuleTitle:   vs.RuleTitle,
				Severity:    vs.Severity,
				Type:        "package",
				Package:     e.Name,
				Version:     e.Version,
				Lockfile:    lockfileName,
				Description: "range covers compromised version " + matched,
			})
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

			if hi.Type != "file" {
				desc := indicatorDescription(hi)
				slog.Info("host indicator skipped", "rule", r.ID, "type", hi.Type, "value", desc, "reason", "not implemented")
				checks = append(checks, HostCheck{Path: desc, Status: StatusSkipped, Reason: hi.Type + " check not implemented", RuleID: r.ID, Notes: hi.Notes})

				continue
			}

			fullPath := buildIndicatorPath(hi)
			if _, err := os.Stat(fullPath); err == nil {
				slog.Warn("host indicator FOUND", "rule", r.ID, "path", fullPath, "notes", hi.Notes)
				checks = append(checks, HostCheck{Path: fullPath, Status: StatusFound, RuleID: r.ID, Notes: hi.Notes})

				findings = append(findings, Finding{
					RuleID:      r.ID,
					RuleTitle:   r.Title,
					Severity:    r.Severity,
					Type:        "host_indicator",
					Description: hi.Notes,
					Path:        fullPath,
				})
			} else {
				slog.Info("host indicator clean", "rule", r.ID, "path", fullPath)
				checks = append(checks, HostCheck{Path: fullPath, Status: StatusClean, RuleID: r.ID, Notes: hi.Notes})
			}
		}
	}

	return findings, checks
}

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

// FormatReport produces a human-readable text report.
func FormatReport(result *Result) string {
	var b strings.Builder

	fmt.Fprintf(&b, "=== Supply Chain Scan Report ===\n\n")

	if len(result.LockfilesUsed) > 0 {
		fmt.Fprintf(&b, "Lockfiles scanned: %s\n", strings.Join(result.LockfilesUsed, ", "))
	}

	fmt.Fprintf(&b, "Total packages analyzed: %d\n", result.PackagesTotal)
	fmt.Fprintf(&b, "Findings: %d\n\n", len(result.Findings))

	if len(result.Findings) == 0 {
		b.WriteString("No compromised packages or host indicators found.\n")
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

	return b.String()
}

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

func formatFinding(b *strings.Builder, num int, f *Finding) {
	fmt.Fprintf(b, "--- Finding %d ---\n", num)
	fmt.Fprintf(b, "  Rule:     %s\n", f.RuleID)
	fmt.Fprintf(b, "  Title:    %s\n", f.RuleTitle)
	fmt.Fprintf(b, "  Severity: %s\n", f.Severity)

	switch f.Type {
	case "package":
		fmt.Fprintf(b, "  Type:     %s\n", f.Type)
		fmt.Fprintf(b, "  Package:  %s@%s\n", f.Package, f.Version)
		fmt.Fprintf(b, "  Lockfile: %s\n", f.Lockfile)

		if f.Description != "" {
			fmt.Fprintf(b, "  Note:     %s\n", f.Description)
		}
	case "installed_package":
		b.WriteString("  Type:     installed package\n")
		fmt.Fprintf(b, "  Package:  %s@%s\n", f.Package, f.Version)
		fmt.Fprintf(b, "  Path:     %s\n", f.Path)
	case "cached_package":
		b.WriteString("  Type:     cached package\n")
		fmt.Fprintf(b, "  Package:  %s@%s\n", f.Package, f.Version)
		fmt.Fprintf(b, "  Cache:    %s\n", f.Path)
	case "host_indicator":
		b.WriteString("  Type:     host indicator\n")

		if f.Description != "" {
			fmt.Fprintf(b, "  Detail:   %s\n", f.Description)
		}

		fmt.Fprintf(b, "  Path:     %s\n", f.Path)
	}

	b.WriteString("\n")
}
