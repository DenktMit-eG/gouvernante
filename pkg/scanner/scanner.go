package scanner

import (
	"fmt"
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

// Result holds the complete scan output.
type Result struct {
	Findings      []Finding
	PackagesTotal int
	LockfilesUsed []string
}

// ScanPackages checks parsed lockfile entries against the package index.
func ScanPackages(entries []lockfile.PackageEntry, idx *rules.PackageIndex, lockfileName string) []Finding {
	var findings []Finding

	for _, e := range entries {
		vs := idx.Packages[e.Name]
		if vs == nil {
			continue
		}

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
		}
	}

	return findings
}

// ScanHostIndicators checks the filesystem for IOCs defined in rules.
func ScanHostIndicators(ruleList []rules.Rule) []Finding {
	osName := mapOSName(runtime.GOOS)

	var findings []Finding

	for i := range ruleList {
		r := &ruleList[i]
		for j := range r.HostIndicators {
			hi := &r.HostIndicators[j]

			if !osMatch(hi.OSes, osName) || hi.Type != "file" {
				continue
			}

			fullPath := buildIndicatorPath(hi)
			if _, err := os.Stat(fullPath); err == nil {
				findings = append(findings, Finding{
					RuleID:      r.ID,
					RuleTitle:   r.Title,
					Severity:    r.Severity,
					Type:        "host_indicator",
					Description: hi.Notes,
					Path:        fullPath,
				})
			}
		}
	}

	return findings
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

		return b.String()
	}

	for i := range result.Findings {
		f := &result.Findings[i]
		formatFinding(&b, i+1, f)
	}

	return b.String()
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
	case "host_indicator":
		b.WriteString("  Type:     host indicator\n")

		if f.Description != "" {
			fmt.Fprintf(b, "  Detail:   %s\n", f.Description)
		}

		fmt.Fprintf(b, "  Path:     %s\n", f.Path)
	}

	b.WriteString("\n")
}
