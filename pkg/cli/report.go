package cli

import (
	"fmt"
	"strings"

	"gouvernante/pkg/lockfile"
	"gouvernante/pkg/rules"
	"gouvernante/pkg/scanner"
)

// JSONReport is the top-level envelope for JSON output, containing findings and a summary.
type JSONReport struct {
	Findings []scanner.Finding `json:"findings"`
	Summary  JSONSummary       `json:"summary"`
}

// JSONSummary holds aggregate scan statistics included in JSON output.
type JSONSummary struct {
	TotalFindings    int   `json:"total_findings"`
	LockfilesScanned int   `json:"lockfiles_scanned"`
	ElapsedMs        int64 `json:"elapsed_ms"`
}

// BuildReportHeader formats the "Scan Configuration" preamble printed before
// the findings section in text mode.
func BuildReportHeader(ruleList []rules.Rule, indexedPkgs int, lockfileResults []lockfile.Result, hostCheck bool) string {
	var b strings.Builder

	fmt.Fprintf(&b, "=== Scan Configuration ===\n\n")
	fmt.Fprintf(&b, "Rules: %d loaded, %d packages indexed\n\n", len(ruleList), indexedPkgs)

	for i := range ruleList {
		r := &ruleList[i]
		fmt.Fprintf(&b, "  %-20s  %-25s  %-10s  %s\n", r.ID, r.Kind, r.Severity, r.Title)
	}

	totalPkgs := 0
	for _, lr := range lockfileResults {
		totalPkgs += len(lr.Entries)
	}

	fmt.Fprintf(&b, "\n=== Lockfiles Found (%d files, %d packages) ===\n\n", len(lockfileResults), totalPkgs)

	for _, lr := range lockfileResults {
		fmt.Fprintf(&b, "  %s: %d packages\n", lr.Name, len(lr.Entries))
	}

	if hostCheck {
		b.WriteString("\n=== Filesystem Checks ===\n\n")
		b.WriteString("  Host IOC files, node_modules, global installs, pnpm store, nvm, npm cache\n")
	}

	b.WriteString("\n")

	return b.String()
}
