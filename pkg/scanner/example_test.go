package scanner_test

import (
	"fmt"

	"gouvernante/pkg/lockfile"
	"gouvernante/pkg/rules"
	"gouvernante/pkg/scanner"
)

func ExampleScanPackages() {
	entries := []lockfile.PackageEntry{
		{Name: "axios", Version: "1.7.8"},
		{Name: "express", Version: "4.18.2"},
	}

	idx := &rules.PackageIndex{
		Packages: map[string]*rules.VersionSet{
			"axios": {
				RuleID:    "SSC-2025-001",
				RuleTitle: "Axios compromise",
				Severity:  "critical",
				Versions:  map[string]bool{"1.7.8": true},
			},
		},
	}

	findings := scanner.ScanPackages(entries, idx, "pnpm-lock.yaml")

	for i := range findings {
		f := &findings[i]
		fmt.Printf("[%s] %s@%s in %s\n", f.Severity, f.Package, f.Version, f.Lockfile)
	}

	// Output:
	// [critical] axios@1.7.8 in pnpm-lock.yaml
}

func ExampleFormatReport() {
	result := &scanner.Result{
		Findings:      nil,
		PackagesTotal: 150,
		LockfilesUsed: []string{"pnpm-lock.yaml"},
	}

	report := scanner.FormatReport(result)
	fmt.Print(report)

	// Output:
	// === Supply Chain Scan Report ===
	//
	// Files scanned: 1
	// Total packages analyzed: 150
	// Findings: 0
	//
	// No compromised packages or host indicators found.
}
