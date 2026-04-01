// gouvernante is a supply chain scanner that checks lockfiles against
// configurable JSON rules and optionally scans the host filesystem
// for known indicators of compromise.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"gouvernante/pkg/lockfile"
	"gouvernante/pkg/rules"
	"gouvernante/pkg/scanner"
)

type config struct {
	rulesDir     string
	scanDir      string
	lockfilePath string
	hostCheck    bool
	outputFile   string
	jsonOutput   bool
}

func main() {
	cfg := parseFlags()

	ruleList := loadRules(cfg.rulesDir)
	idx := rules.BuildPackageIndex(ruleList)
	fmt.Fprintf(os.Stderr, "Indexed %d packages to watch\n", len(idx.Packages))

	lockfileResults := parseLockfiles(cfg)
	allFindings := scanAll(lockfileResults, idx, ruleList, cfg.hostCheck)

	lockfileNames := make([]string, 0, len(lockfileResults))
	totalPackages := 0

	for _, lr := range lockfileResults {
		lockfileNames = append(lockfileNames, lr.Name)
		totalPackages += len(lr.Entries)
	}

	result := &scanner.Result{
		Findings:      allFindings,
		PackagesTotal: totalPackages,
		LockfilesUsed: lockfileNames,
	}

	output := formatOutput(result, cfg.jsonOutput)
	writeOutput(output, cfg.outputFile)

	if len(allFindings) > 0 {
		os.Exit(2)
	}
}

func parseFlags() config {
	var cfg config

	flag.StringVar(&cfg.rulesDir, "rules", "", "directory containing rule JSON files (required)")
	flag.StringVar(&cfg.scanDir, "dir", ".", "directory to scan for lockfiles")
	flag.StringVar(&cfg.lockfilePath, "lockfile", "", "path to a specific lockfile (overrides -dir)")
	flag.BoolVar(&cfg.hostCheck, "host", false, "also check host indicators (filesystem IOCs)")
	flag.StringVar(&cfg.outputFile, "output", "", "write report to file ('auto' for timestamped name)")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "output findings as JSON")
	flag.Parse()

	if cfg.rulesDir == "" {
		fmt.Fprintln(os.Stderr, "error: -rules directory is required")
		flag.Usage()
		os.Exit(1)
	}

	return cfg
}

func loadRules(dir string) []rules.Rule {
	ruleList, err := rules.LoadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading rules: %v\n", err)
		os.Exit(1)
	}

	if len(ruleList) == 0 {
		fmt.Fprintln(os.Stderr, "warning: no rules loaded")
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "Loaded %d rules\n", len(ruleList))

	return ruleList
}

func parseLockfiles(cfg config) []lockfile.Result {
	if cfg.lockfilePath != "" {
		result, err := lockfile.ParseFile(cfg.lockfilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing lockfile: %v\n", err)
			os.Exit(1)
		}

		return []lockfile.Result{*result}
	}

	results, err := lockfile.DetectAndParse(cfg.scanDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error scanning directory: %v\n", err)
		os.Exit(1)
	}

	if len(results) == 0 {
		fmt.Fprintf(os.Stderr, "warning: no lockfiles found in %s\n", cfg.scanDir)
	}

	return results
}

func scanAll(
	lockfileResults []lockfile.Result,
	idx *rules.PackageIndex,
	ruleList []rules.Rule,
	hostCheck bool,
) []scanner.Finding {
	var allFindings []scanner.Finding

	for _, lr := range lockfileResults {
		fmt.Fprintf(os.Stderr, "  %s: %d packages\n", lr.Name, len(lr.Entries))
		findings := scanner.ScanPackages(lr.Entries, idx, lr.Name)
		allFindings = append(allFindings, findings...)
	}

	if hostCheck {
		fmt.Fprintln(os.Stderr, "Checking host indicators...")
		hostFindings := scanner.ScanHostIndicators(ruleList)
		allFindings = append(allFindings, hostFindings...)
	}

	return allFindings
}

func formatOutput(result *scanner.Result, jsonMode bool) string {
	if jsonMode {
		data, err := json.MarshalIndent(result.Findings, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error marshaling JSON: %v\n", err)
			os.Exit(1)
		}

		return string(data) + "\n"
	}

	return scanner.FormatReport(result)
}

func writeOutput(output, outputFile string) {
	if outputFile == "" {
		_, _ = fmt.Fprint(os.Stdout, output) //nolint:forbidigo // intentional stdout write
		return
	}

	name := outputFile
	if name == "auto" {
		name = fmt.Sprintf("scan-report-%d.txt", time.Now().UnixMilli())
	}

	if err := os.WriteFile(name, []byte(output), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "error writing report: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Report written to %s\n", name)
}
