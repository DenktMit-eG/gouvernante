// gouvernante is a supply chain scanner that checks lockfiles against
// configurable JSON rules and optionally scans the host filesystem
// for known indicators of compromise.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gouvernante/pkg/lockfile"
	"gouvernante/pkg/rules"
	"gouvernante/pkg/scanner"
)

type config struct {
	rulesDir     string
	scanDir      string
	lockfilePath string
	recursive    bool
	hostCheck    bool
	outputFile   string
	jsonOutput   bool
	trace        bool
}

func main() {
	cfg := parseFlags()
	configureLogging(cfg)

	ruleList := loadRules(cfg.rulesDir)
	idx := rules.BuildPackageIndex(ruleList)
	slog.Info("index built", "rules", len(ruleList), "packages", len(idx.Packages))

	lockfileResults := parseLockfiles(cfg)
	allFindings, hostChecks, nmChecks := scanAll(lockfileResults, idx, ruleList, cfg)

	lockfileNames := make([]string, 0, len(lockfileResults))
	totalPackages := 0

	for _, lr := range lockfileResults {
		lockfileNames = append(lockfileNames, lr.Name)
		totalPackages += len(lr.Entries)
	}

	result := &scanner.Result{
		Findings:         allFindings,
		PackagesTotal:    totalPackages,
		LockfilesUsed:    lockfileNames,
		HostChecks:       hostChecks,
		NodeModuleChecks: nmChecks,
	}

	header := ""
	if !cfg.jsonOutput {
		header = buildReportHeader(ruleList, len(idx.Packages), lockfileResults, cfg.hostCheck)
	}

	output := formatOutput(result, cfg.jsonOutput)
	writeOutput(header, output, cfg.outputFile)

	if len(allFindings) > 0 {
		os.Exit(2)
	}
}

func parseFlags() config {
	var cfg config

	flag.StringVar(&cfg.rulesDir, "rules", "", "directory containing rule JSON files (required)")
	flag.StringVar(&cfg.scanDir, "dir", ".", "directory to scan for lockfiles")
	flag.StringVar(&cfg.lockfilePath, "lockfile", "", "path to a specific lockfile (overrides -dir)")
	flag.BoolVar(&cfg.recursive, "recursive", false, "scan directory tree for lockfiles")
	flag.BoolVar(&cfg.hostCheck, "host", false, "also check host indicators (filesystem IOCs)")
	flag.StringVar(&cfg.outputFile, "output", "", "write report to file ('auto' for timestamped name)")
	flag.BoolVar(&cfg.jsonOutput, "json", false, "output findings as JSON")
	flag.BoolVar(&cfg.trace, "trace", false, "enable debug-level logging (every directory visited)")
	flag.Parse()

	if cfg.rulesDir == "" {
		slog.Error("missing required flag: -rules")
		flag.Usage()
		os.Exit(1)
	}

	return cfg
}

func configureLogging(cfg config) {
	level := slog.LevelInfo
	if cfg.trace {
		level = slog.LevelDebug
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})
	slog.SetDefault(slog.New(handler))
}

func loadRules(dir string) []rules.Rule {
	ruleList, err := rules.LoadDir(dir)
	if err != nil {
		slog.Error("failed to load rules", "error", err)
		os.Exit(1)
	}

	if len(ruleList) == 0 {
		slog.Warn("no rules loaded", "dir", dir)
		os.Exit(0)
	}

	slog.Info("rules loaded", "count", len(ruleList))

	return ruleList
}

func parseLockfiles(cfg config) []lockfile.Result {
	if cfg.lockfilePath != "" {
		result, err := lockfile.ParseFile(cfg.lockfilePath)
		if err != nil {
			slog.Error("failed to parse lockfile", "path", cfg.lockfilePath, "error", err)
			os.Exit(1)
		}

		return []lockfile.Result{*result}
	}

	var results []lockfile.Result
	var err error

	if cfg.recursive {
		results, err = lockfile.DetectAndParseRecursive(cfg.scanDir)
	} else {
		results, err = lockfile.DetectAndParse(cfg.scanDir)
	}

	if err != nil {
		slog.Error("failed to scan directory", "dir", cfg.scanDir, "error", err)
		os.Exit(1)
	}

	if len(results) == 0 {
		slog.Warn("no lockfiles found", "dir", cfg.scanDir)
	}

	return results
}

func scanAll(
	lockfileResults []lockfile.Result,
	idx *rules.PackageIndex,
	ruleList []rules.Rule,
	cfg config,
) ([]scanner.Finding, []scanner.HostCheck, []scanner.NodeModulesCheck) {
	var allFindings []scanner.Finding
	var hostChecks []scanner.HostCheck
	var nmChecks []scanner.NodeModulesCheck

	for _, lr := range lockfileResults {
		findings := scanner.ScanPackages(lr.Entries, idx, lr.Name)

		if len(findings) > 0 {
			slog.Warn("scanned", "lockfile", lr.Name, "packages", len(lr.Entries), "findings", len(findings))
		} else {
			slog.Info("scanned", "lockfile", lr.Name, "packages", len(lr.Entries), "findings", 0)
		}

		allFindings = append(allFindings, findings...)
	}

	if cfg.hostCheck {
		slog.Info("checking host indicators")

		hostFindings, checks := scanner.ScanHostIndicators(ruleList)
		allFindings = append(allFindings, hostFindings...)
		hostChecks = checks

		// Scan node_modules in project directories.
		projectDirs := extractProjectDirs(lockfileResults, cfg.scanDir)
		nmFindings, nmC := scanner.ScanNodeModules(projectDirs, idx)
		allFindings = append(allFindings, nmFindings...)
		nmChecks = append(nmChecks, nmC...)

		// Scan global node_modules.
		globalFindings, globalC := scanner.ScanGlobalNodeModules(idx)
		allFindings = append(allFindings, globalFindings...)
		nmChecks = append(nmChecks, globalC...)

		// Scan pnpm store/cache.
		pnpmFindings, pnpmC := scanner.ScanPnpmStore(idx)
		allFindings = append(allFindings, pnpmFindings...)
		nmChecks = append(nmChecks, pnpmC...)

		// Scan nvm cache and nvm-managed globals.
		nvmFindings, nvmC := scanner.ScanNvmDirs(idx)
		allFindings = append(allFindings, nvmFindings...)
		nmChecks = append(nmChecks, nvmC...)

		// Scan npm cache.
		cacheFindings, cacheC := scanner.ScanNpmCache(idx)
		allFindings = append(allFindings, cacheFindings...)
		nmChecks = append(nmChecks, cacheC...)
	}

	return allFindings, hostChecks, nmChecks
}

// extractProjectDirs returns the directories containing lockfiles.
func extractProjectDirs(lockfileResults []lockfile.Result, scanDir string) []string {
	seen := make(map[string]bool)
	var dirs []string

	for _, lr := range lockfileResults {
		dir := filepath.Dir(filepath.Join(scanDir, lr.Name))
		if !seen[dir] {
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}

	return dirs
}

func buildReportHeader(ruleList []rules.Rule, indexedPkgs int, lockfileResults []lockfile.Result, hostCheck bool) string {
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

func formatOutput(result *scanner.Result, jsonMode bool) string {
	if jsonMode {
		data, err := json.MarshalIndent(result.Findings, "", "  ")
		if err != nil {
			slog.Error("failed to marshal JSON", "error", err)
			os.Exit(1)
		}

		return string(data) + "\n"
	}

	return scanner.FormatReport(result)
}

func writeOutput(header, output, outputFile string) {
	combined := header + output

	if outputFile == "" {
		_, _ = fmt.Fprint(os.Stdout, combined) //nolint:forbidigo // intentional stdout write
		return
	}

	name := outputFile
	if name == "auto" {
		name = fmt.Sprintf("scan-report-%d.txt", time.Now().UnixMilli())
	}

	if err := os.WriteFile(name, []byte(combined), 0o600); err != nil {
		slog.Error("failed to write report", "file", name, "error", err)
		os.Exit(1)
	}

	slog.Info("report written", "file", name)
}
