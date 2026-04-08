// Package cli implements the gouvernante scan pipeline as a testable library.
// It orchestrates rule loading, lockfile parsing, scanning, and output formatting
// without calling os.Exit — the caller controls process lifecycle.
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"gouvernante/pkg/lockfile"
	"gouvernante/pkg/rules"
	"gouvernante/pkg/scanner"
)

// jsonMarshalIndent is the function used to marshal JSON output.
// Replaced in tests to simulate encoding failures.
var jsonMarshalIndent = json.MarshalIndent

// Config holds all CLI options for a single scan invocation.
type Config struct {
	RulesDir     string
	ScanDir      string
	LockfilePath string
	Recursive    bool
	HostCheck    bool
	OutputFile   string
	JSONOutput   bool
	Trace        bool
}

// Run executes the full scan pipeline and returns the process exit code.
// It does not call os.Exit — the caller is responsible for that.
// Exit codes: 0 = clean, 1 = error, 2 = findings detected.
func Run(cfg Config, stdout io.Writer) int {
	startTime := time.Now()
	ConfigureLogging(cfg)

	ruleList, err := LoadRules(cfg.RulesDir)
	if err != nil {
		slog.Error("failed to load rules", "error", err)
		return 1
	}

	idx := rules.BuildPackageIndex(ruleList)
	slog.Info("index built", "rules", len(ruleList), "packages", len(idx.Packages))

	lockfileResults, err := ParseLockfiles(cfg)
	if err != nil {
		slog.Error("failed to parse lockfiles", "error", err)
		return 1
	}

	allFindings, hostChecks, nmChecks := ScanAll(lockfileResults, idx, ruleList, cfg)

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
	if !cfg.JSONOutput {
		header = BuildReportHeader(ruleList, len(idx.Packages), lockfileResults, cfg.HostCheck)
	}

	elapsed := time.Since(startTime)

	output, err := FormatOutput(result, cfg.JSONOutput, elapsed)
	if err != nil {
		slog.Error("failed to format output", "error", err)
		return 1
	}

	if err := WriteOutput(stdout, header, output, cfg.OutputFile, cfg.JSONOutput); err != nil {
		slog.Error("failed to write output", "error", err)
		return 1
	}

	if len(allFindings) > 0 {
		return 2
	}

	return 0
}

// ConfigureLogging sets the global slog level to Debug when Trace is enabled,
// otherwise defaults to Info. All log output goes to stderr.
func ConfigureLogging(cfg Config) {
	level := slog.LevelInfo
	if cfg.Trace {
		level = slog.LevelDebug
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})
	slog.SetDefault(slog.New(handler))
}

// LoadRules loads and validates all JSON rule files from dir.
// Returns an error if the directory is missing, unreadable, empty, or contains invalid rules.
func LoadRules(dir string) ([]rules.Rule, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("rules directory not found: %w", err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("rules path is not a directory: %s", dir)
	}

	ruleList, err := rules.LoadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}

	if len(ruleList) == 0 {
		return nil, fmt.Errorf("no rules loaded from %s", dir)
	}

	slog.Info("rules loaded", "count", len(ruleList))

	return ruleList, nil
}

// ParseLockfiles detects and parses lockfiles based on the config.
// When LockfilePath is set, parses that single file; otherwise probes ScanDir.
func ParseLockfiles(cfg Config) ([]lockfile.Result, error) {
	if cfg.LockfilePath != "" {
		result, err := lockfile.ParseFile(cfg.LockfilePath)
		if err != nil {
			return nil, fmt.Errorf("parse lockfile %s: %w", cfg.LockfilePath, err)
		}

		return []lockfile.Result{*result}, nil
	}

	var results []lockfile.Result
	var err error

	if cfg.Recursive {
		results, err = lockfile.DetectAndParseRecursive(cfg.ScanDir)
	} else {
		results, err = lockfile.DetectAndParse(cfg.ScanDir)
	}

	if err != nil {
		return nil, fmt.Errorf("scan directory %s: %w", cfg.ScanDir, err)
	}

	if len(results) == 0 {
		slog.Warn("no lockfiles found", "dir", cfg.ScanDir)
	}

	return results, nil
}

// ScanAll runs package scanning against every lockfile and, when HostCheck is enabled,
// also scans host indicators, node_modules, global installs, pnpm store, nvm, and npm cache.
func ScanAll(
	lockfileResults []lockfile.Result,
	idx *rules.PackageIndex,
	ruleList []rules.Rule,
	cfg Config,
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

	if cfg.HostCheck {
		slog.Info("checking host indicators")

		hostFindings, checks := scanner.ScanHostIndicators(ruleList)
		allFindings = append(allFindings, hostFindings...)
		hostChecks = checks

		projectDirs := ExtractProjectDirs(lockfileResults, cfg.ScanDir)
		nmFindings, nmC := scanner.ScanNodeModules(projectDirs, idx)
		allFindings = append(allFindings, nmFindings...)
		nmChecks = append(nmChecks, nmC...)

		globalFindings, globalC := scanner.ScanGlobalNodeModules(idx)
		allFindings = append(allFindings, globalFindings...)
		nmChecks = append(nmChecks, globalC...)

		pnpmFindings, pnpmC := scanner.ScanPnpmStore(idx)
		allFindings = append(allFindings, pnpmFindings...)
		nmChecks = append(nmChecks, pnpmC...)

		nvmFindings, nvmC := scanner.ScanNvmDirs(idx)
		allFindings = append(allFindings, nvmFindings...)
		nmChecks = append(nmChecks, nvmC...)

		cacheFindings, cacheC := scanner.ScanNpmCache(idx)
		allFindings = append(allFindings, cacheFindings...)
		nmChecks = append(nmChecks, cacheC...)
	}

	return allFindings, hostChecks, nmChecks
}

// ExtractProjectDirs returns the directories containing lockfiles.
// When a lockfile result has an explicit Path, its directory is used;
// otherwise the directory is inferred from scanDir and the result Name.
func ExtractProjectDirs(lockfileResults []lockfile.Result, scanDir string) []string {
	seen := make(map[string]bool)
	var dirs []string

	for _, lr := range lockfileResults {
		var dir string
		if lr.Path != "" {
			dir = filepath.Dir(lr.Path)
		} else {
			dir = filepath.Dir(filepath.Join(scanDir, lr.Name))
		}

		if !seen[dir] {
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}

	return dirs
}

// FormatOutput renders scan results as either a JSON envelope (with findings
// and summary) or a human-readable text report.
func FormatOutput(result *scanner.Result, jsonMode bool, elapsed time.Duration) (string, error) {
	if jsonMode {
		report := JSONReport{
			Findings: result.Findings,
			Summary: JSONSummary{
				TotalFindings:    len(result.Findings),
				LockfilesScanned: len(result.LockfilesUsed),
				ElapsedMs:        elapsed.Milliseconds(),
			},
		}
		if report.Findings == nil {
			report.Findings = []scanner.Finding{}
		}

		data, err := jsonMarshalIndent(report, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshal JSON: %w", err)
		}

		return string(data) + "\n", nil
	}

	return scanner.FormatReport(result), nil
}

// WriteOutput writes the combined header+report to stdout or to a file.
// When outputFile is "auto", a timestamped filename is generated.
func WriteOutput(stdout io.Writer, header, output, outputFile string, jsonMode bool) error {
	combined := header + output

	if outputFile == "" {
		_, err := fmt.Fprint(stdout, combined)
		return err
	}

	name := outputFile
	if name == "auto" {
		ext := ".txt"
		if jsonMode {
			ext = ".json"
		}

		name = "gouvernante-" + time.Now().Format("2006-01-02T15-04-05") + ext
	}

	if err := os.WriteFile(name, []byte(combined), 0o600); err != nil {
		return fmt.Errorf("write report to %s: %w", name, err)
	}

	slog.Info("report written", "file", name)

	return nil
}
