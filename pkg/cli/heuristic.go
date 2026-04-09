package cli

import (
	"io"
	"log/slog"
	"strconv"
	"time"

	"gouvernante/pkg/heuristic"
	"gouvernante/pkg/scanner"
)

// RunHeuristic executes the heuristic scan pipeline and returns the process exit code.
// It scans JavaScript and shell files inside node_modules for suspicious patterns
// without requiring any rule files. Exit codes: 0 = clean, 1 = error, 2 = findings.
func RunHeuristic(cfg Config, stdout io.Writer) int {
	startTime := time.Now()
	ConfigureLogging(cfg)

	slog.Info("heuristic scan mode", "dir", cfg.ScanDir, "recursive", cfg.Recursive)

	var findings []scanner.Finding
	var err error

	if cfg.Recursive {
		findings, err = heuristic.ScanDirRecursive(cfg.ScanDir)
	} else {
		findings, err = heuristic.ScanDir(cfg.ScanDir)
	}

	if err != nil {
		slog.Error("heuristic scan failed", "error", err)
		return 1
	}

	result := &scanner.Result{
		Findings:  findings,
		Heuristic: true,
	}

	header := ""
	if !cfg.JSONOutput {
		header = buildHeuristicHeader(cfg, len(findings))
	}

	elapsed := time.Since(startTime)

	output, fmtErr := FormatOutput(result, cfg.JSONOutput, elapsed)
	if fmtErr != nil {
		slog.Error("failed to format output", "error", fmtErr)
		return 1
	}

	if writeErr := WriteOutput(stdout, header, output, cfg.OutputFile, cfg.JSONOutput); writeErr != nil {
		slog.Error("failed to write output", "error", writeErr)
		return 1
	}

	if len(findings) > 0 {
		return 2
	}

	return 0
}

// buildHeuristicHeader creates a header for the heuristic scan report.
func buildHeuristicHeader(cfg Config, findingCount int) string {
	return "gouvernante heuristic scan\n" +
		"  Directory: " + cfg.ScanDir + "\n" +
		"  Findings:  " + formatCount(findingCount) + "\n\n"
}

// formatCount returns the string representation of an integer.
func formatCount(n int) string {
	return strconv.Itoa(n)
}
