// gouvernante is a supply chain scanner that checks lockfiles against
// configurable JSON rules and optionally scans the host filesystem
// for known indicators of compromise.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"gouvernante/pkg/cli"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cfg, exit := parseFlags()
	if exit {
		return
	}

	os.Exit(cli.Run(cfg, os.Stdout))
}

// parseFlags registers CLI flags, parses them, and validates required arguments.
// This stays in main because flag.Parse mutates global state.
// Returns the config and whether the program should exit early (e.g. -version).
func parseFlags() (cli.Config, bool) {
	var cfg cli.Config
	var showVersion bool

	flag.StringVar(&cfg.RulesDir, "rules", "", "directory containing rule JSON files (required)")
	flag.StringVar(&cfg.ScanDir, "dir", ".", "directory to scan for lockfiles")
	flag.StringVar(&cfg.LockfilePath, "lockfile", "", "path to a specific lockfile (overrides -dir)")
	flag.BoolVar(&cfg.Recursive, "recursive", false, "scan directory tree for lockfiles")
	flag.BoolVar(&cfg.HostCheck, "host", false, "also check host indicators (filesystem IOCs)")
	flag.StringVar(&cfg.OutputFile, "output", "", "write report to file ('auto' for timestamped name)")
	flag.BoolVar(&cfg.JSONOutput, "json", false, "output findings as JSON")
	flag.BoolVar(&cfg.Trace, "trace", false, "enable debug-level logging (every directory visited)")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(version)
		return cli.Config{}, true
	}

	if cfg.RulesDir == "" {
		slog.Error("missing required flag: -rules")
		flag.Usage()
		os.Exit(1)
	}

	return cfg, false
}
