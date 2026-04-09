package heuristic

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gouvernante/pkg/scanner"
)

// OsStat is the function used to stat files. Replaced in tests.
var OsStat = os.Stat

// osReadFile is the function used to read files. Replaced in tests.
var osReadFile = os.ReadFile

// ScanDir scans all packages inside node_modules directories found under dir.
// It returns heuristic findings for files matching suspicious patterns.
func ScanDir(dir string) ([]scanner.Finding, error) {
	nmDir := filepath.Join(dir, "node_modules")

	info, err := OsStat(nmDir)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Info("no node_modules directory", "dir", dir)
			return nil, nil
		}

		return nil, err
	}

	if !info.IsDir() {
		return nil, nil
	}

	slog.Info("heuristic scan", "node_modules", nmDir)

	pkgs := listPackages(nmDir)
	var findings []scanner.Finding

	for _, pkg := range pkgs {
		pkgDir := filepath.Join(nmDir, pkg)
		f := scanPackage(pkgDir, pkg)
		findings = append(findings, f...)
	}

	return findings, nil
}

// ScanDirRecursive walks the directory tree and scans every node_modules found.
func ScanDirRecursive(dir string) ([]scanner.Finding, error) {
	var allFindings []scanner.Finding
	seen := make(map[string]bool)

	//nolint:nilerr // walk function returns nil for all errors to skip unreadable directories
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if !d.IsDir() {
			return nil
		}

		if d.Name() == "node_modules" && !seen[path] {
			seen[path] = true
			parentDir := filepath.Dir(path)
			findings, scanErr := ScanDir(parentDir)

			if scanErr != nil {
				slog.Warn("heuristic scan error", "dir", parentDir, "error", scanErr)
				return nil
			}

			allFindings = append(allFindings, findings...)

			return filepath.SkipDir
		}

		return nil
	})

	return allFindings, nil
}

// listPackages returns the names of all installed packages in a node_modules directory,
// including scoped packages (@scope/pkg).
func listPackages(nmDir string) []string {
	entries, err := os.ReadDir(nmDir)
	if err != nil {
		return nil
	}

	var pkgs []string

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		name := e.Name()

		if strings.HasPrefix(name, ".") {
			continue
		}

		if strings.HasPrefix(name, "@") {
			scopeEntries, scopeErr := os.ReadDir(filepath.Join(nmDir, name))
			if scopeErr != nil {
				continue
			}

			for _, se := range scopeEntries {
				if se.IsDir() {
					pkgs = append(pkgs, name+"/"+se.Name())
				}
			}

			continue
		}

		pkgs = append(pkgs, name)
	}

	return pkgs
}

// scanPackage runs all heuristic checks against a single package directory.
func scanPackage(pkgDir, pkgName string) []scanner.Finding {
	var findings []scanner.Finding

	lf := checkLifecycleScripts(pkgDir, pkgName)
	findings = append(findings, lf...)

	files := collectFiles(pkgDir)
	for _, f := range files {
		ff := scanFile(f, pkgName)
		findings = append(findings, ff...)
	}

	return findings
}

// packageJSONScripts is the minimal structure for extracting lifecycle scripts.
type packageJSONScripts struct {
	Scripts map[string]string `json:"scripts"`
}

// checkLifecycleScripts reads package.json and checks preinstall/postinstall/preuninstall
// scripts for suspicious commands.
func checkLifecycleScripts(pkgDir, pkgName string) []scanner.Finding {
	pkgJSONPath := filepath.Join(pkgDir, "package.json")

	data, err := osReadFile(pkgJSONPath) //nolint:gosec // path from directory listing
	if err != nil {
		return nil
	}

	var pkg packageJSONScripts
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	var findings []scanner.Finding

	for _, hook := range lifecycleHooks {
		script, ok := pkg.Scripts[hook]
		if !ok || script == "" {
			continue
		}

		if lifecycleExecPattern.MatchString(script) && !benignPostinstallPattern.MatchString(script) {
			findings = append(findings, scanner.Finding{
				RuleID:      "HEUR-POSTINSTALL-EXEC",
				RuleTitle:   "Suspicious lifecycle script",
				Severity:    severityHigh,
				Type:        scanner.TypeHeuristic,
				Package:     pkgName,
				Path:        pkgJSONPath,
				Description: hook + ": " + truncate(script, 200),
			})
		}
	}

	return findings
}

// collectFiles returns scannable file paths inside a package directory.
// It scans the top level and one level into well-known subdirectories.
func collectFiles(pkgDir string) []string {
	var files []string

	files = appendScannable(files, pkgDir)

	for _, sub := range scannableSubdirs {
		subDir := filepath.Join(pkgDir, sub)

		info, err := os.Stat(subDir)
		if err != nil || !info.IsDir() {
			continue
		}

		files = appendScannable(files, subDir)
	}

	if len(files) > maxFilesPerPackage {
		files = files[:maxFilesPerPackage]
	}

	return files
}

// appendScannable appends scannable files from dir to the files slice.
func appendScannable(files []string, dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return files
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}

		name := e.Name()
		ext := filepath.Ext(name)

		if !isScannable(ext) {
			continue
		}

		if strings.HasSuffix(name, ".min.js") {
			continue
		}

		info, infoErr := OsStat(filepath.Join(dir, name))
		if infoErr != nil {
			continue
		}

		if info.Size() > maxFileSize {
			continue
		}

		files = append(files, filepath.Join(dir, name))
	}

	return files
}

// isScannable reports whether the file extension is one we should scan.
func isScannable(ext string) bool {
	switch ext {
	case ".js", ".cjs", ".mjs", ".sh":
		return true
	default:
		return false
	}
}

// scanFile reads a file and matches it against all applicable heuristic patterns.
func scanFile(path, pkgName string) []scanner.Finding {
	content, err := osReadFile(path) //nolint:gosec // path from directory listing
	if err != nil {
		return nil
	}

	var findings []scanner.Finding

	ext := filepath.Ext(path)

	for i := range Patterns {
		p := &Patterns[i]

		if !extensionMatch(p.Extensions, ext) {
			continue
		}

		if p.Regex.Match(content) {
			loc := p.Regex.FindIndex(content)
			desc := ""

			if loc != nil {
				desc = truncate(string(content[loc[0]:loc[1]]), 200)
			}

			findings = append(findings, scanner.Finding{
				RuleID:      p.ID,
				RuleTitle:   p.Title,
				Severity:    severityHigh,
				Type:        scanner.TypeHeuristic,
				Package:     pkgName,
				Path:        path,
				Description: desc,
			})
		}
	}

	if checkEnvHarvest(content) {
		findings = append(findings, scanner.Finding{
			RuleID:    "HEUR-ENV-HARVEST",
			RuleTitle: "Environment variable credential harvesting",
			Severity:  severityHigh,
			Type:      scanner.TypeHeuristic,
			Package:   pkgName,
			Path:      path,
		})
	}

	if checkHexExec(content) {
		findings = append(findings, scanner.Finding{
			RuleID:    "HEUR-HEX-EXEC",
			RuleTitle: "Hex-encoded payload with execution",
			Severity:  severityHigh,
			Type:      scanner.TypeHeuristic,
			Package:   pkgName,
			Path:      path,
		})
	}

	return findings
}

// checkEnvHarvest returns true when the content accesses 3+ known secret
// environment variables and also contains a network call pattern.
func checkEnvHarvest(content []byte) bool {
	count := 0

	for _, re := range secretEnvVars {
		if re.Match(content) {
			count++
		}

		if count >= envHarvestThreshold {
			break
		}
	}

	if count < envHarvestThreshold {
		return false
	}

	return networkCallPattern.Match(content)
}

// checkHexExec returns true when the content contains a long hex literal
// with an execution function within hexExecProximity bytes.
func checkHexExec(content []byte) bool {
	loc := hexLiteralPattern.FindIndex(content)
	if loc == nil {
		return false
	}

	start := max(0, loc[0]-hexExecProximity)
	end := min(len(content), loc[1]+hexExecProximity)

	return execNearHexPattern.Match(content[start:end])
}

// extensionMatch reports whether ext is in the allowed list.
func extensionMatch(extensions []string, ext string) bool {
	for _, e := range extensions {
		if e == ext {
			return true
		}
	}

	return false
}

// truncate returns s truncated to maxLen characters, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	return s[:maxLen] + "..."
}
