package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gouvernante/pkg/rules"
)

// packageJSON is the minimal structure we read from package.json files.
type packageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// NodeModulesCheck records the result of checking one package in a directory.
type NodeModulesCheck struct {
	Dir     string
	Package string
	Version string
	Status  string
}

// cacheProgressInterval controls how often progress is logged during cache scanning.
const cacheProgressInterval = 500

// cacheLookup holds precomputed byte slices for fast cache blob searching.
type cacheLookup struct {
	name      string
	nameBytes []byte
	vs        *rules.VersionSet
	versions  [][]byte
}

// Command helpers.

// runCommand runs an external command and returns trimmed stdout, or empty string on failure.
func runCommand(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, name, args...).Output() //nolint:gosec // intentional external tool invocation
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
}

// Global npm modules.

// globalNodeModulesPaths returns global node_modules locations.
// Uses `npm config get prefix` if npm is available, falls back to well-known paths.
func globalNodeModulesPaths() []string {
	var paths []string

	// Dynamic: ask npm for its prefix.
	if prefix := runCommand("npm", "config", "get", "prefix"); prefix != "" {
		nmPath := filepath.Join(prefix, "lib", "node_modules")
		slog.Info("npm prefix detected", "prefix", prefix, "node_modules", nmPath)
		paths = append(paths, nmPath)
	} else {
		slog.Debug("npm not available, using default global paths")
	}

	// Static fallbacks per OS.
	switch runtime.GOOS {
	case "linux":
		paths = append(paths, "/usr/lib/node_modules", "/usr/local/lib/node_modules")
	case "darwin":
		paths = append(paths, "/usr/local/lib/node_modules", "/opt/homebrew/lib/node_modules")
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			paths = append(paths, filepath.Join(appdata, "npm", "node_modules"))
		}
	}

	return dedup(paths)
}

// ScanNodeModules checks node_modules directories in the given project directories.
func ScanNodeModules(projectDirs []string, idx *rules.PackageIndex) ([]Finding, []NodeModulesCheck) {
	var findings []Finding
	var checks []NodeModulesCheck

	for _, dir := range projectDirs {
		nmDir := filepath.Join(dir, "node_modules")
		if _, err := os.Stat(nmDir); err != nil {
			slog.Debug("no node_modules", "dir", dir)

			continue
		}

		slog.Info("scanning node_modules", "dir", nmDir)
		f, c := scanSingleNodeModules(nmDir, idx)
		findings = append(findings, f...)
		checks = append(checks, c...)
	}

	return findings, checks
}

// ScanGlobalNodeModules checks well-known global install paths.
func ScanGlobalNodeModules(idx *rules.PackageIndex) ([]Finding, []NodeModulesCheck) {
	paths := globalNodeModulesPaths()

	var findings []Finding
	var checks []NodeModulesCheck

	for _, dir := range paths {
		if _, err := os.Stat(dir); err != nil {
			slog.Debug("global path not found", "dir", dir)

			continue
		}

		slog.Info("scanning global node_modules", "dir", dir)
		f, c := scanSingleNodeModules(dir, idx)
		findings = append(findings, f...)
		checks = append(checks, c...)
	}

	return findings, checks
}

func scanSingleNodeModules(nmDir string, idx *rules.PackageIndex) ([]Finding, []NodeModulesCheck) {
	var findings []Finding
	var checks []NodeModulesCheck

	for pkgName, vs := range idx.Packages {
		version, err := readInstalledVersion(nmDir, pkgName)
		if err != nil {
			slog.Debug("package not installed", "dir", nmDir, "package", pkgName)
			checks = append(checks, NodeModulesCheck{Dir: nmDir, Package: pkgName, Status: StatusNotInstalled})

			continue
		}

		if vs.Matches(version) {
			slog.Warn("compromised package installed", "dir", nmDir, "package", pkgName, "version", version)
			checks = append(checks, NodeModulesCheck{Dir: nmDir, Package: pkgName, Version: version, Status: StatusFound})

			findings = append(findings, Finding{
				RuleID:      vs.RuleID,
				RuleTitle:   vs.RuleTitle,
				Severity:    vs.Severity,
				Type:        "installed_package",
				Package:     pkgName,
				Version:     version,
				Description: "compromised package found in " + nmDir,
				Path:        filepath.Join(nmDir, pkgName),
			})
		} else {
			slog.Info("package installed, version clean", "dir", nmDir, "package", pkgName, "version", version)
			checks = append(checks, NodeModulesCheck{Dir: nmDir, Package: pkgName, Version: version, Status: StatusClean})
		}
	}

	return findings, checks
}

// readInstalledVersion reads the version from a package.json inside a node_modules directory.
func readInstalledVersion(nmDir, pkgName string) (string, error) {
	pkgJSONPath := filepath.Join(nmDir, pkgName, "package.json")

	data, err := os.ReadFile(pkgJSONPath) //nolint:gosec // path from rule index, not user input
	if err != nil {
		return "", err
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return "", err
	}

	return pkg.Version, nil
}

// pnpm store and cache scanning.

// ScanPnpmStore checks pnpm store and cache directories for compromised packages.
func ScanPnpmStore(idx *rules.PackageIndex) ([]Finding, []NodeModulesCheck) {
	home, err := os.UserHomeDir()
	if err != nil {
		slog.Debug("cannot determine home dir for pnpm scan")
		return nil, nil
	}

	dirs := []string{
		filepath.Join(home, ".local", "share", "pnpm"),
		filepath.Join(home, ".cache", "pnpm"),
	}

	if pnpmHome := os.Getenv("PNPM_HOME"); pnpmHome != "" {
		dirs = append(dirs, pnpmHome)
	}

	if storePath := runCommand("pnpm", "store", "path"); storePath != "" {
		dirs = append(dirs, storePath)
	}

	dirs = dedup(dirs)

	var findings []Finding
	var checks []NodeModulesCheck

	for _, dir := range dirs {
		if _, err := os.Stat(dir); err != nil {
			slog.Debug("pnpm dir not found", "dir", dir)

			continue
		}

		slog.Info("scanning pnpm store", "dir", dir)
		f, c := scanStoreForPackages(dir, idx, "pnpm store")
		findings = append(findings, f...)
		checks = append(checks, c...)
	}

	return findings, checks
}

// scanStoreForPackages walks a directory looking for package.json files that
// belong to indexed packages. Used for pnpm store and nvm cache.
func scanStoreForPackages(root string, idx *rules.PackageIndex, label string) ([]Finding, []NodeModulesCheck) {
	var findings []Finding
	var checks []NodeModulesCheck

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // skip errors in WalkDir callback
		}

		if d.Name() != "package.json" {
			return nil
		}

		data, readErr := os.ReadFile(path) //nolint:gosec // walking known store dir
		if readErr != nil {
			return nil //nolint:nilerr // skip unreadable files
		}

		var pkg packageJSON
		if jsonErr := json.Unmarshal(data, &pkg); jsonErr != nil || pkg.Name == "" {
			return nil //nolint:nilerr // skip invalid package.json
		}

		vs, ok := idx.Packages[pkg.Name]
		if !ok {
			return nil
		}

		if vs.Matches(pkg.Version) {
			slog.Warn("compromised package in "+label, "package", pkg.Name, "version", pkg.Version, "path", path)
			checks = append(checks, NodeModulesCheck{Dir: root, Package: pkg.Name, Version: pkg.Version, Status: StatusFound})

			findings = append(findings, Finding{
				RuleID:      vs.RuleID,
				RuleTitle:   vs.RuleTitle,
				Severity:    vs.Severity,
				Type:        "installed_package",
				Package:     pkg.Name,
				Version:     pkg.Version,
				Description: "compromised package found in " + label,
				Path:        path,
			})
		} else {
			slog.Debug("package in "+label+" is clean", "package", pkg.Name, "version", pkg.Version)
			checks = append(checks, NodeModulesCheck{Dir: root, Package: pkg.Name, Version: pkg.Version, Status: StatusClean})
		}

		return nil
	})

	return findings, checks
}

// nvm cache and globals scanning.

// ScanNvmDirs checks nvm cache directories and nvm-managed global node_modules.
func ScanNvmDirs(idx *rules.PackageIndex) ([]Finding, []NodeModulesCheck) {
	nvmDir := os.Getenv("NVM_DIR")
	if nvmDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, nil
		}

		nvmDir = filepath.Join(home, ".nvm")
	}

	if _, err := os.Stat(nvmDir); err != nil {
		slog.Debug("nvm dir not found", "dir", nvmDir)
		return nil, nil
	}

	slog.Info("scanning nvm directory", "dir", nvmDir)

	var findings []Finding
	var checks []NodeModulesCheck

	// nvm cache directories.
	cacheDirs := []string{
		filepath.Join(nvmDir, ".cache"),
		filepath.Join(nvmDir, "src"),
		filepath.Join(nvmDir, ".cache", "src"),
	}

	for _, dir := range cacheDirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}

		slog.Info("scanning nvm cache", "dir", dir)
		f, c := scanStoreForPackages(dir, idx, "nvm cache")
		findings = append(findings, f...)
		checks = append(checks, c...)
	}

	// nvm-managed Node versions: each has its own global node_modules.
	versionsDir := filepath.Join(nvmDir, "versions")
	if _, err := os.Stat(versionsDir); err != nil {
		return findings, checks
	}

	// Find all lib/node_modules dirs under versions/
	_ = filepath.WalkDir(versionsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil //nolint:nilerr // skip errors in WalkDir
		}

		if d.Name() != "node_modules" {
			return nil
		}

		// Must be under lib/ to be a global install location.
		if filepath.Base(filepath.Dir(path)) != "lib" {
			return nil
		}

		slog.Info("scanning nvm global node_modules", "dir", path)
		f, c := scanSingleNodeModules(path, idx)
		findings = append(findings, f...)
		checks = append(checks, c...)

		return fs.SkipDir
	})

	return findings, checks
}

// npm cache scanning.

// ScanNpmCache scans the npm cache for blobs containing indexed packages.
func ScanNpmCache(idx *rules.PackageIndex) ([]Finding, []NodeModulesCheck) {
	cacheDir := runCommand("npm", "config", "get", "cache")
	if cacheDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, nil
		}

		cacheDir = filepath.Join(home, ".npm")
	}

	if _, err := os.Stat(cacheDir); err != nil {
		slog.Debug("npm cache not found", "dir", cacheDir)
		return nil, nil
	}

	slog.Info("scanning npm cache", "dir", cacheDir)

	var lookups []cacheLookup

	for name, vs := range idx.Packages {
		l := cacheLookup{
			name:      name,
			nameBytes: []byte(name),
			vs:        vs,
		}

		// Collect version strings to search for.
		if vs.AnyVersion {
			// For dropper/wildcard packages, just finding the name is enough.
			l.versions = nil
		} else {
			for v := range vs.Versions {
				l.versions = append(l.versions, []byte(v))
			}
		}

		lookups = append(lookups, l)
	}

	var findings []Finding
	var checks []NodeModulesCheck

	// Scan both index and content directories.
	scanDirs := []string{
		filepath.Join(cacheDir, "_cacache", "index-v5"),
		filepath.Join(cacheDir, "_cacache", "content-v2"),
	}

	for _, dir := range scanDirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}

		slog.Info("scanning npm cache dir", "dir", dir)
		f, c := scanCacheBlobs(dir, lookups)
		findings = append(findings, f...)
		checks = append(checks, c...)
	}

	return findings, checks
}

func scanCacheBlobs(dir string, lookups []cacheLookup) ([]Finding, []NodeModulesCheck) {
	var findings []Finding
	var checks []NodeModulesCheck
	blobCount := 0

	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // skip errors in WalkDir callback
		}

		blobCount++
		if blobCount%cacheProgressInterval == 0 {
			slog.Info("npm cache scan progress", "blobs", blobCount)
		}

		data, readErr := os.ReadFile(path) //nolint:gosec // walking known cache dir
		if readErr != nil {
			return nil //nolint:nilerr // skip unreadable files
		}

		f, c := matchBlobAgainstIndex(data, path, dir, lookups)
		findings = append(findings, f...)
		checks = append(checks, c...)

		return nil
	})

	if blobCount > 0 {
		slog.Info("npm cache scan complete", "dir", dir, "blobs_scanned", blobCount)
	}

	return findings, checks
}

func matchBlobAgainstIndex(data []byte, path, dir string, lookups []cacheLookup) ([]Finding, []NodeModulesCheck) {
	var findings []Finding
	var checks []NodeModulesCheck

	for i := range lookups {
		l := &lookups[i]

		if !bytes.Contains(data, l.nameBytes) {
			continue
		}

		if l.vs.AnyVersion {
			slog.Warn("indexed package found in npm cache", "package", l.name, "blob", path)
			checks = append(checks, NodeModulesCheck{Dir: dir, Package: l.name, Status: StatusFound})
			findings = append(findings, Finding{
				RuleID: l.vs.RuleID, RuleTitle: l.vs.RuleTitle, Severity: l.vs.Severity,
				Type: "cached_package", Package: l.name,
				Description: "indexed package found in npm cache", Path: path,
			})

			break
		}

		for _, verBytes := range l.versions {
			if !bytes.Contains(data, verBytes) {
				continue
			}

			ver := string(verBytes)
			slog.Warn("compromised version in npm cache", "package", l.name, "version", ver, "blob", path)
			checks = append(checks, NodeModulesCheck{Dir: dir, Package: l.name, Version: ver, Status: StatusFound})
			findings = append(findings, Finding{
				RuleID: l.vs.RuleID, RuleTitle: l.vs.RuleTitle, Severity: l.vs.Severity,
				Type: "cached_package", Package: l.name, Version: ver,
				Description: "compromised version in npm cache", Path: path,
			})

			break
		}
	}

	return findings, checks
}

// Helpers.

func dedup(items []string) []string {
	seen := make(map[string]bool, len(items))
	var result []string

	for _, item := range items {
		if item != "" && !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}
