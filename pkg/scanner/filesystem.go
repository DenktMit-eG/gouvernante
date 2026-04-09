package scanner

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"gouvernante/pkg/rules"
)

// OS constants for platform-specific path resolution.
const (
	osLinux   = "linux"
	osDarwin  = "darwin"
	osWindows = "windows"
)

// packageJSON is the minimal structure read from a package.json to extract name and version.
type packageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// NodeModulesCheck records the result of checking one package in a directory.
type NodeModulesCheck struct {
	// Dir is the node_modules or store directory that was checked.
	Dir string
	// Package is the npm package name.
	Package string
	// Version is the installed version (empty when Status is StatusNotInstalled).
	Version string
	// Status is the check outcome: StatusFound, StatusClean, or StatusNotInstalled.
	Status string
}

// cacheProgressInterval controls how often progress is logged during cache scanning.
const cacheProgressInterval = 500

// cacheLookup holds precomputed byte slices for fast cache blob searching.
type cacheLookup struct {
	name      string
	nameBytes []byte
	vsList    []*rules.VersionSet
}

// Global npm modules.

// userHomeDir is the function used to resolve the user's home directory.
// Replaced in tests to simulate errors.
var userHomeDir = os.UserHomeDir

// globalNodeModulesPaths returns global node_modules locations using environment
// variables and well-known paths. No external binaries are executed.
func globalNodeModulesPaths() []string {
	return globalNodeModulesPathsForOS(runtime.GOOS)
}

// globalNodeModulesPathsForOS returns global node_modules locations for the given OS.
func globalNodeModulesPathsForOS(goos string) []string {
	var paths []string

	// Check NPM_CONFIG_PREFIX env var (equivalent to `npm config get prefix`).
	if prefix := os.Getenv("NPM_CONFIG_PREFIX"); prefix != "" {
		nmPath := filepath.Join(prefix, "lib", "node_modules")
		slog.Info("npm prefix from env", "prefix", prefix, "node_modules", nmPath)
		paths = append(paths, nmPath)
	}

	// Well-known paths per OS.
	switch goos {
	case osLinux:
		paths = append(paths, "/usr/lib/node_modules", "/usr/local/lib/node_modules")
	case osDarwin:
		paths = append(paths, "/usr/local/lib/node_modules", "/opt/homebrew/lib/node_modules")
	case osWindows:
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

// scanSingleNodeModules walks the installed packages in nmDir and checks each
// against the rule index. This is install-tree driven: it enumerates what is
// actually on disk (O(installed)) and does O(1) index lookups, rather than
// probing the filesystem for every indexed package name (O(rules)).
func scanSingleNodeModules(nmDir string, idx *rules.PackageIndex) ([]Finding, []NodeModulesCheck) {
	var findings []Finding
	var checks []NodeModulesCheck

	for _, pkgName := range listInstalledPackages(nmDir) {
		vsList := idx.Packages[pkgName]
		if len(vsList) == 0 {
			continue // not in the rule index
		}

		version, err := readInstalledVersion(nmDir, pkgName)
		if err != nil {
			slog.Debug("cannot read version", "dir", nmDir, "package", pkgName, "error", err)

			continue
		}

		matched := false

		for _, vs := range vsList {
			if vs.Matches(version) {
				slog.Warn("compromised package installed", "dir", nmDir, "package", pkgName, "version", version, "rule", vs.RuleID)
				checks = append(checks, NodeModulesCheck{Dir: nmDir, Package: pkgName, Version: version, Status: StatusFound})

				findings = append(findings, Finding{
					RuleID:      vs.RuleID,
					RuleTitle:   vs.RuleTitle,
					Severity:    vs.Severity,
					Type:        TypeInstalledPackage,
					Package:     pkgName,
					Version:     version,
					Description: "compromised package found in " + nmDir,
					Path:        filepath.Join(nmDir, pkgName),
				})

				matched = true
			}
		}

		if !matched {
			slog.Info("package installed, version clean", "dir", nmDir, "package", pkgName, "version", version)
			checks = append(checks, NodeModulesCheck{Dir: nmDir, Package: pkgName, Version: version, Status: StatusClean})
		}
	}

	return findings, checks
}

// listInstalledPackages reads the node_modules directory and returns all installed
// package names, including scoped packages (@scope/pkg). Unreadable entries are skipped.
func listInstalledPackages(nmDir string) []string {
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

		// Scoped packages: @scope/ contains subdirectories for each package.
		if strings.HasPrefix(name, "@") {
			scopeDir := filepath.Join(nmDir, name)

			scopeEntries, scopeErr := os.ReadDir(scopeDir)
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

		// Skip hidden directories (.cache, .bin, etc.).
		if strings.HasPrefix(name, ".") {
			continue
		}

		pkgs = append(pkgs, name)
	}

	return pkgs
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
	dirs := pnpmStorePaths(runtime.GOOS)
	if len(dirs) == 0 {
		return nil, nil
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
		if err != nil {
			slog.Warn("scan warning in "+label, "path", path, "error", err)

			return nil //nolint:nilerr // skip errors in WalkDir callback
		}

		if d.IsDir() {
			return nil
		}

		if d.Name() != "package.json" {
			return nil
		}

		data, readErr := os.ReadFile(path) //nolint:gosec // walking known store dir
		if readErr != nil {
			slog.Warn("unreadable file in "+label, "path", path, "error", readErr)

			return nil //nolint:nilerr // skip unreadable files
		}

		var pkg packageJSON
		if jsonErr := json.Unmarshal(data, &pkg); jsonErr != nil || pkg.Name == "" {
			return nil //nolint:nilerr // skip invalid package.json
		}

		vsList := idx.Packages[pkg.Name]
		if len(vsList) == 0 {
			return nil
		}

		matched := false

		for _, vs := range vsList {
			if vs.Matches(pkg.Version) {
				slog.Warn("compromised package in "+label, "package", pkg.Name, "version", pkg.Version, "path", path, "rule", vs.RuleID)
				checks = append(checks, NodeModulesCheck{Dir: root, Package: pkg.Name, Version: pkg.Version, Status: StatusFound})

				findings = append(findings, Finding{
					RuleID:      vs.RuleID,
					RuleTitle:   vs.RuleTitle,
					Severity:    vs.Severity,
					Type:        TypeInstalledPackage,
					Package:     pkg.Name,
					Version:     pkg.Version,
					Description: "compromised package found in " + label,
					Path:        path,
				})

				matched = true
			}
		}

		if !matched {
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
	nvmDir := nvmDirPath(runtime.GOOS)
	if nvmDir == "" {
		return nil, nil
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
		if err != nil {
			slog.Warn("scan warning in nvm versions", "path", path, "error", err)

			return nil //nolint:nilerr // skip errors in WalkDir
		}

		if !d.IsDir() {
			return nil
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
// Uses NPM_CONFIG_CACHE env var or the well-known platform-specific path.
func ScanNpmCache(idx *rules.PackageIndex) ([]Finding, []NodeModulesCheck) {
	cacheDir := npmCachePath()
	if cacheDir == "" {
		return nil, nil
	}

	if _, err := os.Stat(cacheDir); err != nil {
		slog.Debug("npm cache not found", "dir", cacheDir)
		return nil, nil
	}

	slog.Info("scanning npm cache", "dir", cacheDir)

	lookups := make([]cacheLookup, 0, len(idx.Packages))

	for name, vsList := range idx.Packages {
		l := cacheLookup{
			name:      name,
			nameBytes: []byte(name),
			vsList:    vsList,
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

// scanCacheBlobs walks dir reading each file and checking its contents
// against the indexed package names and versions.
func scanCacheBlobs(dir string, lookups []cacheLookup) ([]Finding, []NodeModulesCheck) {
	var findings []Finding
	var checks []NodeModulesCheck
	blobCount := 0

	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			slog.Warn("scan warning in npm cache", "path", path, "error", err)

			return nil //nolint:nilerr // skip errors in WalkDir callback
		}

		if d.IsDir() {
			return nil
		}

		blobCount++
		if blobCount%cacheProgressInterval == 0 {
			slog.Info("npm cache scan progress", "blobs", blobCount)
		}

		data, readErr := os.ReadFile(path) //nolint:gosec // walking known cache dir
		if readErr != nil {
			slog.Warn("unreadable blob in npm cache", "path", path, "error", readErr)

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

// versionProximity is the maximum distance (in bytes) after a package name
// match to search for version strings.
const versionProximity = 100

// semverPattern matches version-like strings (e.g., 1.14.1, 0.30.4, 1.0.0-beta.1).
// Uses structured optional groups for prerelease (-beta.1) and build metadata (+build).
// Does NOT greedily consume file extensions like .tgz.
var semverPattern = regexp.MustCompile(`\d+\.\d+\.\d+(?:-[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*)?(?:\+[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*)?`)

// matchBlobAgainstIndex searches a single cache blob for indexed package names.
// When a name is found at a word boundary, it extracts nearby version strings
// and checks them against the rule index.
func matchBlobAgainstIndex(data []byte, path, dir string, lookups []cacheLookup) ([]Finding, []NodeModulesCheck) {
	var findings []Finding
	var checks []NodeModulesCheck

	for i := range lookups {
		l := &lookups[i]

		namePos := findPackageNameWithBoundary(data, l.nameBytes)
		if namePos < 0 {
			continue
		}

		for _, vs := range l.vsList {
			if vs.AnyVersion {
				slog.Warn("indexed package found in npm cache", "package", l.name, "blob", path, "rule", vs.RuleID)
				checks = append(checks, NodeModulesCheck{Dir: dir, Package: l.name, Status: StatusFound})
				findings = append(findings, Finding{
					RuleID: vs.RuleID, RuleTitle: vs.RuleTitle, Severity: vs.Severity,
					Type: TypeCachedPackage, Package: l.name,
					Description: "indexed package found in npm cache", Path: path,
				})

				continue
			}

			// Extract version-like strings from the proximity window and check against the index.
			window := proximityWindow(data, namePos, len(l.nameBytes))
			versions := semverPattern.FindAll(window, -1)

			for _, verBytes := range versions {
				ver := string(verBytes)
				if !vs.Matches(ver) {
					continue
				}

				slog.Warn("compromised version in npm cache", "package", l.name, "version", ver, "blob", path, "rule", vs.RuleID)
				checks = append(checks, NodeModulesCheck{Dir: dir, Package: l.name, Version: ver, Status: StatusFound})
				findings = append(findings, Finding{
					RuleID: vs.RuleID, RuleTitle: vs.RuleTitle, Severity: vs.Severity,
					Type: TypeCachedPackage, Package: l.name, Version: ver,
					Description: "compromised version in npm cache", Path: path,
				})

				break
			}
		}
	}

	return findings, checks
}

// findPackageNameWithBoundary searches for a package name in data, ensuring
// the match is at a word boundary. This prevents "atrix" from matching inside
// "dommatrix". Boundary characters: start of data, ", /, @, whitespace, :.
func findPackageNameWithBoundary(data, name []byte) int {
	offset := 0

	for {
		pos := bytes.Index(data[offset:], name)
		if pos < 0 {
			return -1
		}

		absPos := offset + pos

		// Check left boundary.
		leftOK := absPos == 0 || isBoundaryChar(data[absPos-1])

		// Check right boundary.
		endPos := absPos + len(name)
		rightOK := endPos >= len(data) || isBoundaryChar(data[endPos])

		if leftOK && rightOK {
			return absPos
		}

		offset = absPos + 1
	}
}

// isBoundaryChar reports whether c is a character that can appear immediately
// before or after a package name in JSON, lockfile, or URL contexts.
func isBoundaryChar(c byte) bool {
	switch c {
	case '"', '/', '@', ':', ' ', '\t', '\n', '\r', ',', '{', '}', '[', ']':
		return true
	default:
		return false
	}
}

// proximityWindow returns the slice of data starting at namePos and extending
// up to versionProximity bytes past the end of the name match.
func proximityWindow(data []byte, namePos, nameLen int) []byte {
	end := namePos + nameLen + versionProximity
	if end > len(data) {
		end = len(data)
	}

	return data[namePos:end]
}

// nvmDirPath returns the nvm directory for the given OS, checking environment
// variables and falling back to well-known paths.
func nvmDirPath(goos string) string {
	if dir := os.Getenv("NVM_DIR"); dir != "" {
		return dir
	}

	if goos == osWindows {
		if dir := os.Getenv("NVM_HOME"); dir != "" {
			return dir
		}
	}

	home, err := userHomeDir()
	if err != nil {
		return ""
	}

	if goos == osWindows {
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			return filepath.Join(appdata, "nvm")
		}

		return filepath.Join(home, "AppData", "Roaming", "nvm")
	}

	return filepath.Join(home, ".nvm")
}

// pnpmStorePaths returns pnpm store and cache directories for the given OS.
func pnpmStorePaths(goos string) []string {
	home, err := userHomeDir()
	if err != nil {
		slog.Debug("cannot determine home dir for pnpm scan")
		return nil
	}

	var dirs []string

	switch goos {
	case osWindows:
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			dirs = append(dirs, filepath.Join(localAppData, "pnpm"), filepath.Join(localAppData, "pnpm-store"))
		}
	default:
		dirs = append(dirs,
			filepath.Join(home, ".local", "share", "pnpm"),
			filepath.Join(home, ".cache", "pnpm"),
		)
	}

	if pnpmHome := os.Getenv("PNPM_HOME"); pnpmHome != "" {
		dirs = append(dirs, pnpmHome)
	}

	return dedup(dirs)
}

// npmCachePath returns the npm cache directory using NPM_CONFIG_CACHE env var
// or the well-known platform-specific default path.
func npmCachePath() string {
	return npmCachePathForOS(runtime.GOOS)
}

// npmCachePathForOS returns the npm cache directory for the given OS.
func npmCachePathForOS(goos string) string {
	if cache := os.Getenv("NPM_CONFIG_CACHE"); cache != "" {
		return cache
	}

	if goos == osWindows {
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			return filepath.Join(localAppData, "npm-cache")
		}

		return ""
	}

	home, err := userHomeDir()
	if err != nil {
		return ""
	}

	return filepath.Join(home, ".npm")
}

// Helpers.

// dedup returns items with duplicates and empty strings removed, preserving order.
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
