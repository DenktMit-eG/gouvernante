package lockfile

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// npmLockfile represents the structure of a package-lock.json file.
type npmLockfile struct {
	Packages     map[string]npmPackage    `json:"packages"`
	Dependencies map[string]npmDependency `json:"dependencies"`
}

// npmPackage is a single entry in the v2/v3 flat packages map.
type npmPackage struct {
	Version string `json:"version"`
}

// npmDependency is a single entry in the v1 nested dependencies tree.
type npmDependency struct {
	Version      string                   `json:"version"`
	Dependencies map[string]npmDependency `json:"dependencies"`
}

// ParsePackageLockJSON parses npm's package-lock.json (v1, v2, and v3 formats).
func ParsePackageLockJSON(path string) ([]PackageEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	var lock npmLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	// v2/v3: flat packages map.
	if len(lock.Packages) > 0 {
		return parseNpmV2Packages(lock.Packages), nil
	}

	// v1 fallback: nested dependencies.
	return parseNpmV1Dependencies(lock.Dependencies), nil
}

// parseNpmV2Packages extracts entries from the v2/v3 flat packages map.
func parseNpmV2Packages(packages map[string]npmPackage) []PackageEntry {
	seen := make(map[string]bool, len(packages))
	entries := make([]PackageEntry, 0, len(packages))

	for key, pkg := range packages {
		if key == "" || pkg.Version == "" {
			continue
		}

		name := extractPackageName(key)
		if name == "" {
			continue
		}

		dedupKey := name + "@" + pkg.Version
		if seen[dedupKey] {
			continue
		}

		seen[dedupKey] = true
		entries = append(entries, PackageEntry{Name: name, Version: pkg.Version})
	}

	return entries
}

// parseNpmV1Dependencies recursively extracts entries from v1 nested dependencies.
func parseNpmV1Dependencies(deps map[string]npmDependency) []PackageEntry {
	seen := make(map[string]bool)
	var entries []PackageEntry

	var walk func(map[string]npmDependency)
	walk = func(d map[string]npmDependency) {
		for name, dep := range d {
			if dep.Version == "" {
				continue
			}

			dedupKey := name + "@" + dep.Version
			if !seen[dedupKey] {
				seen[dedupKey] = true
				entries = append(entries, PackageEntry{Name: name, Version: dep.Version})
			}

			if len(dep.Dependencies) > 0 {
				walk(dep.Dependencies)
			}
		}
	}

	walk(deps)

	return entries
}

// extractPackageName extracts the package name from a packages map key.
// Keys look like "node_modules/axios", "node_modules/@scope/pkg",
// or nested like "node_modules/foo/node_modules/bar".
func extractPackageName(key string) string {
	const prefix = "node_modules/"

	idx := strings.LastIndex(key, prefix)
	if idx < 0 {
		return ""
	}

	return key[idx+len(prefix):]
}
