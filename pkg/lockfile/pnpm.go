package lockfile

import (
	"fmt"
	"os"
	"strings"

	"github.com/goccy/go-yaml"
)

// pnpmLockfile represents the subset of pnpm-lock.yaml we need to parse.
// Using a proper YAML library makes this robust against formatting changes,
// comment variations, and future pnpm lock format evolution — as long as
// the packages/snapshots map keys keep the same naming convention.
type pnpmLockfile struct {
	Packages  yaml.MapSlice `yaml:"packages"`
	Snapshots yaml.MapSlice `yaml:"snapshots"`
}

// ParsePnpmLock parses a pnpm-lock.yaml using a YAML library.
// It extracts package names and versions from the packages: and snapshots: sections.
//
// Supported formats:
//   - pnpm v6-v8: keys like "/axios@1.7.8" or "/axios/1.7.8"
//   - pnpm v9: keys like "axios@1.7.8" (no leading /)
func ParsePnpmLock(path string) ([]PackageEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	var lock pnpmLockfile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	seen := make(map[string]bool)
	var entries []PackageEntry

	entries = extractFromMapSlice(lock.Packages, entries, seen)
	entries = extractFromMapSlice(lock.Snapshots, entries, seen)

	return entries, nil
}

// extractFromMapSlice iterates over a yaml.MapSlice (preserving key order)
// and extracts PackageEntry values from the map keys.
func extractFromMapSlice(ms yaml.MapSlice, entries []PackageEntry, seen map[string]bool) []PackageEntry {
	for _, item := range ms {
		key, ok := item.Key.(string)
		if !ok {
			continue
		}

		// Strip leading / (pnpm v6-v8).
		key = strings.TrimPrefix(key, "/")

		name, version := splitPackageKey(key)
		if name == "" || version == "" {
			continue
		}

		dedupKey := name + "@" + version
		if seen[dedupKey] {
			continue
		}

		seen[dedupKey] = true
		entries = append(entries, PackageEntry{Name: name, Version: version})
	}

	return entries
}

// splitPackageKey extracts the package name and version from a pnpm lockfile key.
//
// Handled formats:
//
//	"axios@1.7.8"           -> ("axios", "1.7.8")
//	"@scope/pkg@1.0.0"      -> ("@scope/pkg", "1.0.0")
//	"axios/1.7.8"           -> ("axios", "1.7.8")       [pnpm v6]
//	"@scope/pkg/1.0.0"      -> ("@scope/pkg", "1.0.0")  [pnpm v6]
//	"axios@1.7.8(peer@2.0)" -> ("axios", "1.7.8")       [pnpm v9 peer suffix]
func splitPackageKey(key string) (name, version string) {
	// Strip pnpm v9 peer dependency suffix.
	if idx := strings.Index(key, "("); idx > 0 {
		key = key[:idx]
	}

	// Try @ separator (skip position 0 which is @ for scoped packages).
	if idx := strings.LastIndex(key, "@"); idx > 0 {
		return key[:idx], key[idx+1:]
	}

	// Try / separator for pnpm v6 format.
	if idx := strings.LastIndex(key, "/"); idx > 0 {
		candidate := key[idx+1:]
		if candidate != "" && candidate[0] >= '0' && candidate[0] <= '9' {
			return key[:idx], candidate
		}
	}

	return "", ""
}
