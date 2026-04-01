package lockfile

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// projectPackageJSON represents the dependency sections of a package.json file.
type projectPackageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// ParsePackageJSON reads a package.json and extracts dependencies and
// devDependencies as PackageEntry values. Version range specifiers (^, ~, >=)
// are passed through as-is — they won't match exact versions in the rule index,
// but dropper packages (AnyVersion) will still be caught by name.
func ParsePackageJSON(path string) ([]PackageEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	var pkg projectPackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	entries := make([]PackageEntry, 0, len(pkg.Dependencies)+len(pkg.DevDependencies))

	for name, version := range pkg.Dependencies {
		entries = append(entries, PackageEntry{
			Name:    name,
			Version: normalizeVersion(version),
		})
	}

	for name, version := range pkg.DevDependencies {
		entries = append(entries, PackageEntry{
			Name:    name,
			Version: normalizeVersion(version),
		})
	}

	return entries, nil
}

// normalizeVersion strips common prefixes that don't affect exact matching.
// "v1.14.1" → "1.14.1", "=1.14.1" → "1.14.1".
// Range specifiers (^, ~, >=, etc.) are left intact — they won't match
// exact versions in the index, which is the correct behavior.
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "=")

	return v
}
