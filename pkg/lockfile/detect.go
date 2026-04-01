package lockfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// DetectAndParse finds lockfiles in the given directory and parses each one.
func DetectAndParse(dir string) ([]Result, error) {
	lockfiles := []struct {
		name   string
		parser func(string) ([]PackageEntry, error)
	}{
		{"pnpm-lock.yaml", ParsePnpmLock},
		{"package-lock.json", ParsePackageLockJSON},
		{"yarn.lock", ParseYarnLock},
	}

	results := make([]Result, 0, len(lockfiles))

	for _, lf := range lockfiles {
		path := filepath.Join(dir, lf.name)
		if _, err := os.Stat(path); err != nil {
			continue
		}

		entries, err := lf.parser(path)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", lf.name, err)
		}

		results = append(results, Result{Name: lf.name, Entries: entries})
	}

	return results, nil
}

// ParseFile parses a specific lockfile by path, auto-detecting format from filename.
func ParseFile(path string) (*Result, error) {
	base := filepath.Base(path)

	var parser func(string) ([]PackageEntry, error)

	switch base {
	case "pnpm-lock.yaml":
		parser = ParsePnpmLock
	case "package-lock.json":
		parser = ParsePackageLockJSON
	case "yarn.lock":
		parser = ParseYarnLock
	default:
		return nil, fmt.Errorf("unknown lockfile format: %s", base)
	}

	entries, err := parser(path)
	if err != nil {
		return nil, err
	}

	return &Result{Name: base, Entries: entries}, nil
}
