package lockfile

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
)

// lockfileFormats maps known lockfile names to their parsers.
const packageJSONName = "package.json"

// lockfileFormats lists recognized lockfile names and their parsers.
// The ecosystem map in pkg/rules/rules.go also includes bun entries
// for forward-compatible filtering; add a parser here when bun support lands.
var lockfileFormats = []struct {
	name   string
	parser func(string) ([]PackageEntry, error)
}{
	{"pnpm-lock.yaml", ParsePnpmLock},
	{"package-lock.json", ParsePackageLockJSON},
	{"yarn.lock", ParseYarnLock},
	{packageJSONName, ParsePackageJSON},
}

// skipDirs are directories that should not be traversed during recursive scanning.
var skipDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	"vendor":       true,
	"dist":         true,
	".next":        true,
	"__pycache__":  true,
}

// dirProgressInterval controls how often directory count is logged at Info level.
const dirProgressInterval = 500

// DetectAndParse finds lockfiles in the given directory and parses each one.
func DetectAndParse(dir string) ([]Result, error) {
	results := make([]Result, 0, len(lockfileFormats))

	for _, lf := range lockfileFormats {
		path := filepath.Join(dir, lf.name)
		if _, err := os.Stat(path); err != nil {
			continue
		}

		entries, err := lf.parser(path)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", lf.name, err)
		}

		results = append(results, Result{Name: lf.name, Path: path, Entries: entries})
	}

	return results, nil
}

// DetectAndParseRecursive walks the directory tree rooted at root and parses
// every lockfile found. Directories like node_modules, .git, and vendor are
// skipped. Each Result.Name is the relative path from root.
func DetectAndParseRecursive(root string) ([]Result, error) {
	w := &recursiveWalker{
		root:    root,
		parsers: buildParserMap(),
	}

	err := filepath.WalkDir(root, w.visit)
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", root, err)
	}

	slog.Info("recursive scan complete",
		"directories", w.dirCount,
		"lockfiles", len(w.results))

	return w.results, nil
}

// recursiveWalker accumulates lockfile parse results while walking a directory tree.
type recursiveWalker struct {
	root     string
	parsers  map[string]func(string) ([]PackageEntry, error)
	results  []Result
	dirCount int
}

// buildParserMap converts the lockfileFormats slice into a map keyed by filename
// for O(1) lookup during directory walking.
func buildParserMap() map[string]func(string) ([]PackageEntry, error) {
	m := make(map[string]func(string) ([]PackageEntry, error), len(lockfileFormats))
	for _, lf := range lockfileFormats {
		m[lf.name] = lf.parser
	}

	return m
}

// visit is the filepath.WalkDir callback that dispatches to visitDir or visitFile.
func (w *recursiveWalker) visit(path string, d fs.DirEntry, err error) error {
	if err != nil {
		return handleWalkError(path, d, err)
	}

	if d.IsDir() {
		return w.visitDir(path, d)
	}

	return w.visitFile(path, d)
}

// handleWalkError skips unreadable directories and ignores file-level errors.
func handleWalkError(path string, d fs.DirEntry, err error) error {
	if d != nil && d.IsDir() {
		slog.Warn("skipping unreadable directory", "path", path, "error", err)
		return fs.SkipDir
	}

	return nil
}

// visitDir skips excluded directories (node_modules, .git, etc.) and logs progress.
func (w *recursiveWalker) visitDir(path string, d fs.DirEntry) error {
	if skipDirs[d.Name()] {
		return fs.SkipDir
	}

	w.dirCount++

	slog.Debug("scanning directory", "path", relPath(w.root, path))

	if w.dirCount%dirProgressInterval == 0 {
		slog.Info("scan progress", "directories", w.dirCount)
	}

	return nil
}

// visitFile checks whether the file is a known lockfile format and parses it.
func (w *recursiveWalker) visitFile(path string, d fs.DirEntry) error {
	parser, ok := w.parsers[d.Name()]
	if !ok {
		return nil
	}

	rel := relPath(w.root, path)

	slog.Debug("found lockfile", "path", rel)

	entries, err := parser(path)
	if err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}

	w.results = append(w.results, Result{Name: rel, Path: path, Entries: entries})

	return nil
}

// relPath returns path relative to root, falling back to the absolute path on error.
func relPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}

	return rel
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
	case packageJSONName:
		parser = ParsePackageJSON
	default:
		return nil, fmt.Errorf("unknown lockfile format: %s", base)
	}

	entries, err := parser(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", base, err)
	}

	return &Result{Name: base, Path: path, Entries: entries}, nil
}
