package lockfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestDetectAndParse_MultipleFormats(t *testing.T) {
	dir := t.TempDir()

	// Write a pnpm lockfile.
	pnpmContent := `lockfileVersion: '9.0'

packages:
  axios@1.7.9:
    resolution: {integrity: sha512-fake}
`
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(pnpmContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Write an npm lockfile.
	npmContent := `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "test", "version": "1.0.0" },
    "node_modules/express": { "version": "4.18.2" }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(npmContent), 0o600); err != nil {
		t.Fatal(err)
	}

	results, err := DetectAndParse(dir)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 lockfile results, got %d", len(results))
	}

	// Verify both lockfiles contributed entries.
	totalEntries := 0
	for _, r := range results {
		totalEntries += len(r.Entries)
	}

	if totalEntries != 2 {
		t.Errorf("expected 2 total entries, got %d", totalEntries)
	}
}

func TestDetectAndParse_NoLockfiles(t *testing.T) {
	dir := t.TempDir()

	results, err := DetectAndParse(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

// Recursive scanning tests.

func TestDetectAndParseRecursive_FindsNested(t *testing.T) {
	root := t.TempDir()

	// Root-level lockfile.
	pnpmContent := `lockfileVersion: '9.0'

packages:
  axios@1.7.9:
    resolution: {integrity: sha512-fake}
`
	if err := os.WriteFile(filepath.Join(root, "pnpm-lock.yaml"), []byte(pnpmContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Nested lockfile in subdirectory.
	subDir := filepath.Join(root, "apps", "frontend")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}

	npmContent := `{
  "name": "frontend",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "frontend", "version": "1.0.0" },
    "node_modules/express": { "version": "4.18.2" }
  }
}`
	if err := os.WriteFile(filepath.Join(subDir, "package-lock.json"), []byte(npmContent), 0o600); err != nil {
		t.Fatal(err)
	}

	results, err := DetectAndParseRecursive(root)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Collect result names.
	names := make(map[string]bool)
	for _, r := range results {
		names[r.Name] = true
	}

	if !names["pnpm-lock.yaml"] {
		t.Error("missing pnpm-lock.yaml at root")
	}

	wantNested := filepath.Join("apps", "frontend", "package-lock.json")
	if !names[wantNested] {
		t.Errorf("missing nested lockfile, got names: %v", names)
	}
}

func TestDetectAndParseRecursive_SkipsDirs(t *testing.T) {
	root := t.TempDir()

	// Lockfile inside node_modules — should be skipped.
	nmDir := filepath.Join(root, "node_modules", "some-pkg")
	if err := os.MkdirAll(nmDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(nmDir, "package-lock.json"), []byte(`{"name":"x","lockfileVersion":3,"packages":{"":{"name":"x","version":"1.0.0"},"node_modules/y":{"version":"2.0.0"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Lockfile inside .git — should be skipped.
	gitDir := filepath.Join(root, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(gitDir, "yarn.lock"), []byte("# fake\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	results, err := DetectAndParseRecursive(root)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(results) != 0 {
		names := make([]string, 0, len(results))
		for _, r := range results {
			names = append(names, r.Name)
		}

		t.Errorf("expected 0 results (skipped dirs), got %d: %v", len(results), names)
	}
}

func TestDetectAndParseRecursive_EmptyTree(t *testing.T) {
	root := t.TempDir()

	results, err := DetectAndParseRecursive(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestParseFile_UnknownFormat(t *testing.T) {
	path := writeTempFile(t, "unknown.lock", "content")

	_, err := ParseFile(path)
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestParseFile_NpmDirect(t *testing.T) {
	path := writeTempFile(t, "package-lock.json", `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "test", "version": "1.0.0" },
    "node_modules/axios": { "version": "1.7.8" }
  }
}`)

	result, err := ParseFile(path)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if result.Name != "package-lock.json" {
		t.Errorf("expected name package-lock.json, got %s", result.Name)
	}

	if len(result.Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(result.Entries))
	}
}

func TestParseFile_YarnDirect(t *testing.T) {
	path := writeTempFile(t, "yarn.lock", `# yarn lockfile v1

axios@^1.7.0:
  version "1.7.8"
  resolved "https://registry.yarnpkg.com/axios/-/axios-1.7.8.tgz#fake"
`)

	result, err := ParseFile(path)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if result.Name != "yarn.lock" {
		t.Errorf("expected name yarn.lock, got %s", result.Name)
	}

	if len(result.Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(result.Entries))
	}
}

func TestParseFile_PnpmDirect(t *testing.T) {
	path := writeTempFile(t, "pnpm-lock.yaml", `lockfileVersion: '9.0'

packages:
  axios@1.7.9:
    resolution: {integrity: sha512-fake}
`)

	result, err := ParseFile(path)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if result.Name != "pnpm-lock.yaml" {
		t.Errorf("expected name pnpm-lock.yaml, got %s", result.Name)
	}

	if len(result.Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(result.Entries))
	}
}

// handleWalkError tests.

// fakeDirEntry implements fs.DirEntry for testing.
type fakeDirEntry struct {
	name  string
	isDir bool
}

func (f *fakeDirEntry) Name() string               { return f.name }
func (f *fakeDirEntry) IsDir() bool                { return f.isDir }
func (f *fakeDirEntry) Type() fs.FileMode          { return 0 }
func (f *fakeDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

func TestHandleWalkError_DirEntry(t *testing.T) {
	d := &fakeDirEntry{name: "baddir", isDir: true}
	err := handleWalkError("/some/path", d, fmt.Errorf("permission denied"))

	if !errors.Is(err, fs.SkipDir) {
		t.Errorf("expected fs.SkipDir, got %v", err)
	}
}

func TestHandleWalkError_NonDirEntry(t *testing.T) {
	d := &fakeDirEntry{name: "badfile.txt", isDir: false}
	err := handleWalkError("/some/path", d, fmt.Errorf("permission denied"))
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestHandleWalkError_NilDirEntry(t *testing.T) {
	err := handleWalkError("/some/path", nil, fmt.Errorf("permission denied"))
	if err != nil {
		t.Errorf("expected nil for nil DirEntry, got %v", err)
	}
}

// relPath tests.

func TestRelPath_Success(t *testing.T) {
	got := relPath("/root", "/root/sub/file.txt")
	want := filepath.Join("sub", "file.txt")

	if got != want {
		t.Errorf("relPath() = %q, want %q", got, want)
	}
}

func TestRelPath_SamePath(t *testing.T) {
	got := relPath("/root", "/root")
	if got != "." {
		t.Errorf("relPath() = %q, want %q", got, ".")
	}
}

// ParseFile with package.json.

func TestParseFile_PackageJSON(t *testing.T) {
	path := writeTempFile(t, "package.json", `{
  "dependencies": {
    "express": "^4.18.0"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}`)

	result, err := ParseFile(path)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if result.Name != "package.json" {
		t.Errorf("expected name package.json, got %s", result.Name)
	}

	if len(result.Entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(result.Entries))
	}
}

// DetectAndParse with package.json.

func TestDetectAndParse_PackageJSON(t *testing.T) {
	dir := t.TempDir()

	content := `{
  "dependencies": {
    "lodash": "^4.17.0"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	results, err := DetectAndParse(dir)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Name != "package.json" {
		t.Errorf("expected name package.json, got %s", results[0].Name)
	}

	if len(results[0].Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(results[0].Entries))
	}
}

// DetectAndParse with invalid lockfile.

func TestDetectAndParse_InvalidLockfile(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{invalid json}"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := DetectAndParse(dir)
	if err == nil {
		t.Fatal("expected error for invalid lockfile")
	}
}

// DetectAndParseRecursive with unreadable directory.

func TestDetectAndParseRecursive_UnreadableDir(t *testing.T) {
	root := t.TempDir()

	// Create a subdirectory that we'll make unreadable.
	subDir := filepath.Join(root, "restricted")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Put a lockfile inside.
	content := `lockfileVersion: '9.0'
packages:
  axios@1.0.0:
    resolution: {integrity: sha512-fake}
`
	if err := os.WriteFile(filepath.Join(subDir, "pnpm-lock.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	// Remove read+execute permission so WalkDir can't enter it.
	if err := os.Chmod(subDir, 0o000); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = os.Chmod(subDir, 0o755)
	})

	// Should not fail — just skip the unreadable directory.
	results, err := DetectAndParseRecursive(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The lockfile in the restricted dir should not have been found.
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

// DetectAndParseRecursive with deep tree to trigger progress logging.

func TestDetectAndParseRecursive_DeepTree(t *testing.T) {
	root := t.TempDir()

	// Create 501+ directories to trigger the progress logging path (dirCount % 500 == 0).
	for i := range 502 {
		dir := filepath.Join(root, fmt.Sprintf("dir%04d", i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Add a lockfile in one of them to also exercise visitFile.
	content := `{
  "dependencies": {
    "express": "^4.18.0"
  }
}`
	if err := os.WriteFile(filepath.Join(root, "dir0001", "package.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	results, err := DetectAndParseRecursive(root)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// visitFile with unparseable lockfile (error return path).

func TestDetectAndParseRecursive_InvalidNestedLockfile(t *testing.T) {
	root := t.TempDir()

	subDir := filepath.Join(root, "sub")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(subDir, "package-lock.json"), []byte("{invalid}"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := DetectAndParseRecursive(root)
	if err == nil {
		t.Fatal("expected error for invalid nested lockfile")
	}
}
