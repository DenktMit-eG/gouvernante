package lockfile

import (
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
