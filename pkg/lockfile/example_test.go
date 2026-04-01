package lockfile_test

import (
	"fmt"
	"os"
	"path/filepath"

	"gouvernante/pkg/lockfile"
)

func ExampleParsePnpmLock() {
	dir, _ := os.MkdirTemp("", "example")
	defer func() { _ = os.RemoveAll(dir) }()

	content := `lockfileVersion: '9.0'

packages:
  axios@1.7.9:
    resolution: {integrity: sha512-fake}

  express@4.18.2:
    resolution: {integrity: sha512-fake}
`
	path := filepath.Join(dir, "pnpm-lock.yaml")
	_ = os.WriteFile(path, []byte(content), 0o600)

	entries, _ := lockfile.ParsePnpmLock(path)
	for _, e := range entries {
		fmt.Printf("%s@%s\n", e.Name, e.Version)
	}

	// Unordered output:
	// axios@1.7.9
	// express@4.18.2
}

func ExampleParsePackageLockJSON() {
	dir, _ := os.MkdirTemp("", "example")
	defer func() { _ = os.RemoveAll(dir) }()

	content := `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "test", "version": "1.0.0" },
    "node_modules/axios": { "version": "1.7.8" }
  }
}`
	path := filepath.Join(dir, "package-lock.json")
	_ = os.WriteFile(path, []byte(content), 0o600)

	entries, _ := lockfile.ParsePackageLockJSON(path)
	for _, e := range entries {
		fmt.Printf("%s@%s\n", e.Name, e.Version)
	}

	// Output:
	// axios@1.7.8
}
