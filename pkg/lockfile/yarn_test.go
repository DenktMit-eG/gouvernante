package lockfile

import (
	"testing"
)

func TestParseYarnLock_Classic(t *testing.T) {
	path := writeTempFile(t, "yarn.lock", `# yarn lockfile v1

axios@^1.7.0:
  version "1.7.8"
  resolved "https://registry.yarnpkg.com/axios/-/axios-1.7.8.tgz#fake"
  integrity sha512-fake

express@^4.18.0, express@~4.18.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz#fake"

"@scope/pkg@^2.0.0":
  version "2.0.0"
  resolved "https://registry.yarnpkg.com/@scope/pkg/-/pkg-2.0.0.tgz#fake"
`)

	entries, err := ParseYarnLock(path)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	pkgs := entriesToMap(entries)

	tests := []struct {
		name    string
		version string
	}{
		{"axios", "1.7.8"},
		{"express", "4.18.2"},
		{"@scope/pkg", "2.0.0"},
	}

	for _, tt := range tests {
		v, ok := pkgs[tt.name]
		if !ok {
			t.Errorf("missing package %s", tt.name)

			continue
		}

		if v != tt.version {
			t.Errorf("package %s: got version %s, want %s", tt.name, v, tt.version)
		}
	}

	// "express" should appear once despite two specifiers.
	count := 0
	for _, e := range entries {
		if e.Name == "express" {
			count++
		}
	}

	if count != 1 {
		t.Errorf("express should be deduplicated to 1 entry, got %d", count)
	}
}

func TestParseYarnLock_Empty(t *testing.T) {
	path := writeTempFile(t, "yarn.lock", `# yarn lockfile v1

`)

	entries, err := ParseYarnLock(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParseYarnLock_FileNotFound(t *testing.T) {
	_, err := ParseYarnLock("/nonexistent/yarn.lock")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}
