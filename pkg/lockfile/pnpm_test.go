package lockfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/goccy/go-yaml"
)

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, name)

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestParsePnpmLock_V9(t *testing.T) {
	path := writeTempFile(t, "pnpm-lock.yaml", `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:
  '.':
    dependencies:
      axios:
        specifier: ^1.7.0
        version: 1.7.9

packages:
  axios@1.7.9:
    resolution: {integrity: sha512-fake}

  express@4.18.2:
    resolution: {integrity: sha512-fake}

  '@scope/pkg@2.0.0':
    resolution: {integrity: sha512-fake}
`)

	entries, err := ParsePnpmLock(path)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	pkgs := entriesToMap(entries)

	tests := []struct {
		name    string
		version string
	}{
		{"axios", "1.7.9"},
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
}

func TestParsePnpmLock_V6(t *testing.T) {
	path := writeTempFile(t, "pnpm-lock.yaml", `lockfileVersion: 5.4

packages:
  /axios/1.7.8:
    resolution: {integrity: sha512-fake}
    dev: false

  /@scope/pkg/1.0.0:
    resolution: {integrity: sha512-fake}
    dev: true
`)

	entries, err := ParsePnpmLock(path)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	pkgs := entriesToMap(entries)

	if v := pkgs["axios"]; v != "1.7.8" {
		t.Errorf("axios: got %q, want 1.7.8", v)
	}

	if v := pkgs["@scope/pkg"]; v != "1.0.0" {
		t.Errorf("@scope/pkg: got %q, want 1.0.0", v)
	}
}

func TestParsePnpmLock_V9PeerSuffix(t *testing.T) {
	path := writeTempFile(t, "pnpm-lock.yaml", `lockfileVersion: '9.0'

packages:
  axios@1.7.9:
    resolution: {integrity: sha512-fake}

snapshots:
  axios@1.7.9(debug@4.3.4):
    dependencies:
      debug: 4.3.4
`)

	entries, err := ParsePnpmLock(path)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	pkgs := entriesToMap(entries)

	if v := pkgs["axios"]; v != "1.7.9" {
		t.Errorf("axios: got %q, want 1.7.9", v)
	}

	if len(entries) != 1 {
		t.Errorf("expected 1 deduplicated entry, got %d", len(entries))
	}
}

func TestParsePnpmLock_EmptyFile(t *testing.T) {
	path := writeTempFile(t, "pnpm-lock.yaml", `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
`)

	entries, err := ParsePnpmLock(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParsePnpmLock_FileNotFound(t *testing.T) {
	_, err := ParsePnpmLock("/nonexistent/pnpm-lock.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestSplitPackageKey(t *testing.T) {
	tests := []struct {
		key     string
		name    string
		version string
	}{
		{"axios@1.7.8", "axios", "1.7.8"},
		{"@scope/pkg@1.0.0", "@scope/pkg", "1.0.0"},
		{"axios/1.7.8", "axios", "1.7.8"},
		{"@scope/pkg/1.0.0", "@scope/pkg", "1.0.0"},
		{"axios@1.7.8(peer@2.0)", "axios", "1.7.8"},
		{"", "", ""},
		{"noversion", "", ""},
	}

	for _, tt := range tests {
		name, version := splitPackageKey(tt.key)
		if name != tt.name || version != tt.version {
			t.Errorf("splitPackageKey(%q) = (%q, %q), want (%q, %q)",
				tt.key, name, version, tt.name, tt.version)
		}
	}
}

func TestExtractFromMapSlice_NonStringKey(t *testing.T) {
	// yaml.MapSlice with a non-string key should be skipped without panic.
	ms := yaml.MapSlice{
		{Key: 42, Value: nil},
		{Key: "axios@1.7.9", Value: nil},
	}

	seen := make(map[string]bool)
	entries := extractFromMapSlice(ms, nil, seen)

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	if entries[0].Name != "axios" || entries[0].Version != "1.7.9" {
		t.Errorf("unexpected entry: %+v", entries[0])
	}
}

func TestParsePnpmLock_InvalidYAML(t *testing.T) {
	path := writeTempFile(t, "pnpm-lock.yaml", `{{{invalid yaml`)

	_, err := ParsePnpmLock(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func entriesToMap(entries []PackageEntry) map[string]string {
	m := make(map[string]string, len(entries))
	for _, e := range entries {
		m[e.Name] = e.Version
	}

	return m
}
