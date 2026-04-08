package lockfile

import (
	"testing"
)

func TestParsePackageLockJSON_V3(t *testing.T) {
	path := writeTempFile(t, "package-lock.json", `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "test", "version": "1.0.0" },
    "node_modules/axios": { "version": "1.7.8" },
    "node_modules/@scope/pkg": { "version": "2.0.0" },
    "node_modules/foo/node_modules/bar": { "version": "3.0.0" }
  }
}`)

	entries, err := ParsePackageLockJSON(path)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	pkgs := entriesToMap(entries)

	if v := pkgs["axios"]; v != "1.7.8" {
		t.Errorf("axios: got %q, want 1.7.8", v)
	}

	if v := pkgs["@scope/pkg"]; v != "2.0.0" {
		t.Errorf("@scope/pkg: got %q, want 2.0.0", v)
	}

	if v := pkgs["bar"]; v != "3.0.0" {
		t.Errorf("bar (nested): got %q, want 3.0.0", v)
	}
}

func TestParsePackageLockJSON_V1(t *testing.T) {
	path := writeTempFile(t, "package-lock.json", `{
  "name": "test",
  "lockfileVersion": 1,
  "dependencies": {
    "axios": {
      "version": "1.7.8",
      "dependencies": {
        "follow-redirects": {
          "version": "1.15.0"
        }
      }
    },
    "express": {
      "version": "4.18.2"
    }
  }
}`)

	entries, err := ParsePackageLockJSON(path)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	pkgs := entriesToMap(entries)

	if v := pkgs["axios"]; v != "1.7.8" {
		t.Errorf("axios: got %q, want 1.7.8", v)
	}

	if v := pkgs["follow-redirects"]; v != "1.15.0" {
		t.Errorf("follow-redirects: got %q, want 1.15.0", v)
	}

	if v := pkgs["express"]; v != "4.18.2" {
		t.Errorf("express: got %q, want 4.18.2", v)
	}
}

func TestParsePackageLockJSON_EmptyPackages(t *testing.T) {
	path := writeTempFile(t, "package-lock.json", `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "test", "version": "1.0.0" }
  }
}`)

	entries, err := ParsePackageLockJSON(path)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParsePackageLockJSON_InvalidJSON(t *testing.T) {
	path := writeTempFile(t, "package-lock.json", `{invalid json}`)

	_, err := ParsePackageLockJSON(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParsePackageLockJSON_FileNotFound(t *testing.T) {
	_, err := ParsePackageLockJSON("/nonexistent/package-lock.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestParsePackageLockJSON_V3_Dedup(t *testing.T) {
	// Same package at different node_modules paths should be deduplicated.
	path := writeTempFile(t, "package-lock.json", `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "test", "version": "1.0.0" },
    "node_modules/lodash": { "version": "4.17.21" },
    "node_modules/foo/node_modules/lodash": { "version": "4.17.21" }
  }
}`)

	entries, err := ParsePackageLockJSON(path)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	count := 0
	for _, e := range entries {
		if e.Name == "lodash" && e.Version == "4.17.21" {
			count++
		}
	}

	if count != 1 {
		t.Errorf("lodash@4.17.21 should appear once (deduplicated), got %d", count)
	}
}

func TestExtractPackageName(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"node_modules/axios", "axios"},
		{"node_modules/@scope/pkg", "@scope/pkg"},
		{"node_modules/foo/node_modules/bar", "bar"},
		{"node_modules/foo/node_modules/@org/lib", "@org/lib"},
		{"", ""},
		{"no-node-modules", ""},
	}

	for _, tt := range tests {
		got := extractPackageName(tt.key)
		if got != tt.want {
			t.Errorf("extractPackageName(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

func TestParseNpmV2_EmptyNameKey(t *testing.T) {
	// A key that resolves to an empty package name should be skipped.
	path := writeTempFile(t, "package-lock.json", `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "": {"version": "1.0.0"},
    "no-node-modules": {"version": "2.0.0"}
  }
}`)

	entries, err := ParsePackageLockJSON(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty/unrecognized keys, got %d", len(entries))
	}
}

func TestParseNpmV1_EmptyVersion(t *testing.T) {
	// Dependencies with empty versions should be skipped.
	path := writeTempFile(t, "package-lock.json", `{
  "name": "test",
  "dependencies": {
    "axios": {"version": ""},
    "express": {"version": "4.18.0"}
  }
}`)

	entries, err := ParsePackageLockJSON(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("expected 1 entry (express only), got %d", len(entries))
	}
}
