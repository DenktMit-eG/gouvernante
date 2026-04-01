package lockfile

import (
	"testing"
)

func TestParsePackageJSON_ExactVersions(t *testing.T) {
	path := writeTempFile(t, "package.json", `{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "axios": "1.14.1",
    "express": "4.18.2"
  }
}`)

	entries, err := ParsePackageJSON(path)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	pkgs := entriesToMap(entries)

	if v := pkgs["axios"]; v != "1.14.1" {
		t.Errorf("axios: got %q, want 1.14.1", v)
	}

	if v := pkgs["express"]; v != "4.18.2" {
		t.Errorf("express: got %q, want 4.18.2", v)
	}
}

func TestParsePackageJSON_RangeVersions(t *testing.T) {
	path := writeTempFile(t, "package.json", `{
  "dependencies": {
    "axios": "^1.14.0",
    "lodash": "~4.17.0",
    "express": ">=4.0.0 <5.0.0"
  }
}`)

	entries, err := ParsePackageJSON(path)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	pkgs := entriesToMap(entries)

	// Ranges are passed through as-is (after stripping = prefix).
	if v := pkgs["axios"]; v != "^1.14.0" {
		t.Errorf("axios: got %q, want ^1.14.0", v)
	}

	if v := pkgs["lodash"]; v != "~4.17.0" {
		t.Errorf("lodash: got %q, want ~4.17.0", v)
	}

	if v := pkgs["express"]; v != ">=4.0.0 <5.0.0" {
		t.Errorf("express: got %q, want >=4.0.0 <5.0.0", v)
	}
}

func TestParsePackageJSON_DevDependencies(t *testing.T) {
	path := writeTempFile(t, "package.json", `{
  "dependencies": {
    "axios": "1.14.1"
  },
  "devDependencies": {
    "jest": "29.0.0",
    "plain-crypto-js": "4.2.1"
  }
}`)

	entries, err := ParsePackageJSON(path)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	pkgs := entriesToMap(entries)

	if len(entries) != 3 {
		t.Errorf("expected 3 entries (deps + devDeps), got %d", len(entries))
	}

	if v := pkgs["plain-crypto-js"]; v != "4.2.1" {
		t.Errorf("plain-crypto-js: got %q, want 4.2.1", v)
	}
}

func TestParsePackageJSON_Empty(t *testing.T) {
	path := writeTempFile(t, "package.json", `{
  "name": "empty-project",
  "version": "1.0.0"
}`)

	entries, err := ParsePackageJSON(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParsePackageJSON_InvalidJSON(t *testing.T) {
	path := writeTempFile(t, "package.json", `{invalid json}`)

	_, err := ParsePackageJSON(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParsePackageJSON_FileNotFound(t *testing.T) {
	_, err := ParsePackageJSON("/nonexistent/package.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestParsePackageJSON_NormalizeVersion(t *testing.T) {
	path := writeTempFile(t, "package.json", `{
  "dependencies": {
    "a": "v1.0.0",
    "b": "=2.0.0",
    "c": "  3.0.0  "
  }
}`)

	entries, err := ParsePackageJSON(path)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	pkgs := entriesToMap(entries)

	if v := pkgs["a"]; v != "1.0.0" {
		t.Errorf("a: got %q, want 1.0.0 (v prefix stripped)", v)
	}

	if v := pkgs["b"]; v != "2.0.0" {
		t.Errorf("b: got %q, want 2.0.0 (= prefix stripped)", v)
	}

	if v := pkgs["c"]; v != "3.0.0" {
		t.Errorf("c: got %q, want 3.0.0 (whitespace stripped)", v)
	}
}
