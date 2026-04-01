package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"gouvernante/pkg/rules"
)

func writePackageJSON(t *testing.T, nmDir, pkgName, version string) {
	t.Helper()

	pkgDir := filepath.Join(nmDir, pkgName)
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}

	content := `{"name":"` + pkgName + `","version":"` + version + `"}`
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func testIndex() *rules.PackageIndex {
	return &rules.PackageIndex{
		Packages: map[string]*rules.VersionSet{
			"axios": {
				RuleID:    "R1",
				RuleTitle: "Test",
				Severity:  "critical",
				Versions:  map[string]bool{"1.14.1": true, "0.30.4": true},
			},
			"plain-crypto-js": {
				RuleID:     "R1",
				RuleTitle:  "Test",
				Severity:   "critical",
				AnyVersion: true,
			},
		},
	}
}

func TestScanNodeModules_FindsCompromised(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")

	writePackageJSON(t, nmDir, "axios", "1.14.1")
	writePackageJSON(t, nmDir, "express", "4.18.2")

	findings, checks := ScanNodeModules([]string{dir}, testIndex())

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Package != "axios" || findings[0].Version != "1.14.1" {
		t.Errorf("finding: got %s@%s, want axios@1.14.1", findings[0].Package, findings[0].Version)
	}

	if findings[0].Type != "installed_package" {
		t.Errorf("type: got %q, want installed_package", findings[0].Type)
	}

	// axios found + plain-crypto-js not installed.
	foundCount := 0
	for _, c := range checks {
		if c.Status == StatusFound {
			foundCount++
		}
	}

	if foundCount != 1 {
		t.Errorf("expected 1 found check, got %d", foundCount)
	}
}

func TestScanNodeModules_FindsDropper(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")

	writePackageJSON(t, nmDir, "plain-crypto-js", "4.2.1")

	findings, _ := ScanNodeModules([]string{dir}, testIndex())

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (dropper), got %d", len(findings))
	}

	if findings[0].Package != "plain-crypto-js" {
		t.Errorf("expected plain-crypto-js, got %s", findings[0].Package)
	}
}

func TestScanNodeModules_CleanVersion(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")

	writePackageJSON(t, nmDir, "axios", "1.7.7") // safe version

	findings, checks := ScanNodeModules([]string{dir}, testIndex())

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for safe version, got %d", len(findings))
	}

	cleanCount := 0
	for _, c := range checks {
		if c.Package == "axios" && c.Status == StatusClean {
			cleanCount++
		}
	}

	if cleanCount != 1 {
		t.Errorf("expected 1 clean check for axios, got %d", cleanCount)
	}
}

func TestScanNodeModules_NoNodeModulesDir(t *testing.T) {
	dir := t.TempDir()

	findings, _ := ScanNodeModules([]string{dir}, testIndex())

	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no node_modules, got %d", len(findings))
	}
}

func TestScanNodeModules_ScopedPackage(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")

	idx := &rules.PackageIndex{
		Packages: map[string]*rules.VersionSet{
			"@scope/evil": {
				RuleID:     "R2",
				RuleTitle:  "Scoped test",
				Severity:   "high",
				AnyVersion: true,
			},
		},
	}

	writePackageJSON(t, nmDir, "@scope/evil", "1.0.0")

	findings, _ := ScanNodeModules([]string{dir}, idx)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for scoped package, got %d", len(findings))
	}

	if findings[0].Package != "@scope/evil" {
		t.Errorf("expected @scope/evil, got %s", findings[0].Package)
	}
}

func TestReadInstalledVersion(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")

	writePackageJSON(t, nmDir, "axios", "1.14.1")

	version, err := readInstalledVersion(nmDir, "axios")
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if version != "1.14.1" {
		t.Errorf("version: got %q, want 1.14.1", version)
	}
}

func TestScanStoreForPackages_FindsCompromised(t *testing.T) {
	root := t.TempDir()

	// Simulate pnpm store structure: <store>/axios/1.14.1/package.json
	axiosDir := filepath.Join(root, "axios", "1.14.1")
	if err := os.MkdirAll(axiosDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(axiosDir, "package.json"),
		[]byte(`{"name":"axios","version":"1.14.1"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, _ := scanStoreForPackages(root, testIndex(), "test store")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Package != "axios" || findings[0].Version != "1.14.1" {
		t.Errorf("finding: got %s@%s", findings[0].Package, findings[0].Version)
	}
}

func TestScanStoreForPackages_IgnoresCleanVersion(t *testing.T) {
	root := t.TempDir()

	axiosDir := filepath.Join(root, "axios", "1.7.7")
	if err := os.MkdirAll(axiosDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(axiosDir, "package.json"),
		[]byte(`{"name":"axios","version":"1.7.7"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, _ := scanStoreForPackages(root, testIndex(), "test store")

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean version, got %d", len(findings))
	}
}

func TestScanStoreForPackages_IgnoresNonIndexedPackage(t *testing.T) {
	root := t.TempDir()

	pkgDir := filepath.Join(root, "express", "4.18.2")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"),
		[]byte(`{"name":"express","version":"4.18.2"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, _ := scanStoreForPackages(root, testIndex(), "test store")

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-indexed package, got %d", len(findings))
	}
}

func TestMatchBlobAgainstIndex_FindsCompromisedVersion(t *testing.T) {
	idx := testIndex()
	lookups := buildCacheLookups(idx)

	blob := []byte(`{"name":"axios","version":"1.14.1","resolved":"https://registry.npmjs.org/axios/-/axios-1.14.1.tgz"}`)
	findings, checks := matchBlobAgainstIndex(blob, "/cache/blob1", "/cache", lookups)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Type != "cached_package" {
		t.Errorf("type: got %q, want cached_package", findings[0].Type)
	}

	foundCount := 0
	for _, c := range checks {
		if c.Status == StatusFound {
			foundCount++
		}
	}

	if foundCount != 1 {
		t.Errorf("expected 1 found check, got %d", foundCount)
	}
}

func TestMatchBlobAgainstIndex_FindsDropper(t *testing.T) {
	idx := testIndex()
	lookups := buildCacheLookups(idx)

	blob := []byte(`{"name":"plain-crypto-js","version":"4.2.1"}`)
	findings, _ := matchBlobAgainstIndex(blob, "/cache/blob2", "/cache", lookups)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for dropper, got %d", len(findings))
	}
}

func TestMatchBlobAgainstIndex_NoMatch(t *testing.T) {
	idx := testIndex()
	lookups := buildCacheLookups(idx)

	blob := []byte(`{"name":"express","version":"4.18.2"}`)
	findings, _ := matchBlobAgainstIndex(blob, "/cache/blob3", "/cache", lookups)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-indexed package, got %d", len(findings))
	}
}

// buildCacheLookups creates cacheLookup entries from the test index.
func buildCacheLookups(idx *rules.PackageIndex) []cacheLookup {
	lookups := make([]cacheLookup, 0, len(idx.Packages))

	for name, vs := range idx.Packages {
		l := cacheLookup{
			name:      name,
			nameBytes: []byte(name),
			vs:        vs,
		}

		if !vs.AnyVersion {
			for v := range vs.Versions {
				l.versions = append(l.versions, []byte(v))
			}
		}

		lookups = append(lookups, l)
	}

	return lookups
}

func TestReadInstalledVersion_NotInstalled(t *testing.T) {
	dir := t.TempDir()

	_, err := readInstalledVersion(dir, "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing package")
	}
}
