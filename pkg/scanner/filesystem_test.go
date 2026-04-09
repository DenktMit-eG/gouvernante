package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
		Packages: map[string][]*rules.VersionSet{
			"axios": {
				{
					RuleID:    "R1",
					RuleTitle: "Test",
					Severity:  "critical",
					Versions:  map[string]bool{"1.14.1": true, "0.30.4": true},
				},
			},
			"plain-crypto-js": {
				{
					RuleID:     "R1",
					RuleTitle:  "Test",
					Severity:   "critical",
					AnyVersion: true,
				},
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

	if findings[0].Type != TypeInstalledPackage {
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
		Packages: map[string][]*rules.VersionSet{
			"@scope/evil": {
				{
					RuleID:     "R2",
					RuleTitle:  "Scoped test",
					Severity:   "high",
					AnyVersion: true,
				},
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

	for name, vsList := range idx.Packages {
		l := cacheLookup{
			name:      name,
			nameBytes: []byte(name),
			vsList:    vsList,
		}

		lookups = append(lookups, l)
	}

	return lookups
}

func TestFindPackageNameWithBoundary(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		pkg     string
		wantPos bool
	}{
		{"exact match in JSON", `"atrix":"1.0.3"`, "atrix", true},
		{"substring should not match", `"dommatrix":"^1.0.3"`, "atrix", false},
		{"at sign boundary", `atrix@1.0.3`, "atrix", true},
		{"slash boundary", `/atrix/1.0.3`, "atrix", true},
		{"start of data", `atrix@1.0.0`, "atrix", true},
		{"scoped package", `"@scope/pkg":"1.0.0"`, "@scope/pkg", true},
		{"embedded in word", `formatrix-lib`, "atrix", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pos := findPackageNameWithBoundary([]byte(tt.data), []byte(tt.pkg))
			gotFound := pos >= 0

			if gotFound != tt.wantPos {
				t.Errorf("findPackageNameWithBoundary(%q, %q) found=%v, want found=%v",
					tt.data, tt.pkg, gotFound, tt.wantPos)
			}
		})
	}
}

func TestMatchBlobAgainstIndex_NoFalsePositiveSubstring(t *testing.T) {
	// "atrix" should NOT match inside "dommatrix".
	idx := &rules.PackageIndex{
		Packages: map[string][]*rules.VersionSet{
			"atrix": {
				{
					RuleID: "R1", RuleTitle: "Test", Severity: "high",
					Versions: map[string]bool{"1.0.3": true},
				},
			},
		},
	}
	lookups := buildCacheLookups(idx)

	blob := []byte(`{"dommatrix":"^1.0.3","web-animations":"2.0.0"}`)
	findings, _ := matchBlobAgainstIndex(blob, "/cache/blob", "/cache", lookups)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings (substring false positive), got %d", len(findings))
	}
}

func TestMatchBlobAgainstIndex_TruePositiveWithBoundary(t *testing.T) {
	idx := &rules.PackageIndex{
		Packages: map[string][]*rules.VersionSet{
			"atrix": {
				{
					RuleID: "R1", RuleTitle: "Test", Severity: "high",
					Versions: map[string]bool{"1.0.3": true},
				},
			},
		},
	}
	lookups := buildCacheLookups(idx)

	blob := []byte(`"atrix/-/atrix-1.0.3.tgz"`)
	findings, _ := matchBlobAgainstIndex(blob, "/cache/blob", "/cache", lookups)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestReadInstalledVersion_NotInstalled(t *testing.T) {
	dir := t.TempDir()

	_, err := readInstalledVersion(dir, "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing package")
	}
}

// Additional tests.

func TestScanCacheBlobs(t *testing.T) {
	dir := t.TempDir()

	// Create fake blob files
	subdir := filepath.Join(dir, "ab")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Blob that matches: contains axios with compromised version
	blob1 := []byte(`{"name":"axios","version":"1.14.1","resolved":"https://registry.npmjs.org/axios/-/axios-1.14.1.tgz"}`)
	if err := os.WriteFile(filepath.Join(subdir, "blob1"), blob1, 0o600); err != nil {
		t.Fatal(err)
	}

	// Blob that doesn't match
	blob2 := []byte(`{"name":"express","version":"4.18.2"}`)
	if err := os.WriteFile(filepath.Join(subdir, "blob2"), blob2, 0o600); err != nil {
		t.Fatal(err)
	}

	idx := testIndex()
	lookups := buildCacheLookups(idx)

	findings, checks := scanCacheBlobs(dir, lookups)

	if len(findings) < 1 {
		t.Fatalf("expected at least 1 finding, got %d", len(findings))
	}

	foundAxios := false
	for _, f := range findings {
		if f.Package == "axios" && f.Version == "1.14.1" {
			foundAxios = true
		}
	}

	if !foundAxios {
		t.Error("expected to find axios@1.14.1 in cache blobs")
	}

	if len(checks) == 0 {
		t.Error("expected at least one check")
	}
}

func TestScanNpmCache_FakeHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Ensure npm command won't be found or returns nothing useful
	t.Setenv("PATH", "")

	// Create fake npm cache structure
	cacheDir := filepath.Join(home, ".npm", "_cacache", "index-v5", "ab")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatal(err)
	}

	blob := []byte(`{"name":"axios","version":"1.14.1","integrity":"sha512-abc123"}`)
	if err := os.WriteFile(filepath.Join(cacheDir, "blob1"), blob, 0o600); err != nil {
		t.Fatal(err)
	}

	idx := testIndex()
	findings, _ := ScanNpmCache(idx)

	// We should find the compromised package in the cache
	foundAxios := false
	for _, f := range findings {
		if f.Package == "axios" {
			foundAxios = true
		}
	}

	if !foundAxios {
		t.Error("expected to find axios in npm cache")
	}
}

func TestScanPnpmStore_FakeHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "")
	t.Setenv("PNPM_HOME", "")

	// Create fake pnpm store structure
	storeDir := filepath.Join(home, ".local", "share", "pnpm", "axios", "1.14.1")
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	pkgJSON := `{"name":"axios","version":"1.14.1"}`
	if err := os.WriteFile(filepath.Join(storeDir, "package.json"), []byte(pkgJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	idx := testIndex()
	findings, _ := ScanPnpmStore(idx)

	foundAxios := false
	for _, f := range findings {
		if f.Package == "axios" && f.Version == "1.14.1" {
			foundAxios = true
		}
	}

	if !foundAxios {
		t.Error("expected to find axios@1.14.1 in pnpm store")
	}
}

func TestScanNvmDirs_FakeNvmDir(t *testing.T) {
	nvmDir := t.TempDir()
	t.Setenv("NVM_DIR", nvmDir)

	// Create fake nvm cache with a compromised package
	cacheDir := filepath.Join(nvmDir, ".cache", "axios", "1.14.1")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatal(err)
	}

	pkgJSON := `{"name":"axios","version":"1.14.1"}`
	if err := os.WriteFile(filepath.Join(cacheDir, "package.json"), []byte(pkgJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	idx := testIndex()
	findings, _ := ScanNvmDirs(idx)

	foundAxios := false
	for _, f := range findings {
		if f.Package == "axios" && f.Version == "1.14.1" {
			foundAxios = true
		}
	}

	if !foundAxios {
		t.Error("expected to find axios@1.14.1 in nvm cache")
	}
}

func TestScanNvmDirs_NoNvmDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("NVM_DIR", "")

	// No .nvm directory exists
	findings, checks := ScanNvmDirs(testIndex())

	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no nvm dir, got %d", len(findings))
	}

	if len(checks) != 0 {
		t.Errorf("expected 0 checks when no nvm dir, got %d", len(checks))
	}
}

func TestScanNvmDirs_WithVersionsDir(t *testing.T) {
	nvmDir := t.TempDir()
	t.Setenv("NVM_DIR", nvmDir)

	// Create a nvm-managed node version with global node_modules
	nmDir := filepath.Join(nvmDir, "versions", "node", "v18.0.0", "lib", "node_modules")
	writePackageJSON(t, nmDir, "axios", "1.14.1")

	idx := testIndex()
	findings, _ := ScanNvmDirs(idx)

	foundAxios := false
	for _, f := range findings {
		if f.Package == "axios" && f.Version == "1.14.1" {
			foundAxios = true
		}
	}

	if !foundAxios {
		t.Error("expected to find axios@1.14.1 in nvm versions global node_modules")
	}
}

func TestDedup_Filesystem(t *testing.T) {
	got := dedup([]string{"/usr/lib/node_modules", "/usr/local/lib/node_modules", "/usr/lib/node_modules"})
	if len(got) != 2 {
		t.Errorf("expected 2 unique paths, got %d: %v", len(got), got)
	}
}

func TestScanCacheBlobs_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	lookups := buildCacheLookups(testIndex())

	findings, checks := scanCacheBlobs(dir, lookups)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty dir, got %d", len(findings))
	}

	if len(checks) != 0 {
		t.Errorf("expected 0 checks for empty dir, got %d", len(checks))
	}
}

func TestGlobalNodeModulesPaths(t *testing.T) {
	// This tests the function on the current platform (linux in CI).
	// It should return at least the static fallback paths.
	paths := globalNodeModulesPaths()

	// On Linux, we should at least get the static fallback paths.
	if len(paths) == 0 {
		t.Error("expected at least some paths from globalNodeModulesPaths")
	}

	// All paths should be unique (dedup was applied).
	seen := make(map[string]bool)
	for _, p := range paths {
		if seen[p] {
			t.Errorf("duplicate path: %s", p)
		}
		seen[p] = true
	}
}

func TestScanGlobalNodeModules(t *testing.T) {
	// ScanGlobalNodeModules should not panic and should return without error.
	// With an empty index, there should be no findings.
	idx := &rules.PackageIndex{
		Packages: map[string][]*rules.VersionSet{},
	}

	findings, checks := ScanGlobalNodeModules(idx)

	// No packages in the index, so no findings expected.
	if len(findings) != 0 {
		t.Errorf("expected 0 findings with empty index, got %d", len(findings))
	}

	// Checks may or may not be empty depending on what's installed globally.
	_ = checks
}

func TestScanStoreForPackages_InvalidJSON(t *testing.T) {
	root := t.TempDir()

	// Create a package.json with invalid JSON
	pkgDir := filepath.Join(root, "bad")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{invalid json`), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, checks := scanStoreForPackages(root, testIndex(), "test")

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for invalid JSON, got %d", len(findings))
	}

	if len(checks) != 0 {
		t.Errorf("expected 0 checks for invalid JSON, got %d", len(checks))
	}
}

func TestScanStoreForPackages_MissingName(t *testing.T) {
	root := t.TempDir()

	// Create a package.json without a name field
	pkgDir := filepath.Join(root, "noname")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{"version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, checks := scanStoreForPackages(root, testIndex(), "test")

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for missing name, got %d", len(findings))
	}

	if len(checks) != 0 {
		t.Errorf("expected 0 checks for missing name, got %d", len(checks))
	}
}

func TestReadInstalledVersion_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := filepath.Join(nmDir, "bad-pkg")

	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{invalid`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := readInstalledVersion(nmDir, "bad-pkg")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestScanCacheBlobs_WithDropperPackage(t *testing.T) {
	dir := t.TempDir()

	subdir := filepath.Join(dir, "cd")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Blob containing a dropper package (AnyVersion = true)
	blob := []byte(`{"name":"plain-crypto-js","version":"4.2.1"}`)
	if err := os.WriteFile(filepath.Join(subdir, "blob1"), blob, 0o600); err != nil {
		t.Fatal(err)
	}

	idx := testIndex()
	lookups := buildCacheLookups(idx)

	findings, _ := scanCacheBlobs(dir, lookups)

	found := false
	for _, f := range findings {
		if f.Package == "plain-crypto-js" {
			found = true
		}
	}

	if !found {
		t.Error("expected to find plain-crypto-js dropper in cache blobs")
	}
}

func TestScanPnpmStore_WithPnpmHome(t *testing.T) {
	home := t.TempDir()
	pnpmHome := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "")
	t.Setenv("PNPM_HOME", pnpmHome)

	// Create a package in PNPM_HOME
	storeDir := filepath.Join(pnpmHome, "axios", "1.14.1")
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	pkgJSON := `{"name":"axios","version":"1.14.1"}`
	if err := os.WriteFile(filepath.Join(storeDir, "package.json"), []byte(pkgJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	idx := testIndex()
	findings, _ := ScanPnpmStore(idx)

	foundAxios := false
	for _, f := range findings {
		if f.Package == "axios" && f.Version == "1.14.1" {
			foundAxios = true
		}
	}

	if !foundAxios {
		t.Error("expected to find axios@1.14.1 in PNPM_HOME")
	}
}

func TestScanNpmCache_NoCacheDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "")

	// No .npm directory exists
	findings, checks := ScanNpmCache(testIndex())

	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no npm cache, got %d", len(findings))
	}

	if len(checks) != 0 {
		t.Errorf("expected 0 checks when no npm cache, got %d", len(checks))
	}
}

func TestScanNpmCache_WithContentDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", "")

	// Create both index-v5 and content-v2 directories
	indexDir := filepath.Join(home, ".npm", "_cacache", "index-v5", "ab")
	contentDir := filepath.Join(home, ".npm", "_cacache", "content-v2", "sha512", "ab")
	if err := os.MkdirAll(indexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(contentDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Put a matching blob in content-v2
	blob := []byte(`{"name":"axios","version":"0.30.4","resolved":"test"}`)
	if err := os.WriteFile(filepath.Join(contentDir, "blob1"), blob, 0o600); err != nil {
		t.Fatal(err)
	}

	idx := testIndex()
	findings, _ := ScanNpmCache(idx)

	foundAxios := false
	for _, f := range findings {
		if f.Package == "axios" {
			foundAxios = true
		}
	}

	if !foundAxios {
		t.Error("expected to find axios in npm cache content-v2")
	}
}

func TestGlobalNodeModulesPaths_WithEnvPrefix(t *testing.T) {
	prefix := t.TempDir()
	t.Setenv("NPM_CONFIG_PREFIX", prefix)

	paths := globalNodeModulesPathsForOS("linux")

	expected := filepath.Join(prefix, "lib", "node_modules")
	found := false

	for _, p := range paths {
		if p == expected {
			found = true
		}
	}

	if !found {
		t.Errorf("expected %q in paths from NPM_CONFIG_PREFIX, got %v", expected, paths)
	}
}

func TestGlobalNodeModulesPaths_Linux(t *testing.T) {
	t.Setenv("NPM_CONFIG_PREFIX", "")

	paths := globalNodeModulesPathsForOS("linux")

	if len(paths) != 2 {
		t.Errorf("expected 2 linux paths, got %d: %v", len(paths), paths)
	}
}

func TestGlobalNodeModulesPaths_Darwin(t *testing.T) {
	t.Setenv("NPM_CONFIG_PREFIX", "")

	paths := globalNodeModulesPathsForOS("darwin")

	if len(paths) != 2 {
		t.Errorf("expected 2 darwin paths, got %d: %v", len(paths), paths)
	}

	found := false
	for _, p := range paths {
		if p == "/opt/homebrew/lib/node_modules" {
			found = true
		}
	}

	if !found {
		t.Error("expected /opt/homebrew/lib/node_modules in darwin paths")
	}
}

func TestGlobalNodeModulesPaths_Windows(t *testing.T) {
	t.Setenv("NPM_CONFIG_PREFIX", "")
	t.Setenv("APPDATA", "/test/appdata")

	paths := globalNodeModulesPathsForOS("windows")

	if len(paths) != 1 {
		t.Errorf("expected 1 windows path, got %d: %v", len(paths), paths)
	}
}

func TestGlobalNodeModulesPaths_WindowsNoAppData(t *testing.T) {
	t.Setenv("NPM_CONFIG_PREFIX", "")
	t.Setenv("APPDATA", "")

	paths := globalNodeModulesPathsForOS("windows")

	if len(paths) != 0 {
		t.Errorf("expected 0 windows paths without APPDATA, got %d: %v", len(paths), paths)
	}
}

func TestScanGlobalNodeModules_WithCompromised(t *testing.T) {
	dir := t.TempDir()
	writePackageJSON(t, dir, "axios", "1.14.1")

	idx := testIndex()

	// Directly test scanSingleNodeModules on a dir containing a compromised package.
	findings, checks := scanSingleNodeModules(dir, idx)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Type != TypeInstalledPackage {
		t.Errorf("expected installed_package type, got %s", findings[0].Type)
	}

	// Verify checks contain at least one entry.
	if len(checks) == 0 {
		t.Error("expected at least one check entry")
	}
}

func TestScanPnpmStore_NoHomeDir(t *testing.T) {
	orig := userHomeDir
	userHomeDir = func() (string, error) { return "", fmt.Errorf("no home") }
	defer func() { userHomeDir = orig }()

	findings, checks := ScanPnpmStore(testIndex())

	if len(findings) != 0 {
		t.Errorf("expected 0 findings when home dir unavailable, got %d", len(findings))
	}

	if len(checks) != 0 {
		t.Errorf("expected 0 checks when home dir unavailable, got %d", len(checks))
	}
}

func TestScanNvmDirs_NoHomeDir(t *testing.T) {
	orig := userHomeDir
	userHomeDir = func() (string, error) { return "", fmt.Errorf("no home") }
	defer func() { userHomeDir = orig }()

	t.Setenv("NVM_DIR", "")

	findings, checks := ScanNvmDirs(testIndex())

	if len(findings) != 0 || len(checks) != 0 {
		t.Error("expected empty results when home dir unavailable")
	}
}

func TestScanNpmCache_NoHomeDir(t *testing.T) {
	orig := userHomeDir
	userHomeDir = func() (string, error) { return "", fmt.Errorf("no home") }
	defer func() { userHomeDir = orig }()

	t.Setenv("NPM_CONFIG_CACHE", "")

	findings, checks := ScanNpmCache(testIndex())

	if len(findings) != 0 || len(checks) != 0 {
		t.Error("expected empty results when home dir unavailable")
	}
}

func TestListInstalledPackages_Basic(t *testing.T) {
	nmDir := t.TempDir()

	// Regular package.
	if err := os.MkdirAll(filepath.Join(nmDir, "express"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Scoped package.
	if err := os.MkdirAll(filepath.Join(nmDir, "@scope", "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Hidden dir — should be skipped.
	if err := os.MkdirAll(filepath.Join(nmDir, ".cache"), 0o755); err != nil {
		t.Fatal(err)
	}

	// File — should be skipped.
	if err := os.WriteFile(filepath.Join(nmDir, ".package-lock.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs := listInstalledPackages(nmDir)

	found := map[string]bool{}
	for _, p := range pkgs {
		found[p] = true
	}

	if !found["express"] {
		t.Error("expected express in list")
	}

	if !found["@scope/pkg"] {
		t.Error("expected @scope/pkg in list")
	}

	if found[".cache"] {
		t.Error("hidden dir .cache should be skipped")
	}

	if found[".package-lock.json"] {
		t.Error("files should be skipped")
	}
}

func TestListInstalledPackages_UnreadableDir(t *testing.T) {
	pkgs := listInstalledPackages("/nonexistent/node_modules")
	if len(pkgs) != 0 {
		t.Errorf("expected nil for unreadable dir, got %v", pkgs)
	}
}

func TestListInstalledPackages_UnreadableScopeDir(t *testing.T) {
	nmDir := t.TempDir()

	scopeDir := filepath.Join(nmDir, "@scope")
	if err := os.MkdirAll(scopeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(scopeDir, 0o000); err != nil {
		t.Fatal(err)
	}

	defer func() { _ = os.Chmod(scopeDir, 0o755) }()

	pkgs := listInstalledPackages(nmDir)

	// Should not crash; unreadable scope dir is skipped.
	for _, p := range pkgs {
		if strings.HasPrefix(p, "@scope") {
			t.Errorf("should not list packages from unreadable scope dir, got %s", p)
		}
	}
}

func TestScanSingleNodeModules_BrokenPackageJSON(t *testing.T) {
	nmDir := t.TempDir()

	// Create an axios dir with invalid package.json.
	pkgDir := filepath.Join(nmDir, "axios")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte("{bad json}"), 0o600); err != nil {
		t.Fatal(err)
	}

	idx := testIndex()
	findings, _ := scanSingleNodeModules(nmDir, idx)

	// Should not crash; broken package.json is skipped.
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for broken package.json, got %d", len(findings))
	}
}

func TestScanGlobalNodeModules_FindsCompromised(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NPM_CONFIG_PREFIX", dir)

	// Create lib/node_modules/<pkg>/package.json structure.
	nmDir := filepath.Join(dir, "lib", "node_modules")
	writePackageJSON(t, nmDir, "axios", "1.14.1")

	idx := testIndex()
	findings, _ := ScanGlobalNodeModules(idx)

	foundAxios := false
	for _, f := range findings {
		if f.Package == "axios" {
			foundAxios = true
		}
	}

	if !foundAxios {
		t.Error("expected to find axios in global node_modules")
	}
}

func TestScanStoreForPackages_UnreadableFile(t *testing.T) {
	root := t.TempDir()

	pkgDir := filepath.Join(root, "some-pkg")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create a package.json with no read permissions.
	path := filepath.Join(pkgDir, "package.json")
	if err := os.WriteFile(path, []byte(`{"name":"axios","version":"1.14.1"}`), 0o000); err != nil {
		t.Fatal(err)
	}

	idx := testIndex()
	findings, _ := scanStoreForPackages(root, idx, "test")

	// Should not crash, just skip the unreadable file.
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanStoreForPackages_WalkError(t *testing.T) {
	root := t.TempDir()

	// Create a subdirectory that is not readable — WalkDir will pass an error.
	unreadable := filepath.Join(root, "noperm")
	if err := os.MkdirAll(unreadable, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}

	defer func() { _ = os.Chmod(unreadable, 0o755) }()

	idx := testIndex()
	findings, _ := scanStoreForPackages(root, idx, "test")

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanStoreForPackages_NonPackageJSON(t *testing.T) {
	root := t.TempDir()

	// Create a non-package.json file — should be skipped.
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	idx := testIndex()
	findings, _ := scanStoreForPackages(root, idx, "test")

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanCacheBlobs_UnreadableFile(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "ab")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create a file with no read permissions.
	path := filepath.Join(subdir, "blob1")
	if err := os.WriteFile(path, []byte(`"axios":"1.14.1"`), 0o000); err != nil {
		t.Fatal(err)
	}

	lookups := buildCacheLookups(testIndex())
	findings, _ := scanCacheBlobs(dir, lookups)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unreadable blob, got %d", len(findings))
	}
}

func TestScanCacheBlobs_WalkError(t *testing.T) {
	dir := t.TempDir()
	unreadable := filepath.Join(dir, "noperm")
	if err := os.MkdirAll(unreadable, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}

	defer func() { _ = os.Chmod(unreadable, 0o755) }()

	lookups := buildCacheLookups(testIndex())
	findings, _ := scanCacheBlobs(dir, lookups)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanNvmDirs_WalkError(t *testing.T) {
	nvmDir := t.TempDir()
	t.Setenv("NVM_DIR", nvmDir)

	versionsDir := filepath.Join(nvmDir, "versions")
	unreadable := filepath.Join(versionsDir, "noperm")

	if err := os.MkdirAll(unreadable, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}

	defer func() { _ = os.Chmod(unreadable, 0o755) }()

	idx := testIndex()
	findings, _ := ScanNvmDirs(idx)

	// Should not crash.
	_ = findings
}

func TestScanCacheBlobs_ProgressLogging(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "ab")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create cacheProgressInterval+1 blobs to trigger progress logging.
	for i := 0; i <= cacheProgressInterval; i++ {
		name := filepath.Join(subdir, fmt.Sprintf("blob%d", i))
		if err := os.WriteFile(name, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	lookups := buildCacheLookups(testIndex())
	findings, _ := scanCacheBlobs(dir, lookups)

	// No crashes, just verifying the progress path runs.
	_ = findings
}

func TestMatchBlobAgainstIndex_VersionNotMatching(t *testing.T) {
	idx := &rules.PackageIndex{
		Packages: map[string][]*rules.VersionSet{
			"axios": {
				{
					RuleID: "R1", RuleTitle: "Test", Severity: "high",
					Versions: map[string]bool{"1.14.1": true},
				},
			},
		},
	}
	lookups := buildCacheLookups(idx)

	// Blob contains axios with a non-matching version nearby.
	blob := []byte(`"axios":"2.0.0","resolved":"test"`)
	findings, _ := matchBlobAgainstIndex(blob, "/cache/blob", "/cache", lookups)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-matching version, got %d", len(findings))
	}
}

func TestScanNvmDirs_VersionsDir(t *testing.T) {
	nvmDir := t.TempDir()
	t.Setenv("NVM_DIR", nvmDir)

	// Create versions/node/v18/lib/node_modules/<pkg>/package.json.
	nmDir := filepath.Join(nvmDir, "versions", "node", "v18.0.0", "lib", "node_modules")
	writePackageJSON(t, nmDir, "axios", "1.14.1")

	// Also create a node_modules dir NOT under lib/ — should be skipped.
	wrongDir := filepath.Join(nvmDir, "versions", "node", "v18.0.0", "bin", "node_modules")
	writePackageJSON(t, wrongDir, "axios", "1.14.1")

	idx := testIndex()
	findings, _ := ScanNvmDirs(idx)

	foundAxios := false
	for _, f := range findings {
		if f.Package == "axios" && f.Type == TypeInstalledPackage {
			foundAxios = true
		}
	}

	if !foundAxios {
		t.Error("expected to find axios in nvm versions lib/node_modules")
	}
}

func TestScanNpmCache_WithEnvCacheDir(t *testing.T) {
	home := t.TempDir()
	cacheDir := filepath.Join(home, "custom-cache")
	t.Setenv("NPM_CONFIG_CACHE", cacheDir)

	indexDir := filepath.Join(cacheDir, "_cacache", "index-v5", "ab")
	if err := os.MkdirAll(indexDir, 0o755); err != nil {
		t.Fatal(err)
	}

	blob := []byte(`{"axios":"1.14.1","integrity":"sha512-abc"}`)
	if err := os.WriteFile(filepath.Join(indexDir, "blob1"), blob, 0o600); err != nil {
		t.Fatal(err)
	}

	idx := testIndex()
	findings, _ := ScanNpmCache(idx)

	foundAxios := false
	for _, f := range findings {
		if f.Package == "axios" {
			foundAxios = true
		}
	}

	if !foundAxios {
		t.Error("expected to find axios via NPM_CONFIG_CACHE")
	}
}

// npmCachePathForOS tests.

func TestNpmCachePathForOS_EnvOverride(t *testing.T) {
	t.Setenv("NPM_CONFIG_CACHE", "/custom/cache")

	result := npmCachePathForOS("linux")
	if result != "/custom/cache" {
		t.Errorf("expected /custom/cache, got %s", result)
	}
}

func TestNpmCachePathForOS_Windows(t *testing.T) {
	t.Setenv("NPM_CONFIG_CACHE", "")

	localAppData := t.TempDir()
	t.Setenv("LOCALAPPDATA", localAppData)

	result := npmCachePathForOS("windows")

	expected := filepath.Join(localAppData, "npm-cache")
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestNpmCachePathForOS_WindowsNoLocalAppData(t *testing.T) {
	t.Setenv("NPM_CONFIG_CACHE", "")
	t.Setenv("LOCALAPPDATA", "")

	result := npmCachePathForOS("windows")
	if result != "" {
		t.Errorf("expected empty string, got %s", result)
	}
}

func TestNpmCachePathForOS_Linux(t *testing.T) {
	t.Setenv("NPM_CONFIG_CACHE", "")

	home := t.TempDir()

	orig := userHomeDir
	userHomeDir = func() (string, error) { return home, nil }
	defer func() { userHomeDir = orig }()

	result := npmCachePathForOS("linux")

	expected := filepath.Join(home, ".npm")
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestNpmCachePathForOS_NoHome(t *testing.T) {
	t.Setenv("NPM_CONFIG_CACHE", "")

	orig := userHomeDir
	userHomeDir = func() (string, error) { return "", fmt.Errorf("no home") }
	defer func() { userHomeDir = orig }()

	result := npmCachePathForOS("linux")
	if result != "" {
		t.Errorf("expected empty string, got %s", result)
	}
}

// pnpmStorePaths tests.

func TestPnpmStorePaths_Linux(t *testing.T) {
	t.Setenv("PNPM_HOME", "")

	home := t.TempDir()

	orig := userHomeDir
	userHomeDir = func() (string, error) { return home, nil }
	defer func() { userHomeDir = orig }()

	paths := pnpmStorePaths("linux")

	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}

	if paths[0] != filepath.Join(home, ".local", "share", "pnpm") {
		t.Errorf("unexpected path[0]: %s", paths[0])
	}

	if paths[1] != filepath.Join(home, ".cache", "pnpm") {
		t.Errorf("unexpected path[1]: %s", paths[1])
	}
}

func TestPnpmStorePaths_Windows(t *testing.T) {
	t.Setenv("PNPM_HOME", "")

	localAppData := t.TempDir()
	t.Setenv("LOCALAPPDATA", localAppData)

	home := t.TempDir()

	orig := userHomeDir
	userHomeDir = func() (string, error) { return home, nil }
	defer func() { userHomeDir = orig }()

	paths := pnpmStorePaths("windows")

	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}

	expected0 := filepath.Join(localAppData, "pnpm")
	expected1 := filepath.Join(localAppData, "pnpm-store")

	if paths[0] != expected0 {
		t.Errorf("expected %s, got %s", expected0, paths[0])
	}

	if paths[1] != expected1 {
		t.Errorf("expected %s, got %s", expected1, paths[1])
	}
}

func TestPnpmStorePaths_WindowsNoLocalAppData(t *testing.T) {
	t.Setenv("PNPM_HOME", "")
	t.Setenv("LOCALAPPDATA", "")

	home := t.TempDir()

	orig := userHomeDir
	userHomeDir = func() (string, error) { return home, nil }
	defer func() { userHomeDir = orig }()

	paths := pnpmStorePaths("windows")
	if len(paths) != 0 {
		t.Errorf("expected 0 paths, got %d: %v", len(paths), paths)
	}
}

func TestPnpmStorePaths_WithPnpmHomeEnv(t *testing.T) {
	t.Setenv("PNPM_HOME", "/custom/pnpm")

	home := t.TempDir()

	orig := userHomeDir
	userHomeDir = func() (string, error) { return home, nil }
	defer func() { userHomeDir = orig }()

	paths := pnpmStorePaths("linux")

	found := false
	for _, p := range paths {
		if p == "/custom/pnpm" {
			found = true
		}
	}

	if !found {
		t.Errorf("expected /custom/pnpm in paths, got %v", paths)
	}
}

func TestPnpmStorePaths_NoHome(t *testing.T) {
	t.Setenv("PNPM_HOME", "")

	orig := userHomeDir
	userHomeDir = func() (string, error) { return "", fmt.Errorf("no home") }
	defer func() { userHomeDir = orig }()

	paths := pnpmStorePaths("linux")
	if paths != nil {
		t.Errorf("expected nil, got %v", paths)
	}
}

// nvmDirPath tests.

func TestNvmDirPath_EnvOverride(t *testing.T) {
	t.Setenv("NVM_DIR", "/custom/nvm")

	result := nvmDirPath("linux")
	if result != "/custom/nvm" {
		t.Errorf("expected /custom/nvm, got %s", result)
	}
}

func TestNvmDirPath_WindowsNvmHome(t *testing.T) {
	t.Setenv("NVM_DIR", "")

	nvmHome := t.TempDir()
	t.Setenv("NVM_HOME", nvmHome)

	result := nvmDirPath("windows")
	if result != nvmHome {
		t.Errorf("expected %s, got %s", nvmHome, result)
	}
}

func TestNvmDirPath_WindowsFallbackAppdata(t *testing.T) {
	t.Setenv("NVM_DIR", "")
	t.Setenv("NVM_HOME", "")

	appdata := t.TempDir()
	t.Setenv("APPDATA", appdata)

	home := t.TempDir()

	orig := userHomeDir
	userHomeDir = func() (string, error) { return home, nil }
	defer func() { userHomeDir = orig }()

	result := nvmDirPath("windows")

	expected := filepath.Join(appdata, "nvm")
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestNvmDirPath_WindowsFallbackHome(t *testing.T) {
	t.Setenv("NVM_DIR", "")
	t.Setenv("NVM_HOME", "")
	t.Setenv("APPDATA", "")

	home := t.TempDir()

	orig := userHomeDir
	userHomeDir = func() (string, error) { return home, nil }
	defer func() { userHomeDir = orig }()

	result := nvmDirPath("windows")

	expected := filepath.Join(home, "AppData", "Roaming", "nvm")
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestNvmDirPath_LinuxFallback(t *testing.T) {
	t.Setenv("NVM_DIR", "")

	home := t.TempDir()

	orig := userHomeDir
	userHomeDir = func() (string, error) { return home, nil }
	defer func() { userHomeDir = orig }()

	result := nvmDirPath("linux")

	expected := filepath.Join(home, ".nvm")
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestNvmDirPath_NoHome(t *testing.T) {
	t.Setenv("NVM_DIR", "")
	t.Setenv("NVM_HOME", "")

	orig := userHomeDir
	userHomeDir = func() (string, error) { return "", fmt.Errorf("no home") }
	defer func() { userHomeDir = orig }()

	result := nvmDirPath("linux")
	if result != "" {
		t.Errorf("expected empty string, got %s", result)
	}
}
