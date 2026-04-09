package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gouvernante/pkg/lockfile"
	"gouvernante/pkg/rules"
	"gouvernante/pkg/scanner"
)

const validRuleJSON = `{
  "schema_version": "1.0.0",
  "rules": [
    {
      "id": "SSC-TEST-001",
      "title": "Test rule",
      "kind": "compromised-release",
      "ecosystem": "npm",
      "severity": "critical",
      "package_rules": [
        {
          "package_name": "axios",
          "affected_versions": ["=1.7.8"]
        }
      ]
    }
  ]
}`

func writeRule(t *testing.T, dir, name, content string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// LoadRules tests.

func TestLoadRules_Valid(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "rule.json", validRuleJSON)

	ruleList, err := LoadRules(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ruleList) != 1 {
		t.Errorf("expected 1 rule, got %d", len(ruleList))
	}
}

func TestLoadRules_MissingDir(t *testing.T) {
	_, err := LoadRules("/nonexistent/rules/dir")
	if err == nil {
		t.Fatal("expected error for missing directory")
	}
}

func TestLoadRules_NotADir(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(f, []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadRules(f)
	if err == nil {
		t.Fatal("expected error for non-directory path")
	}
}

func TestLoadRules_EmptyDir(t *testing.T) {
	_, err := LoadRules(t.TempDir())
	if err == nil {
		t.Fatal("expected error for empty rules directory")
	}
}

func TestLoadRules_InvalidRule(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "bad.json", `{"schema_version":"1.0.0","rules":[{"id":"","title":"x","kind":"vulnerability","ecosystem":"npm","severity":"low","package_rules":[{"package_name":"x","affected_versions":["*"]}]}]}`)

	_, err := LoadRules(dir)
	if err == nil {
		t.Fatal("expected error for invalid rule")
	}
}

// ParseLockfiles tests.

func TestParseLockfiles_SpecificFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")

	if err := os.WriteFile(path, []byte(`{"dependencies":{"a":"1.0.0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := Config{LockfilePath: path}

	results, err := ParseLockfiles(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestParseLockfiles_DirectoryScan(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"a":"1.0.0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := Config{ScanDir: dir}

	results, err := ParseLockfiles(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) == 0 {
		t.Error("expected at least 1 result")
	}
}

func TestParseLockfiles_RecursiveScan(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")

	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(sub, "package.json"), []byte(`{"dependencies":{"a":"1.0.0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := Config{ScanDir: root, Recursive: true}

	results, err := ParseLockfiles(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) == 0 {
		t.Error("expected at least 1 result from recursive scan")
	}
}

func TestParseLockfiles_ParseError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package-lock.json")

	if err := os.WriteFile(path, []byte("{bad json}"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := Config{LockfilePath: path}

	_, err := ParseLockfiles(cfg)
	if err == nil {
		t.Fatal("expected error for invalid lockfile")
	}
}

func TestParseLockfiles_EmptyDirectory(t *testing.T) {
	cfg := Config{ScanDir: t.TempDir()}

	results, err := ParseLockfiles(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results for empty dir, got %d", len(results))
	}
}

func TestParseLockfiles_NoLockfilesFound(t *testing.T) {
	cfg := Config{ScanDir: t.TempDir()}

	results, err := ParseLockfiles(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

// ScanAll tests.

func TestScanAll_WithFindings(t *testing.T) {
	entries := []lockfile.PackageEntry{{Name: "axios", Version: "1.7.8"}}
	lr := []lockfile.Result{{Name: "package-lock.json", Entries: entries}}

	ruleList := []rules.Rule{
		{
			ID: "R1", Title: "Test", Kind: "compromised-release",
			Ecosystem: "npm", Severity: "critical",
			PackageRules: []rules.PackageRule{
				{PackageName: "axios", AffectedVersions: []string{"1.7.8"}},
			},
		},
	}
	idx := rules.BuildPackageIndex(ruleList)
	cfg := Config{}

	findings, _, _ := ScanAll(lr, idx, ruleList, cfg)

	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

func TestScanAll_NoFindings(t *testing.T) {
	entries := []lockfile.PackageEntry{{Name: "express", Version: "4.18.0"}}
	lr := []lockfile.Result{{Name: "package-lock.json", Entries: entries}}

	ruleList := []rules.Rule{
		{
			ID: "R1", Title: "Test", Kind: "compromised-release",
			Ecosystem: "npm", Severity: "critical",
			PackageRules: []rules.PackageRule{
				{PackageName: "axios", AffectedVersions: []string{"1.7.8"}},
			},
		},
	}
	idx := rules.BuildPackageIndex(ruleList)
	cfg := Config{}

	findings, _, _ := ScanAll(lr, idx, ruleList, cfg)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanAll_WithHostCheck(t *testing.T) {
	entries := []lockfile.PackageEntry{{Name: "express", Version: "4.18.0"}}
	lr := []lockfile.Result{{Name: "package-lock.json", Path: filepath.Join(t.TempDir(), "package-lock.json"), Entries: entries}}

	ruleList := []rules.Rule{
		{
			ID: "R1", Title: "Test", Kind: "compromised-release",
			Ecosystem: "npm", Severity: "critical",
			PackageRules: []rules.PackageRule{
				{PackageName: "nonexistent-pkg-12345", AffectedVersions: []string{"*"}},
			},
		},
	}
	idx := rules.BuildPackageIndex(ruleList)
	cfg := Config{HostCheck: true}

	// Should not crash — host scan runs against filesystem.
	findings, hostChecks, nmChecks := ScanAll(lr, idx, ruleList, cfg)
	_ = findings
	_ = hostChecks
	_ = nmChecks
}

func TestParseLockfiles_RecursiveError(t *testing.T) {
	// Create a dir with an unreadable subdirectory to trigger recursive walk error.
	root := t.TempDir()
	sub := filepath.Join(root, "sub")

	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	// Write an invalid lockfile that will cause a parse error during recursive walk.
	if err := os.WriteFile(filepath.Join(sub, "package-lock.json"), []byte("{bad json}"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := Config{ScanDir: root, Recursive: true}

	_, err := ParseLockfiles(cfg)
	if err == nil {
		t.Fatal("expected error for invalid lockfile during recursive scan")
	}
}

// ExtractProjectDirs tests.

func TestExtractProjectDirs_WithPath(t *testing.T) {
	results := []lockfile.Result{
		{Name: "package-lock.json", Path: "/some/project/package-lock.json"},
	}

	dirs := ExtractProjectDirs(results, "/other/dir")

	if len(dirs) != 1 || dirs[0] != "/some/project" {
		t.Errorf("expected [/some/project], got %v", dirs)
	}
}

func TestExtractProjectDirs_WithoutPath(t *testing.T) {
	results := []lockfile.Result{
		{Name: "package-lock.json"},
	}

	dirs := ExtractProjectDirs(results, "/scan/dir")

	if len(dirs) != 1 || dirs[0] != "/scan/dir" {
		t.Errorf("expected [/scan/dir], got %v", dirs)
	}
}

func TestExtractProjectDirs_Dedup(t *testing.T) {
	results := []lockfile.Result{
		{Name: "package-lock.json", Path: "/project/package-lock.json"},
		{Name: "yarn.lock", Path: "/project/yarn.lock"},
	}

	dirs := ExtractProjectDirs(results, ".")

	if len(dirs) != 1 {
		t.Errorf("expected 1 deduped dir, got %d", len(dirs))
	}
}

// FormatOutput tests.

func TestFormatOutput_JSON(t *testing.T) {
	result := &scanner.Result{
		Findings: []scanner.Finding{
			{RuleID: "R1", Package: "axios", Version: "1.7.8", Severity: "critical", Type: scanner.TypePackage},
		},
		LockfilesUsed: []string{"pnpm-lock.yaml"},
	}

	output, err := FormatOutput(result, true, 42*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if report.Summary.TotalFindings != 1 {
		t.Errorf("expected total_findings=1, got %d", report.Summary.TotalFindings)
	}

	if report.Summary.LockfilesScanned != 1 {
		t.Errorf("expected lockfiles_scanned=1, got %d", report.Summary.LockfilesScanned)
	}

	if report.Summary.ElapsedMs != 42 {
		t.Errorf("expected elapsed_ms=42, got %d", report.Summary.ElapsedMs)
	}
}

func TestFormatOutput_JSONEmptyFindings(t *testing.T) {
	result := &scanner.Result{}

	output, err := FormatOutput(result, true, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should serialize as empty array, not null.
	if !strings.Contains(output, `"findings": []`) {
		t.Error("expected empty findings array, not null")
	}
}

func TestFormatOutput_JSONMarshalError(t *testing.T) {
	original := jsonMarshalIndent
	jsonMarshalIndent = func(_ any, _ string, _ string) ([]byte, error) {
		return nil, fmt.Errorf("synthetic marshal error")
	}

	t.Cleanup(func() { jsonMarshalIndent = original })

	result := &scanner.Result{
		Findings: []scanner.Finding{
			{RuleID: "R1", Package: "p", Version: "1.0.0", Severity: "critical", Type: scanner.TypePackage},
		},
	}

	_, err := FormatOutput(result, true, 0)
	if err == nil {
		t.Fatal("expected error from FormatOutput")
	}

	if !strings.Contains(err.Error(), "marshal JSON") {
		t.Errorf("expected 'marshal JSON' in error, got: %v", err)
	}
}

func TestFormatOutput_Text(t *testing.T) {
	result := &scanner.Result{
		Findings:      nil,
		PackagesTotal: 42,
		LockfilesUsed: []string{"pnpm-lock.yaml"},
	}

	output, err := FormatOutput(result, false, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "Supply Chain Scan Report") {
		t.Error("expected text report header")
	}
}

// WriteOutput tests.

func TestWriteOutput_Stdout(t *testing.T) {
	var buf bytes.Buffer

	err := WriteOutput(&buf, "header\n", "body\n", "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if buf.String() != "header\nbody\n" {
		t.Errorf("unexpected output: %q", buf.String())
	}
}

func TestWriteOutput_File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report-heuristics.txt")
	var buf bytes.Buffer

	err := WriteOutput(&buf, "header\n", "body\n", path, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if string(data) != "header\nbody\n" {
		t.Errorf("unexpected file content: %q", string(data))
	}
}

func TestWriteOutput_FileNotStdout(t *testing.T) {
	var buf bytes.Buffer
	outFile := filepath.Join(t.TempDir(), "report-heuristics.txt")

	err := WriteOutput(&buf, "header\n", "body\n", outFile, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if buf.Len() != 0 {
		t.Errorf("expected no stdout output when writing to file, got %d bytes", buf.Len())
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if string(data) != "header\nbody\n" {
		t.Errorf("unexpected file content: %q", string(data))
	}
}

func TestWriteOutput_AutoTxt(t *testing.T) {
	// Change to temp dir so auto-named file is created there.
	orig, _ := os.Getwd()
	dir := t.TempDir()
	_ = os.Chdir(dir)

	defer func() { _ = os.Chdir(orig) }()

	var buf bytes.Buffer

	err := WriteOutput(&buf, "", "content", "auto", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entries, _ := os.ReadDir(dir)

	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "gouvernante-") && strings.HasSuffix(e.Name(), ".txt") {
			found = true
		}
	}

	if !found {
		t.Error("expected auto-generated .txt file")
	}
}

func TestWriteOutput_AutoJSON(t *testing.T) {
	orig, _ := os.Getwd()
	dir := t.TempDir()
	_ = os.Chdir(dir)

	defer func() { _ = os.Chdir(orig) }()

	var buf bytes.Buffer

	err := WriteOutput(&buf, "", "content", "auto", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entries, _ := os.ReadDir(dir)

	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "gouvernante-") && strings.HasSuffix(e.Name(), ".json") {
			found = true
		}
	}

	if !found {
		t.Error("expected auto-generated .json file")
	}
}

func TestWriteOutput_FileError(t *testing.T) {
	var buf bytes.Buffer

	err := WriteOutput(&buf, "", "content", "/nonexistent/dir/report-heuristics.txt", false)
	if err == nil {
		t.Fatal("expected error for unwritable path")
	}
}

// ConfigureLogging tests.

func TestConfigureLogging_Default(t *testing.T) {
	ConfigureLogging(Config{})
	// Should not panic.
}

func TestConfigureLogging_Trace(t *testing.T) {
	ConfigureLogging(Config{Trace: true})
	// Should not panic.
}

// Run integration tests.

func TestRun_Clean(t *testing.T) {
	rulesDir := t.TempDir()
	writeRule(t, rulesDir, "rule.json", validRuleJSON)

	scanDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(scanDir, "package.json"), []byte(`{"dependencies":{"express":"4.18.0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cfg := Config{RulesDir: rulesDir, ScanDir: scanDir}
	code := Run(cfg, &buf)

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestRun_Findings(t *testing.T) {
	rulesDir := t.TempDir()
	writeRule(t, rulesDir, "rule.json", validRuleJSON)

	scanDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(scanDir, "package.json"), []byte(`{"dependencies":{"axios":"1.7.8"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cfg := Config{RulesDir: rulesDir, ScanDir: scanDir}
	code := Run(cfg, &buf)

	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestRun_BadRulesDir(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{RulesDir: "/nonexistent", ScanDir: "."}
	code := Run(cfg, &buf)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestRun_EmptyScanDir(t *testing.T) {
	rulesDir := t.TempDir()
	writeRule(t, rulesDir, "rule.json", validRuleJSON)

	// Empty scan dir has no lockfiles → exit 0 (clean, no findings).
	var buf bytes.Buffer
	cfg := Config{RulesDir: rulesDir, ScanDir: t.TempDir()}
	code := Run(cfg, &buf)

	if code != 0 {
		t.Errorf("expected exit code 0 (no lockfiles = clean), got %d", code)
	}
}

func TestRun_BadLockfilePath(t *testing.T) {
	rulesDir := t.TempDir()
	writeRule(t, rulesDir, "rule.json", validRuleJSON)

	var buf bytes.Buffer
	cfg := Config{RulesDir: rulesDir, LockfilePath: "/nonexistent/package-lock.json"}
	code := Run(cfg, &buf)

	if code != 1 {
		t.Errorf("expected exit code 1 for bad lockfile path, got %d", code)
	}
}

func TestRun_JSONOutput(t *testing.T) {
	rulesDir := t.TempDir()
	writeRule(t, rulesDir, "rule.json", validRuleJSON)

	scanDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(scanDir, "package.json"), []byte(`{"dependencies":{"express":"4.18.0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cfg := Config{RulesDir: rulesDir, ScanDir: scanDir, JSONOutput: true}
	code := Run(cfg, &buf)

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
}

func TestRun_WriteError(t *testing.T) {
	rulesDir := t.TempDir()
	writeRule(t, rulesDir, "rule.json", validRuleJSON)

	scanDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(scanDir, "package.json"), []byte(`{"dependencies":{"express":"4.18.0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Write to a file in a nonexistent directory → WriteOutput fails.
	var buf bytes.Buffer
	cfg := Config{RulesDir: rulesDir, ScanDir: scanDir, OutputFile: "/nonexistent/dir/report-heuristics.txt"}
	code := Run(cfg, &buf)

	if code != 1 {
		t.Errorf("expected exit code 1 for write error, got %d", code)
	}
}

func TestRun_FormatError(t *testing.T) {
	original := jsonMarshalIndent
	jsonMarshalIndent = func(_ any, _ string, _ string) ([]byte, error) {
		return nil, fmt.Errorf("synthetic marshal error")
	}

	t.Cleanup(func() { jsonMarshalIndent = original })

	rulesDir := t.TempDir()
	writeRule(t, rulesDir, "rule.json", validRuleJSON)

	scanDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(scanDir, "package.json"), []byte(`{"dependencies":{"express":"4.18.0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cfg := Config{RulesDir: rulesDir, ScanDir: scanDir, JSONOutput: true}
	code := Run(cfg, &buf)

	if code != 1 {
		t.Errorf("expected exit code 1 for format error, got %d", code)
	}
}

func TestRun_FileOutput(t *testing.T) {
	rulesDir := t.TempDir()
	writeRule(t, rulesDir, "rule.json", validRuleJSON)

	scanDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(scanDir, "package.json"), []byte(`{"dependencies":{"express":"4.18.0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	outFile := filepath.Join(t.TempDir(), "report-heuristics.txt")
	var buf bytes.Buffer
	cfg := Config{RulesDir: rulesDir, ScanDir: scanDir, OutputFile: outFile}
	code := Run(cfg, &buf)

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty report file")
	}
}

func TestRun_TextReportContainsHeader(t *testing.T) {
	rulesDir := t.TempDir()
	writeRule(t, rulesDir, "rule.json", validRuleJSON)

	scanDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(scanDir, "package.json"), []byte(`{"dependencies":{"express":"4.18.0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cfg := Config{RulesDir: rulesDir, ScanDir: scanDir}
	code := Run(cfg, &buf)

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	out := buf.String()
	if !strings.Contains(out, "Scan Configuration") {
		t.Error("expected text report to contain 'Scan Configuration' header")
	}

	if !strings.Contains(out, "Supply Chain Scan Report") {
		t.Error("expected text report to contain scan report section")
	}
}
