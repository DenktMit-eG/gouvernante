package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gouvernante/pkg/heuristic"
)

func makeEvilPackage(t *testing.T, dir, pkgName, content string) {
	t.Helper()

	pkgDir := filepath.Join(dir, "node_modules", pkgName)
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"),
		[]byte(`{"name":"`+pkgName+`","version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(pkgDir, "index.js"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRunHeuristic_Clean(t *testing.T) {
	scanDir := t.TempDir()
	nmDir := filepath.Join(scanDir, "node_modules", "safe-pkg")

	if err := os.MkdirAll(nmDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(nmDir, "index.js"), []byte(`console.log("safe")`), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cfg := Config{ScanDir: scanDir, Heuristic: true}
	code := Run(cfg, &buf)

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestRunHeuristic_Findings(t *testing.T) {
	scanDir := t.TempDir()
	makeEvilPackage(t, scanDir, "evil-pkg", `eval(atob("d2hvYW1p"))`)

	var buf bytes.Buffer
	cfg := Config{ScanDir: scanDir, Heuristic: true}
	code := Run(cfg, &buf)

	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestRunHeuristic_JSONOutput(t *testing.T) {
	scanDir := t.TempDir()
	makeEvilPackage(t, scanDir, "evil-pkg", `eval(atob("x"))`)

	var buf bytes.Buffer
	cfg := Config{ScanDir: scanDir, Heuristic: true, JSONOutput: true}
	code := Run(cfg, &buf)

	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if report.Summary.TotalFindings != 1 {
		t.Errorf("expected 1 finding, got %d", report.Summary.TotalFindings)
	}
}

func TestRunHeuristic_NoNodeModules(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{ScanDir: t.TempDir(), Heuristic: true}
	code := Run(cfg, &buf)

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestRunHeuristic_Recursive(t *testing.T) {
	root := t.TempDir()
	projDir := filepath.Join(root, "project")
	makeEvilPackage(t, projDir, "evil-pkg", `eval(atob("x"))`)

	var buf bytes.Buffer
	cfg := Config{ScanDir: root, Heuristic: true, Recursive: true}
	code := Run(cfg, &buf)

	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestRunHeuristic_WriteError(t *testing.T) {
	scanDir := t.TempDir()

	var buf bytes.Buffer
	cfg := Config{ScanDir: scanDir, Heuristic: true, OutputFile: "/nonexistent/dir/report-heuristics.txt"}
	code := Run(cfg, &buf)

	if code != 1 {
		t.Errorf("expected exit code 1 for write error, got %d", code)
	}
}

func TestRunHeuristic_FormatError(t *testing.T) {
	original := jsonMarshalIndent
	jsonMarshalIndent = func(_ any, _ string, _ string) ([]byte, error) {
		return nil, fmt.Errorf("synthetic marshal error")
	}

	t.Cleanup(func() { jsonMarshalIndent = original })

	scanDir := t.TempDir()

	var buf bytes.Buffer
	cfg := Config{ScanDir: scanDir, Heuristic: true, JSONOutput: true}
	code := Run(cfg, &buf)

	if code != 1 {
		t.Errorf("expected exit code 1 for format error, got %d", code)
	}
}

func TestRunHeuristic_TextOutput(t *testing.T) {
	scanDir := t.TempDir()

	var buf bytes.Buffer
	cfg := Config{ScanDir: scanDir, Heuristic: true}
	code := Run(cfg, &buf)

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	out := buf.String()
	if !strings.Contains(out, "heuristic scan") {
		t.Error("expected text output to contain 'heuristic scan'")
	}
}

func TestRunHeuristic_ScanError(t *testing.T) {
	scanDir := t.TempDir()

	// Create a node_modules directory so the path exists.
	nmDir := filepath.Join(scanDir, "node_modules")
	if err := os.MkdirAll(nmDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Inject a stat function that returns a non-NotExist error.
	origStat := heuristic.OsStat
	heuristic.OsStat = func(name string) (os.FileInfo, error) {
		return nil, fmt.Errorf("injected permission error")
	}

	t.Cleanup(func() { heuristic.OsStat = origStat })

	var buf bytes.Buffer
	cfg := Config{ScanDir: scanDir, Heuristic: true}
	code := Run(cfg, &buf)

	if code != 1 {
		t.Errorf("expected exit code 1 for scan error, got %d", code)
	}
}

func TestBuildHeuristicHeader(t *testing.T) {
	cfg := Config{ScanDir: "/test/dir"}
	header := buildHeuristicHeader(cfg, 3)

	if !strings.Contains(header, "/test/dir") {
		t.Error("expected directory in header")
	}

	if !strings.Contains(header, "3") {
		t.Error("expected finding count in header")
	}
}

func TestFormatCount(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{100, "100"},
	}

	for _, tt := range tests {
		got := formatCount(tt.input)
		if got != tt.want {
			t.Errorf("formatCount(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
