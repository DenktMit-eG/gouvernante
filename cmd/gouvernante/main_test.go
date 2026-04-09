package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// helperProcess re-executes the test binary as a child process.
// The child detects GOUVERNANTE_TEST_SUBPROCESS=1 and calls main().
// The parent inspects exit code and output.
func helperProcess(t *testing.T, args ...string) (output string, exitCode int) {
	t.Helper()

	binary := os.Args[0]

	cmd := exec.CommandContext(context.Background(), binary, "-test.run=TestSubprocess") //nolint:gosec // test-only subprocess
	cmd.Env = append(os.Environ(), "GOUVERNANTE_TEST_SUBPROCESS=1",
		"GOUVERNANTE_TEST_ARGS="+strings.Join(args, "\x1f"))

	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return string(out), exitErr.ExitCode()
		}

		t.Fatalf("failed to run subprocess: %v", err)
	}

	return string(out), 0
}

// TestSubprocess is the entry point for child processes. It is not a real test —
// it calls main() with the arguments passed via GOUVERNANTE_TEST_ARGS.
func TestSubprocess(t *testing.T) {
	if os.Getenv("GOUVERNANTE_TEST_SUBPROCESS") != "1" {
		t.Skip("not a subprocess invocation")
	}

	argsStr := os.Getenv("GOUVERNANTE_TEST_ARGS")
	if argsStr != "" {
		os.Args = append([]string{"gouvernante"}, strings.Split(argsStr, "\x1f")...)
	} else {
		os.Args = []string{"gouvernante"}
	}

	main()
}

func TestMain_VersionFlag(t *testing.T) {
	out, code := helperProcess(t, "-version")
	if code != 0 {
		t.Errorf("expected exit code 0 for -version, got %d", code)
	}

	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		t.Error("expected version output, got empty string")
	}
}

func TestMain_VersionExitsEarly(t *testing.T) {
	origArgs := os.Args
	origFlags := flag.CommandLine
	origExit := osExit

	defer func() {
		os.Args = origArgs
		flag.CommandLine = origFlags
		osExit = origExit
	}()

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = []string{"gouvernante", "-version"}

	exitCalled := false
	osExit = func(_ int) { exitCalled = true }

	main()

	if exitCalled {
		t.Error("os.Exit should not be called when -version is used")
	}
}

func TestParseFlags_Version(t *testing.T) {
	origArgs := os.Args
	origFlags := flag.CommandLine

	defer func() {
		os.Args = origArgs
		flag.CommandLine = origFlags
	}()

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = []string{"gouvernante", "-version"}

	var buf strings.Builder

	_, exit := parseFlags(&buf)
	if !exit {
		t.Error("expected exit=true for -version")
	}

	if !strings.Contains(buf.String(), version) {
		t.Errorf("expected version %q in output, got %q", version, buf.String())
	}
}

func TestMain_MissingRulesFlag(t *testing.T) {
	_, code := helperProcess(t)
	if code != 1 {
		t.Errorf("expected exit code 1 for missing -rules, got %d", code)
	}
}

func TestMain_InvalidRulesDir(t *testing.T) {
	_, code := helperProcess(t, "-rules", "/nonexistent/rules/dir")
	if code != 1 {
		t.Errorf("expected exit code 1 for invalid rules dir, got %d", code)
	}
}

func TestMain_CleanScan(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestRule(t, rulesDir)

	scanDir := t.TempDir()
	writeTestLockfile(t, scanDir, `{"dependencies":{"express":"4.18.0"}}`)

	out, code := helperProcess(t, "-rules", rulesDir, "-dir", scanDir)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d\noutput: %s", code, out)
	}
}

func TestMain_WithFindings(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestRule(t, rulesDir)

	scanDir := t.TempDir()
	writeTestLockfile(t, scanDir, `{"dependencies":{"axios":"1.7.8"}}`)

	_, code := helperProcess(t, "-rules", rulesDir, "-dir", scanDir)
	if code != 2 {
		t.Errorf("expected exit code 2 for findings, got %d", code)
	}
}

func TestMain_JSONOutput(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestRule(t, rulesDir)

	scanDir := t.TempDir()
	writeTestLockfile(t, scanDir, `{"dependencies":{"express":"4.18.0"}}`)

	out, code := helperProcess(t, "-rules", rulesDir, "-dir", scanDir, "-json")
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	if !strings.Contains(out, `"findings"`) {
		t.Error("expected JSON output with findings key")
	}
}

func TestMain_TraceFlag(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestRule(t, rulesDir)

	scanDir := t.TempDir()
	writeTestLockfile(t, scanDir, `{"dependencies":{"express":"4.18.0"}}`)

	_, code := helperProcess(t, "-rules", rulesDir, "-dir", scanDir, "-trace")
	if code != 0 {
		t.Errorf("expected exit code 0 with -trace, got %d", code)
	}
}

func TestMain_FileOutput(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestRule(t, rulesDir)

	scanDir := t.TempDir()
	writeTestLockfile(t, scanDir, `{"dependencies":{"express":"4.18.0"}}`)

	outFile := filepath.Join(t.TempDir(), "report.txt")
	_, code := helperProcess(t, "-rules", rulesDir, "-dir", scanDir, "-output", outFile)

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

// writeTestRule creates a minimal valid rule file in dir.
func writeTestRule(t *testing.T, dir string) {
	t.Helper()

	rule := `{
  "schema_version": "1.0.0",
  "rules": [{
    "id": "SSC-TEST-001",
    "title": "Test rule",
    "kind": "compromised-release",
    "ecosystem": "npm",
    "severity": "critical",
    "package_rules": [{"package_name": "axios", "affected_versions": ["=1.7.8"]}]
  }]
}`

	if err := os.WriteFile(filepath.Join(dir, "rule.json"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeTestLockfile creates a package.json in dir.
func writeTestLockfile(t *testing.T, dir, content string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
