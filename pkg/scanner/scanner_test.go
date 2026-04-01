package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gouvernante/pkg/lockfile"
	"gouvernante/pkg/rules"
)

func TestScanPackages_Matches(t *testing.T) {
	entries := []lockfile.PackageEntry{
		{Name: "axios", Version: "1.7.8"},
		{Name: "express", Version: "4.18.2"},
		{Name: "plain-crypto-js", Version: "1.0.0"},
	}

	idx := &rules.PackageIndex{
		Packages: map[string]*rules.VersionSet{
			"axios": {
				RuleID:    "R1",
				RuleTitle: "Axios compromise",
				Severity:  "critical",
				Versions:  map[string]bool{"1.7.8": true},
			},
			"plain-crypto-js": {
				RuleID:     "R1",
				RuleTitle:  "Axios compromise",
				Severity:   "critical",
				AnyVersion: true,
			},
		},
	}

	findings := ScanPackages(entries, idx, "pnpm-lock.yaml")

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// Verify first finding.
	if findings[0].Package != "axios" || findings[0].Version != "1.7.8" {
		t.Errorf("finding 0: got %s@%s, want axios@1.7.8", findings[0].Package, findings[0].Version)
	}

	if findings[0].Lockfile != "pnpm-lock.yaml" {
		t.Errorf("finding 0 lockfile: got %q, want pnpm-lock.yaml", findings[0].Lockfile)
	}

	// Verify dropper finding.
	if findings[1].Package != "plain-crypto-js" {
		t.Errorf("finding 1: got %s, want plain-crypto-js", findings[1].Package)
	}
}

func TestScanPackages_NoMatches(t *testing.T) {
	entries := []lockfile.PackageEntry{
		{Name: "express", Version: "4.18.2"},
		{Name: "lodash", Version: "4.17.21"},
	}

	idx := &rules.PackageIndex{
		Packages: map[string]*rules.VersionSet{
			"axios": {
				RuleID:   "R1",
				Severity: "critical",
				Versions: map[string]bool{"1.7.8": true},
			},
		},
	}

	findings := ScanPackages(entries, idx, "package-lock.json")

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanPackages_EmptyIndex(t *testing.T) {
	entries := []lockfile.PackageEntry{
		{Name: "axios", Version: "1.7.8"},
	}

	idx := &rules.PackageIndex{
		Packages: map[string]*rules.VersionSet{},
	}

	findings := ScanPackages(entries, idx, "test")

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanHostIndicators_FileExists(t *testing.T) {
	dir := t.TempDir()
	indicator := filepath.Join(dir, "malware.bin")

	if err := os.WriteFile(indicator, []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}

	ruleList := []rules.Rule{
		{
			ID:       "R1",
			Title:    "Test IOC",
			Severity: "critical",
			HostIndicators: []rules.HostIndicator{
				{
					Type:     "file",
					Path:     dir,
					FileName: "malware.bin",
					OSes:     []string{mapOSName("linux"), mapOSName("darwin"), "linux", "macos", "windows"},
					Notes:    "Test indicator",
				},
			},
		},
	}

	findings, _ := ScanHostIndicators(ruleList)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Type != "host_indicator" {
		t.Errorf("type: got %q, want host_indicator", findings[0].Type)
	}

	if findings[0].Path != indicator {
		t.Errorf("path: got %q, want %q", findings[0].Path, indicator)
	}
}

func TestScanHostIndicators_FileDoesNotExist(t *testing.T) {
	ruleList := []rules.Rule{
		{
			ID:       "R1",
			Title:    "Test IOC",
			Severity: "critical",
			HostIndicators: []rules.HostIndicator{
				{
					Type:     "file",
					Path:     "/nonexistent/path",
					FileName: "malware.bin",
					OSes:     []string{"linux", "macos", "windows"},
				},
			},
		},
	}

	findings, _ := ScanHostIndicators(ruleList)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanHostIndicators_WrongOS(t *testing.T) {
	dir := t.TempDir()
	indicator := filepath.Join(dir, "malware.bin")

	if err := os.WriteFile(indicator, []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Use an OS that doesn't match the current platform.
	ruleList := []rules.Rule{
		{
			ID:       "R1",
			Title:    "Test IOC",
			Severity: "critical",
			HostIndicators: []rules.HostIndicator{
				{
					Type:     "file",
					Path:     dir,
					FileName: "malware.bin",
					OSes:     []string{"nonexistent_os"},
				},
			},
		},
	}

	findings, _ := ScanHostIndicators(ruleList)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for wrong OS, got %d", len(findings))
	}
}

func TestScanHostIndicators_NonFileType(t *testing.T) {
	ruleList := []rules.Rule{
		{
			ID:       "R1",
			Title:    "Test",
			Severity: "high",
			HostIndicators: []rules.HostIndicator{
				{
					Type:  "process",
					Value: "some-process",
					OSes:  []string{"linux", "macos", "windows"},
				},
			},
		},
	}

	findings, _ := ScanHostIndicators(ruleList)

	if len(findings) != 0 {
		t.Errorf("non-file indicators should be skipped, got %d findings", len(findings))
	}
}

func TestFormatReport_NoFindings(t *testing.T) {
	result := &Result{
		Findings:      nil,
		PackagesTotal: 42,
		LockfilesUsed: []string{"pnpm-lock.yaml"},
	}

	report := FormatReport(result)

	if !strings.Contains(report, "Total packages analyzed: 42") {
		t.Error("report should contain package count")
	}

	if !strings.Contains(report, "Findings: 0") {
		t.Error("report should show 0 findings")
	}

	if !strings.Contains(report, "No compromised packages") {
		t.Error("report should contain clean message")
	}
}

func TestFormatReport_WithFindings(t *testing.T) {
	result := &Result{
		Findings: []Finding{
			{
				RuleID:    "R1",
				RuleTitle: "Test rule",
				Severity:  "critical",
				Type:      "package",
				Package:   "axios",
				Version:   "1.7.8",
				Lockfile:  "pnpm-lock.yaml",
			},
			{
				RuleID:      "R1",
				RuleTitle:   "Test rule",
				Severity:    "critical",
				Type:        "host_indicator",
				Description: "RAT binary",
				Path:        "/tmp/malware",
			},
		},
		PackagesTotal: 100,
		LockfilesUsed: []string{"pnpm-lock.yaml"},
	}

	report := FormatReport(result)

	if !strings.Contains(report, "Findings: 2") {
		t.Error("report should show 2 findings")
	}

	if !strings.Contains(report, "axios@1.7.8") {
		t.Error("report should contain package finding")
	}

	if !strings.Contains(report, "host indicator") {
		t.Error("report should contain host indicator finding")
	}

	if !strings.Contains(report, "/tmp/malware") {
		t.Error("report should contain IOC path")
	}
}

func TestMapOSName(t *testing.T) {
	tests := []struct {
		goos string
		want string
	}{
		{"darwin", "macos"},
		{"linux", "linux"},
		{"windows", "windows"},
	}

	for _, tt := range tests {
		got := mapOSName(tt.goos)
		if got != tt.want {
			t.Errorf("mapOSName(%q) = %q, want %q", tt.goos, got, tt.want)
		}
	}
}

func TestOsMatch(t *testing.T) {
	tests := []struct {
		name    string
		oses    []string
		current string
		want    bool
	}{
		{"empty allows all", nil, "linux", true},
		{"match", []string{"linux", "macos"}, "linux", true},
		{"no match", []string{"windows"}, "linux", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := osMatch(tt.oses, tt.current)
			if got != tt.want {
				t.Errorf("osMatch(%v, %q) = %v, want %v", tt.oses, tt.current, got, tt.want)
			}
		})
	}
}

func TestExpandPath(t *testing.T) {
	// Test home directory expansion.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home dir")
	}

	got := expandPath("~/test")
	want := filepath.Join(home, "test")

	if got != want {
		t.Errorf("expandPath(~/test) = %q, want %q", got, want)
	}
}

func TestExpandPath_NoExpansion(t *testing.T) {
	got := expandPath("/absolute/path")
	if got != "/absolute/path" {
		t.Errorf("expandPath(/absolute/path) = %q, want /absolute/path", got)
	}
}

func TestExpandPath_ProgramData(t *testing.T) {
	t.Setenv("PROGRAMDATA", "/test/programdata")
	got := expandPath("%PROGRAMDATA%\\malware")

	if got != "/test/programdata\\malware" {
		t.Errorf("expandPath(%%PROGRAMDATA%%\\malware) = %q, want /test/programdata\\malware", got)
	}
}

func TestExpandPath_ProgramDataDefault(t *testing.T) {
	t.Setenv("PROGRAMDATA", "")
	got := expandPath("%PROGRAMDATA%\\malware")

	if got != `C:\ProgramData\malware` {
		t.Errorf("expandPath(%%PROGRAMDATA%%) with empty env = %q, want C:\\ProgramData\\malware", got)
	}
}

func TestExpandPath_AppData(t *testing.T) {
	t.Setenv("APPDATA", "/test/appdata")
	got := expandPath("%APPDATA%\\config")

	if got != "/test/appdata\\config" {
		t.Errorf("expandPath(%%APPDATA%%\\config) = %q, want /test/appdata\\config", got)
	}
}

func TestExpandPath_Temp(t *testing.T) {
	t.Setenv("TEMP", "/test/temp")
	got := expandPath("%TEMP%\\6202033.vbs")

	if got != "/test/temp\\6202033.vbs" {
		t.Errorf("expandPath(%%TEMP%%\\6202033.vbs) = %q, want /test/temp\\6202033.vbs", got)
	}
}

func TestExpandPath_TempDefault(t *testing.T) {
	t.Setenv("TEMP", "")
	got := expandPath("%TEMP%\\payload")
	want := os.TempDir() + "\\payload"

	if got != want {
		t.Errorf("expandPath(%%TEMP%%) with empty env = %q, want %q", got, want)
	}
}

func TestBuildIndicatorPath_PathOnly(t *testing.T) {
	hi := &rules.HostIndicator{
		Type: "file",
		Path: "/tmp/malware.bin",
		OSes: []string{"linux"},
	}
	got := buildIndicatorPath(hi)

	if got != "/tmp/malware.bin" {
		t.Errorf("buildIndicatorPath (path only) = %q, want /tmp/malware.bin", got)
	}
}

func TestBuildIndicatorPath_PathAndFileName(t *testing.T) {
	hi := &rules.HostIndicator{
		Type:     "file",
		Path:     "/tmp",
		FileName: "malware.bin",
		OSes:     []string{"linux"},
	}
	got := buildIndicatorPath(hi)
	want := "/tmp" + string(filepath.Separator) + "malware.bin"

	if got != want {
		t.Errorf("buildIndicatorPath (path+filename) = %q, want %q", got, want)
	}
}
