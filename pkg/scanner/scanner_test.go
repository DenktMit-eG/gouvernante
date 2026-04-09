package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gouvernante/pkg/lockfile"
	"gouvernante/pkg/rules"

	"github.com/Masterminds/semver/v3"
)

func TestScanPackages_Matches(t *testing.T) {
	entries := []lockfile.PackageEntry{
		{Name: "axios", Version: "1.7.8"},
		{Name: "express", Version: "4.18.2"},
		{Name: "plain-crypto-js", Version: "1.0.0"},
	}

	idx := &rules.PackageIndex{
		Packages: map[string][]*rules.VersionSet{
			"axios": {
				{
					RuleID:    "R1",
					RuleTitle: "Axios compromise",
					Severity:  "critical",
					Versions:  map[string]bool{"1.7.8": true},
				},
			},
			"plain-crypto-js": {
				{
					RuleID:     "R1",
					RuleTitle:  "Axios compromise",
					Severity:   "critical",
					AnyVersion: true,
				},
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
		Packages: map[string][]*rules.VersionSet{
			"axios": {
				{
					RuleID:   "R1",
					Severity: "critical",
					Versions: map[string]bool{"1.7.8": true},
				},
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
		Packages: map[string][]*rules.VersionSet{},
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

func TestScanHostIndicators_FileNameOnlyNoPath(t *testing.T) {
	// A file indicator with file_name but no path triggers the CWD warning
	// and resolves relative to CWD. The file won't exist so no finding.
	ruleList := []rules.Rule{
		{
			ID: "R1", Title: "Test IOC", Severity: "critical",
			HostIndicators: []rules.HostIndicator{
				{
					Type:     "file",
					FileName: "nonexistent-malware-12345.bin",
					OSes:     []string{mapOSName("linux"), mapOSName("darwin"), "linux", "macos", "windows"},
					Notes:    "CWD file indicator",
				},
			},
		},
	}

	findings, checks := ScanHostIndicators(ruleList)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}

	// Should still have a check entry (clean).
	if len(checks) != 1 {
		t.Errorf("expected 1 check, got %d", len(checks))
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
				Type:      TypePackage,
				Package:   "axios",
				Version:   "1.7.8",
				Lockfile:  "pnpm-lock.yaml",
			},
			{
				RuleID:      "R1",
				RuleTitle:   "Test rule",
				Severity:    "critical",
				Type:        TypeHostIndicator,
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

// Additional tests.

func TestFormatHostChecks(t *testing.T) {
	checks := []HostCheck{
		{Path: "/tmp/malware.bin", Status: StatusFound, RuleID: "R1"},
		{Path: "/home/user/.ssh/key", Status: StatusClean, RuleID: "R2"},
		{Path: "some-process", Status: StatusSkipped, Reason: "process check not implemented", RuleID: "R3"},
	}

	var b strings.Builder
	formatHostChecks(&b, checks)
	out := b.String()

	if !strings.Contains(out, "=== Host Indicator Checks ===") {
		t.Error("missing header")
	}

	if !strings.Contains(out, "[FOUND]   /tmp/malware.bin  (R1)") {
		t.Error("missing FOUND entry")
	}

	if !strings.Contains(out, "[CLEAN]   /home/user/.ssh/key  (R2)") {
		t.Error("missing CLEAN entry")
	}

	if !strings.Contains(out, "[SKIP]    some-process") {
		t.Error("missing SKIP entry")
	}

	if !strings.Contains(out, "process check not implemented  (R3)") {
		t.Error("missing skip reason")
	}
}

func TestFormatNodeModulesChecks(t *testing.T) {
	checks := []NodeModulesCheck{
		{Dir: "/project/node_modules", Package: "axios", Version: "1.14.1", Status: StatusFound},
		{Dir: "/project/node_modules", Package: "express", Version: "4.18.2", Status: StatusClean},
		{Dir: "/project/node_modules", Package: "lodash", Version: "", Status: StatusNotInstalled},
	}

	var b strings.Builder
	formatNodeModulesChecks(&b, checks)
	out := b.String()

	if !strings.Contains(out, "=== Node Modules Checks ===") {
		t.Error("missing header")
	}

	if !strings.Contains(out, "[FOUND]   axios@1.14.1 in /project/node_modules") {
		t.Error("missing FOUND entry")
	}

	if !strings.Contains(out, "[CLEAN]   express@4.18.2 in /project/node_modules") {
		t.Error("missing CLEAN entry")
	}

	// not_installed should be omitted
	if strings.Contains(out, "lodash") {
		t.Error("not_installed entry should be omitted")
	}
}

func TestIndicatorDescription(t *testing.T) {
	tests := []struct {
		name string
		hi   rules.HostIndicator
		want string
	}{
		{
			name: "path and filename",
			hi:   rules.HostIndicator{Path: "/tmp", FileName: "malware.bin"},
			want: "/tmp/malware.bin",
		},
		{
			name: "path only",
			hi:   rules.HostIndicator{Path: "/tmp/malware.bin"},
			want: "/tmp/malware.bin",
		},
		{
			name: "filename only",
			hi:   rules.HostIndicator{FileName: "malware.bin"},
			want: "malware.bin",
		},
		{
			name: "value only",
			hi:   rules.HostIndicator{Value: "some-process"},
			want: "some-process",
		},
		{
			name: "notes fallback",
			hi:   rules.HostIndicator{Notes: "suspicious activity"},
			want: "suspicious activity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := indicatorDescription(&tt.hi)
			if got != tt.want {
				t.Errorf("indicatorDescription() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatFinding_Package(t *testing.T) {
	var b strings.Builder
	f := &Finding{
		RuleID: "R1", RuleTitle: "Test", Severity: "critical",
		Type: TypePackage, Package: "axios", Version: "1.7.8", Lockfile: "pnpm-lock.yaml",
	}
	formatFinding(&b, 1, f)
	out := b.String()

	if !strings.Contains(out, "--- Finding 1 ---") {
		t.Error("missing finding header")
	}
	if !strings.Contains(out, "Package:  axios@1.7.8") {
		t.Error("missing package info")
	}
	if !strings.Contains(out, "Lockfile: pnpm-lock.yaml") {
		t.Error("missing lockfile")
	}
	// No description, so Note: should not appear
	if strings.Contains(out, "Note:") {
		t.Error("Note should not appear without description")
	}
}

func TestFormatFinding_PackageWithDescription(t *testing.T) {
	var b strings.Builder
	f := &Finding{
		RuleID: "R1", RuleTitle: "Test", Severity: "critical",
		Type: TypePackage, Package: "axios", Version: "^1.14.0", Lockfile: "package.json",
		Description: "range covers compromised version 1.14.1",
	}
	formatFinding(&b, 1, f)
	out := b.String()

	if !strings.Contains(out, "Note:     range covers compromised version 1.14.1") {
		t.Error("missing description note")
	}
}

func TestFormatFinding_InstalledPackage(t *testing.T) {
	var b strings.Builder
	f := &Finding{
		RuleID: "R1", RuleTitle: "Test", Severity: "critical",
		Type: TypeInstalledPackage, Package: "axios", Version: "1.14.1",
		Path:        "/project/node_modules/axios",
		Description: "compromised package found in pnpm store",
	}
	formatFinding(&b, 1, f)
	out := b.String()

	if !strings.Contains(out, "installed package") {
		t.Error("missing type text")
	}
	if !strings.Contains(out, "Package:  axios@1.14.1") {
		t.Error("missing package info")
	}
	if !strings.Contains(out, "Path:     /project/node_modules/axios") {
		t.Error("missing path")
	}
	if !strings.Contains(out, "Source:   compromised package found in pnpm store") {
		t.Error("missing source/description")
	}
}

func TestFormatFinding_InstalledPackageNoDescription(t *testing.T) {
	var b strings.Builder
	f := &Finding{
		RuleID: "R1", RuleTitle: "Test", Severity: "critical",
		Type: TypeInstalledPackage, Package: "axios", Version: "1.14.1",
		Path: "/project/node_modules/axios",
	}
	formatFinding(&b, 1, f)
	out := b.String()

	if strings.Contains(out, "Source:") {
		t.Error("should not contain Source when Description is empty")
	}
}

func TestFormatFinding_CachedPackage(t *testing.T) {
	var b strings.Builder
	f := &Finding{
		RuleID: "R1", RuleTitle: "Test", Severity: "critical",
		Type: TypeCachedPackage, Package: "axios", Version: "1.14.1",
		Path: "/home/user/.npm/_cacache/content-v2/sha512/abc",
	}
	formatFinding(&b, 1, f)
	out := b.String()

	if !strings.Contains(out, "cached package") {
		t.Error("missing type text")
	}
	if !strings.Contains(out, "Cache:    /home/user/.npm/_cacache/content-v2/sha512/abc") {
		t.Error("missing cache path")
	}

	if strings.Contains(out, "Source:") {
		t.Error("should not contain Source when Description is empty")
	}
}

func TestFormatFinding_CachedPackageWithDescription(t *testing.T) {
	var b strings.Builder
	f := &Finding{
		RuleID: "R1", RuleTitle: "Test", Severity: "critical",
		Type: TypeCachedPackage, Package: "axios", Version: "1.14.1",
		Path:        "/home/user/.npm/_cacache/content-v2/sha512/abc",
		Description: "indexed package found in npm cache",
	}
	formatFinding(&b, 1, f)
	out := b.String()

	if !strings.Contains(out, "Source:   indexed package found in npm cache") {
		t.Error("missing source/description")
	}
}

func TestFormatFinding_HostIndicator(t *testing.T) {
	var b strings.Builder
	f := &Finding{
		RuleID: "R1", RuleTitle: "Test", Severity: "critical",
		Type: TypeHostIndicator, Description: "RAT binary", Path: "/tmp/malware",
	}
	formatFinding(&b, 1, f)
	out := b.String()

	if !strings.Contains(out, "host indicator") {
		t.Error("missing type text")
	}
	if !strings.Contains(out, "Detail:   RAT binary") {
		t.Error("missing detail")
	}
	if !strings.Contains(out, "Path:     /tmp/malware") {
		t.Error("missing path")
	}
}

func TestFormatFinding_HostIndicatorNoDescription(t *testing.T) {
	var b strings.Builder
	f := &Finding{
		RuleID: "R1", RuleTitle: "Test", Severity: "critical",
		Type: TypeHostIndicator, Path: "/tmp/malware",
	}
	formatFinding(&b, 1, f)
	out := b.String()

	if strings.Contains(out, "Detail:") {
		t.Error("Detail should not appear without description")
	}
	if !strings.Contains(out, "Path:     /tmp/malware") {
		t.Error("missing path")
	}
}

func TestFormatFinding_Heuristic(t *testing.T) {
	var b strings.Builder
	f := &Finding{
		RuleID: "HEUR-EVAL-DECODE", RuleTitle: "Decoded payload execution", Severity: "high",
		Type: TypeHeuristic, Package: "evil-pkg", Path: "/tmp/node_modules/evil-pkg/index.js",
		Description: `eval(atob("payload"))`,
	}
	formatFinding(&b, 1, f)
	out := b.String()

	if !strings.Contains(out, "Type:     heuristic") {
		t.Error("missing heuristic type")
	}
	if !strings.Contains(out, "Package:  evil-pkg") {
		t.Error("missing package")
	}
	if !strings.Contains(out, "Path:     /tmp/node_modules/evil-pkg/index.js") {
		t.Error("missing path")
	}
	if !strings.Contains(out, `Match:    eval(atob("payload"))`) {
		t.Error("missing match description")
	}
}

func TestFormatFinding_HeuristicNoDescription(t *testing.T) {
	var b strings.Builder
	f := &Finding{
		RuleID: "HEUR-ENV-HARVEST", RuleTitle: "Credential harvesting", Severity: "high",
		Type: TypeHeuristic, Package: "harvester", Path: "/tmp/node_modules/harvester/index.js",
	}
	formatFinding(&b, 1, f)
	out := b.String()

	if strings.Contains(out, "Match:") {
		t.Error("Match should not appear without description")
	}
	if !strings.Contains(out, "Package:  harvester") {
		t.Error("missing package")
	}
}

func TestFormatReport_Heuristic(t *testing.T) {
	result := &Result{
		Findings: []Finding{
			{RuleID: "HEUR-EVAL-DECODE", RuleTitle: "Decoded payload", Severity: "high", Type: TypeHeuristic, Package: "evil", Path: "/tmp/evil/index.js"},
		},
		Heuristic: true,
	}
	out := FormatReport(result)

	if !strings.Contains(out, "Heuristic Scan Report") {
		t.Error("expected 'Heuristic Scan Report' header")
	}

	if strings.Contains(out, "Files scanned") {
		t.Error("heuristic report should not mention 'Files scanned'")
	}

	if strings.Contains(out, "lockfiles") {
		t.Error("heuristic report should not mention 'lockfiles'")
	}

	if !strings.Contains(out, "Heuristic scan complete: 1 findings.") {
		t.Error("expected heuristic footer")
	}
}

func TestFormatReport_HeuristicClean(t *testing.T) {
	result := &Result{
		Heuristic: true,
	}
	out := FormatReport(result)

	if !strings.Contains(out, "No suspicious patterns found.") {
		t.Error("expected 'No suspicious patterns found.' for clean heuristic scan")
	}

	if strings.Contains(out, "compromised packages") {
		t.Error("heuristic report should not mention 'compromised packages'")
	}
}

func TestDedup(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "with duplicates",
			input: []string{"/a", "/b", "/a", "/c", "/b"},
			want:  []string{"/a", "/b", "/c"},
		},
		{
			name:  "empty strings filtered",
			input: []string{"a", "", "b", "", "c"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "empty input",
			input: []string{},
			want:  nil,
		},
		{
			name:  "nil input",
			input: nil,
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dedup(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("dedup(%v) = %v, want %v", tt.input, got, tt.want)
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("dedup(%v)[%d] = %q, want %q", tt.input, i, v, tt.want[i])
				}
			}
		})
	}
}

func TestScanPackages_MultiRuleAttribution(t *testing.T) {
	entries := []lockfile.PackageEntry{
		{Name: "axios", Version: "1.7.8"},
	}

	idx := &rules.PackageIndex{
		Packages: map[string][]*rules.VersionSet{
			"axios": {
				{
					RuleID:    "R1",
					RuleTitle: "First rule",
					Severity:  "critical",
					Versions:  map[string]bool{"1.7.8": true},
				},
				{
					RuleID:    "R2",
					RuleTitle: "Second rule",
					Severity:  "high",
					Versions:  map[string]bool{"1.7.8": true},
				},
			},
		},
	}

	findings := ScanPackages(entries, idx, "package-lock.json")

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (one per rule), got %d", len(findings))
	}

	ruleIDs := map[string]bool{}
	for _, f := range findings {
		ruleIDs[f.RuleID] = true
	}

	if !ruleIDs["R1"] || !ruleIDs["R2"] {
		t.Errorf("expected findings from both R1 and R2, got %v", ruleIDs)
	}
}

func TestScanPackages_LockfileEcosystemFilter(t *testing.T) {
	entries := []lockfile.PackageEntry{
		{Name: "axios", Version: "1.7.8"},
	}

	idx := &rules.PackageIndex{
		Packages: map[string][]*rules.VersionSet{
			"axios": {
				{
					RuleID:             "R1",
					RuleTitle:          "Yarn-only rule",
					Severity:           "critical",
					Versions:           map[string]bool{"1.7.8": true},
					LockfileEcosystems: []string{"yarn"},
				},
			},
		},
	}

	// Should NOT match package-lock.json (npm ecosystem).
	findings := ScanPackages(entries, idx, "package-lock.json")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for npm lockfile with yarn-only rule, got %d", len(findings))
	}

	// Should match yarn.lock.
	findings = ScanPackages(entries, idx, "yarn.lock")
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for yarn lockfile with yarn-only rule, got %d", len(findings))
	}
}

func TestScanPackages_LockfileEcosystemEmpty(t *testing.T) {
	entries := []lockfile.PackageEntry{
		{Name: "axios", Version: "1.7.8"},
	}

	idx := &rules.PackageIndex{
		Packages: map[string][]*rules.VersionSet{
			"axios": {
				{
					RuleID:   "R1",
					Severity: "critical",
					Versions: map[string]bool{"1.7.8": true},
					// No LockfileEcosystems — applies to all.
				},
			},
		},
	}

	findings := ScanPackages(entries, idx, "package-lock.json")
	if len(findings) != 1 {
		t.Errorf("expected 1 finding when no ecosystem filter, got %d", len(findings))
	}
}

func TestScanPackages_RangeMatch(t *testing.T) {
	entries := []lockfile.PackageEntry{
		{Name: "axios", Version: "^1.14.0"},
	}

	idx := &rules.PackageIndex{
		Packages: map[string][]*rules.VersionSet{
			"axios": {
				{
					RuleID:    "R1",
					RuleTitle: "Axios compromise",
					Severity:  "critical",
					Versions:  map[string]bool{"1.14.1": true},
				},
			},
		},
	}

	findings := ScanPackages(entries, idx, "package.json")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for range match, got %d", len(findings))
	}

	if findings[0].Description == "" {
		t.Error("range match should have a description")
	}

	if !strings.Contains(findings[0].Description, "1.14.1") {
		t.Errorf("description should mention matched version, got %q", findings[0].Description)
	}
}

func TestScanPackages_RangeOverlapDescription(t *testing.T) {
	entries := []lockfile.PackageEntry{
		{Name: "axios", Version: "^1.5.0"},
	}

	constraint, _ := semver.NewConstraint(">= 1.7.0, < 1.8.0")

	idx := &rules.PackageIndex{
		Packages: map[string][]*rules.VersionSet{
			"axios": {
				{
					RuleID:      "R1",
					RuleTitle:   "Axios compromise",
					Severity:    "critical",
					Constraints: []*semver.Constraints{constraint},
					// No Versions map — forces constraintOverlap path.
				},
			},
		},
	}

	findings := ScanPackages(entries, idx, "package.json")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for range overlap, got %d", len(findings))
	}

	if !strings.Contains(findings[0].Description, "range overlaps with rule constraint") {
		t.Errorf("expected 'range overlaps with rule constraint' description, got %q", findings[0].Description)
	}
}

func TestFormatReport_WithHostAndNodeModuleChecks(t *testing.T) {
	result := &Result{
		Findings: []Finding{
			{
				RuleID: "R1", RuleTitle: "Test", Severity: "critical",
				Type: TypePackage, Package: "axios", Version: "1.14.1", Lockfile: "pnpm-lock.yaml",
			},
		},
		PackagesTotal: 50,
		LockfilesUsed: []string{"pnpm-lock.yaml"},
		HostChecks: []HostCheck{
			{Path: "/tmp/malware.bin", Status: StatusFound, RuleID: "R1"},
			{Path: "/home/user/.ssh/key", Status: StatusClean, RuleID: "R2"},
		},
		NodeModuleChecks: []NodeModulesCheck{
			{Dir: "/project/node_modules", Package: "axios", Version: "1.14.1", Status: StatusFound},
			{Dir: "/project/node_modules", Package: "express", Version: "4.18.2", Status: StatusClean},
		},
	}

	report := FormatReport(result)

	if !strings.Contains(report, "=== Host Indicator Checks ===") {
		t.Error("report should contain host checks section")
	}

	if !strings.Contains(report, "=== Node Modules Checks ===") {
		t.Error("report should contain node modules checks section")
	}

	if !strings.Contains(report, "[FOUND]") {
		t.Error("report should contain FOUND entries")
	}

	if !strings.Contains(report, "[CLEAN]") {
		t.Error("report should contain CLEAN entries")
	}
}

func TestScanHostIndicators_FileHashMatch(t *testing.T) {
	dir := t.TempDir()
	indicator := filepath.Join(dir, "payload.bin")

	if err := os.WriteFile(indicator, []byte("known-bad-content"), 0o600); err != nil {
		t.Fatal(err)
	}

	ruleList := []rules.Rule{
		{
			ID: "R1", Title: "Hash IOC", Severity: "critical",
			HostIndicators: []rules.HostIndicator{
				{
					Type:     "file",
					Path:     dir,
					FileName: "payload.bin",
					OSes:     []string{"linux", "macos", "windows"},
					Hashes: []rules.FileHash{
						{Algorithm: "sha256", Value: "231d243bd5264e8840b9be8ea81d9c9818a614c10a980e139cf06061bd719095"},
					},
					Notes: "known malware",
				},
			},
		},
	}

	findings, checks := ScanHostIndicators(ruleList)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if !strings.Contains(findings[0].Description, "hash confirmed") {
		t.Errorf("expected 'hash confirmed' in description, got %q", findings[0].Description)
	}

	if !strings.Contains(findings[0].Description, "sha256") {
		t.Errorf("expected 'sha256' in description, got %q", findings[0].Description)
	}

	if !strings.Contains(findings[0].Description, "known malware") {
		t.Errorf("expected notes in description, got %q", findings[0].Description)
	}

	if len(checks) != 1 || checks[0].Status != StatusFound {
		t.Errorf("expected 1 FOUND check, got %v", checks)
	}
}

func TestScanHostIndicators_FileHashMismatch(t *testing.T) {
	dir := t.TempDir()
	indicator := filepath.Join(dir, "payload.bin")

	if err := os.WriteFile(indicator, []byte("different-content"), 0o600); err != nil {
		t.Fatal(err)
	}

	ruleList := []rules.Rule{
		{
			ID: "R1", Title: "Hash IOC", Severity: "critical",
			HostIndicators: []rules.HostIndicator{
				{
					Type:     "file",
					Path:     dir,
					FileName: "payload.bin",
					OSes:     []string{"linux", "macos", "windows"},
					Hashes: []rules.FileHash{
						{Algorithm: "sha256", Value: "231d243bd5264e8840b9be8ea81d9c9818a614c10a980e139cf06061bd719095"},
					},
					Notes: "known malware",
				},
			},
		},
	}

	findings, _ := ScanHostIndicators(ruleList)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if !strings.Contains(findings[0].Description, "hash does not match") {
		t.Errorf("expected 'hash does not match' in description, got %q", findings[0].Description)
	}

	if !strings.Contains(findings[0].Description, "known malware") {
		t.Errorf("expected notes in description, got %q", findings[0].Description)
	}
}

func TestScanHostIndicators_FileHashMultipleAlgorithms(t *testing.T) {
	dir := t.TempDir()
	indicator := filepath.Join(dir, "payload.bin")

	if err := os.WriteFile(indicator, []byte("known-bad-content"), 0o600); err != nil {
		t.Fatal(err)
	}

	ruleList := []rules.Rule{
		{
			ID: "R1", Title: "Hash IOC", Severity: "critical",
			HostIndicators: []rules.HostIndicator{
				{
					Type:     "file",
					Path:     dir,
					FileName: "payload.bin",
					OSes:     []string{"linux", "macos", "windows"},
					Hashes: []rules.FileHash{
						{Algorithm: "md5", Value: "7f3499269f3f7c98961fc2202c2f54a9"},
						{Algorithm: "sha1", Value: "6e3f008f02deb90b3240ec17797c527b067adedf"},
						{Algorithm: "sha256", Value: "231d243bd5264e8840b9be8ea81d9c9818a614c10a980e139cf06061bd719095"},
					},
				},
			},
		},
	}

	findings, _ := ScanHostIndicators(ruleList)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	desc := findings[0].Description
	if !strings.Contains(desc, "hash confirmed") {
		t.Errorf("expected 'hash confirmed', got %q", desc)
	}

	for _, algo := range []string{"md5", "sha1", "sha256"} {
		if !strings.Contains(desc, algo) {
			t.Errorf("expected %q in description, got %q", algo, desc)
		}
	}
}

func TestScanHostIndicators_FileHashNoHashes(t *testing.T) {
	// Backward compatibility: no hashes on indicator means existence-only check.
	dir := t.TempDir()
	indicator := filepath.Join(dir, "payload.bin")

	if err := os.WriteFile(indicator, []byte("anything"), 0o600); err != nil {
		t.Fatal(err)
	}

	ruleList := []rules.Rule{
		{
			ID: "R1", Title: "No Hash IOC", Severity: "critical",
			HostIndicators: []rules.HostIndicator{
				{
					Type:     "file",
					Path:     dir,
					FileName: "payload.bin",
					OSes:     []string{"linux", "macos", "windows"},
					Notes:    "existence only",
				},
			},
		},
	}

	findings, _ := ScanHostIndicators(ruleList)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Description != "existence only" {
		t.Errorf("expected notes as description, got %q", findings[0].Description)
	}
}

func TestScanHostIndicators_FileHashEmptyNotes(t *testing.T) {
	dir := t.TempDir()
	indicator := filepath.Join(dir, "payload.bin")

	if err := os.WriteFile(indicator, []byte("known-bad-content"), 0o600); err != nil {
		t.Fatal(err)
	}

	ruleList := []rules.Rule{
		{
			ID: "R1", Title: "Hash IOC", Severity: "critical",
			HostIndicators: []rules.HostIndicator{
				{
					Type:     "file",
					Path:     dir,
					FileName: "payload.bin",
					OSes:     []string{"linux", "macos", "windows"},
					Hashes: []rules.FileHash{
						{Algorithm: "sha256", Value: "231d243bd5264e8840b9be8ea81d9c9818a614c10a980e139cf06061bd719095"},
					},
				},
			},
		},
	}

	findings, _ := ScanHostIndicators(ruleList)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if !strings.Contains(findings[0].Description, "hash confirmed") {
		t.Errorf("expected 'hash confirmed' without notes prefix, got %q", findings[0].Description)
	}

	if strings.HasPrefix(findings[0].Description, ";") {
		t.Errorf("description should not start with semicolon, got %q", findings[0].Description)
	}
}

func TestScanHostIndicators_FileHashMismatchEmptyNotes(t *testing.T) {
	dir := t.TempDir()
	indicator := filepath.Join(dir, "payload.bin")

	if err := os.WriteFile(indicator, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}

	ruleList := []rules.Rule{
		{
			ID: "R1", Title: "Hash IOC", Severity: "critical",
			HostIndicators: []rules.HostIndicator{
				{
					Type:     "file",
					Path:     dir,
					FileName: "payload.bin",
					OSes:     []string{"linux", "macos", "windows"},
					Hashes: []rules.FileHash{
						{Algorithm: "sha256", Value: "0000000000000000000000000000000000000000000000000000000000000000"},
					},
				},
			},
		},
	}

	findings, _ := ScanHostIndicators(ruleList)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Description != "file exists but hash does not match any known variant" {
		t.Errorf("unexpected description: %q", findings[0].Description)
	}
}

func TestComputeFileHashes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")

	if err := os.WriteFile(path, []byte("known-bad-content"), 0o600); err != nil {
		t.Fatal(err)
	}

	hashes := []rules.FileHash{
		{Algorithm: "md5", Value: "ignored"},
		{Algorithm: "sha256", Value: "ignored"},
	}

	result, err := computeFileHashes(path, hashes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result["md5"] != "7f3499269f3f7c98961fc2202c2f54a9" {
		t.Errorf("md5: got %q", result["md5"])
	}

	if result["sha256"] != "231d243bd5264e8840b9be8ea81d9c9818a614c10a980e139cf06061bd719095" {
		t.Errorf("sha256: got %q", result["sha256"])
	}
}

func TestComputeFileHashes_NonexistentFile(t *testing.T) {
	hashes := []rules.FileHash{{Algorithm: "sha256", Value: "x"}}

	_, err := computeFileHashes("/nonexistent/path/file.bin", hashes)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}

	if !strings.Contains(err.Error(), "open") {
		t.Errorf("expected open error, got: %v", err)
	}
}

func TestComputeFileHashes_ReadError(t *testing.T) {
	// Opening a directory succeeds but reading it fails.
	dir := t.TempDir()
	hashes := []rules.FileHash{{Algorithm: "sha256", Value: "x"}}

	_, err := computeFileHashes(dir, hashes)
	if err == nil {
		t.Fatal("expected error when reading directory as file")
	}

	if !strings.Contains(err.Error(), "read") {
		t.Errorf("expected read error, got: %v", err)
	}
}

func TestComputeFileHashes_DuplicateAlgorithm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")

	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Two sha256 entries — should only compute once.
	hashes := []rules.FileHash{
		{Algorithm: "sha256", Value: "aaa"},
		{Algorithm: "sha256", Value: "bbb"},
	}

	result, err := computeFileHashes(path, hashes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("expected 1 algorithm in result, got %d", len(result))
	}
}

func TestComputeFileHashes_UnknownAlgorithm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")

	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	hashes := []rules.FileHash{
		{Algorithm: "blake2b", Value: "ignored"},
		{Algorithm: "sha256", Value: "ignored"},
	}

	result, err := computeFileHashes(path, hashes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := result["blake2b"]; ok {
		t.Error("unknown algorithm should be skipped")
	}

	if _, ok := result["sha256"]; !ok {
		t.Error("sha256 should still be computed")
	}
}

func TestNewHashFunc(t *testing.T) {
	tests := []struct {
		algo string
		ok   bool
	}{
		{"md5", true},
		{"sha1", true},
		{"sha256", true},
		{"sha512", true},
		{"blake2b", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			h, ok := newHashFunc(tt.algo)
			if ok != tt.ok {
				t.Errorf("newHashFunc(%q) ok = %v, want %v", tt.algo, ok, tt.ok)
			}

			if tt.ok && h == nil {
				t.Errorf("newHashFunc(%q) returned nil hash", tt.algo)
			}
		})
	}
}

func TestHashCheckDescription_ReadError(t *testing.T) {
	// Create a directory — os.Open succeeds but reading it as a file fails on some platforms,
	// so instead use a nonexistent path to trigger open error.
	desc := hashCheckDescription("/nonexistent/file.bin", []rules.FileHash{
		{Algorithm: "sha256", Value: "abc"},
	}, "malware payload")

	if !strings.Contains(desc, "hash verification failed") {
		t.Errorf("expected 'hash verification failed', got %q", desc)
	}

	if !strings.Contains(desc, "malware payload") {
		t.Errorf("expected notes prefix, got %q", desc)
	}
}

func TestHashCheckDescription_ReadErrorNoNotes(t *testing.T) {
	desc := hashCheckDescription("/nonexistent/file.bin", []rules.FileHash{
		{Algorithm: "sha256", Value: "abc"},
	}, "")

	if !strings.Contains(desc, "hash verification failed") {
		t.Errorf("expected 'hash verification failed', got %q", desc)
	}

	if strings.HasPrefix(desc, ";") {
		t.Errorf("description should not start with semicolon, got %q", desc)
	}
}

func TestScanHostIndicators_FileHashSha512(t *testing.T) {
	dir := t.TempDir()
	indicator := filepath.Join(dir, "payload.bin")

	// Empty file — use known empty-file sha512.
	if err := os.WriteFile(indicator, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}

	ruleList := []rules.Rule{
		{
			ID: "R1", Title: "Hash IOC", Severity: "critical",
			HostIndicators: []rules.HostIndicator{
				{
					Type:     "file",
					Path:     dir,
					FileName: "payload.bin",
					OSes:     []string{"linux", "macos", "windows"},
					Hashes: []rules.FileHash{
						{Algorithm: "sha512", Value: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
					},
				},
			},
		},
	}

	findings, _ := ScanHostIndicators(ruleList)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if !strings.Contains(findings[0].Description, "hash confirmed") {
		t.Errorf("expected 'hash confirmed', got %q", findings[0].Description)
	}

	if !strings.Contains(findings[0].Description, "sha512") {
		t.Errorf("expected 'sha512' in description, got %q", findings[0].Description)
	}
}

func TestExpandPath_AppDataEmpty(t *testing.T) {
	t.Setenv("APPDATA", "")
	got := expandPath("%APPDATA%\\config")

	home, _ := os.UserHomeDir()
	want := filepath.Join(home, "AppData", "Roaming") + "\\config"

	if got != want {
		t.Errorf("expandPath(%%APPDATA%%) with empty env = %q, want %q", got, want)
	}
}
