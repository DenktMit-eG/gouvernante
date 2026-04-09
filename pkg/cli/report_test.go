package cli

import (
	"strings"
	"testing"

	"gouvernante/pkg/lockfile"
	"gouvernante/pkg/rules"
)

func TestBuildReportHeader_Basic(t *testing.T) {
	ruleList := []rules.Rule{
		{ID: "R1", Kind: "vulnerability", Severity: "high", Title: "Test"},
	}
	results := []lockfile.Result{
		{Name: "pnpm-lock.yaml", Entries: []lockfile.PackageEntry{{Name: "a", Version: "1.0"}}},
	}

	header := BuildReportHeader(ruleList, 5, results, false)

	if !strings.Contains(header, "Scan Configuration") {
		t.Error("expected Scan Configuration header")
	}

	if !strings.Contains(header, "R1") {
		t.Error("expected rule ID in header")
	}

	if !strings.Contains(header, "1 files") {
		t.Error("expected lockfile count")
	}

	if strings.Contains(header, "Filesystem Checks") {
		t.Error("should not contain Filesystem Checks when hostCheck=false")
	}
}

func TestBuildReportHeader_WithHostCheck(t *testing.T) {
	header := BuildReportHeader(nil, 0, nil, true)

	if !strings.Contains(header, "Filesystem Checks") {
		t.Error("expected Filesystem Checks section when hostCheck=true")
	}
}
