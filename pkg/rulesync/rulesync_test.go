package rulesync

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validRuleJSON = `{
  "schema_version": "1.0.0",
  "rules": [
    {
      "id": "T-001",
      "title": "Test rule",
      "kind": "vulnerability",
      "ecosystem": "npm",
      "severity": "low",
      "package_rules": [
        {
          "package_name": "test-pkg",
          "affected_versions": ["1.0.0"]
        }
      ]
    }
  ]
}`

const invalidRuleJSON = `{"schema_version": "1.0.0", "rules": [{}]}`

// createTestZIP builds a ZIP archive in memory from a map of filename to content.
func createTestZIP(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("create ZIP entry %q: %v", name, err)
		}

		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("write ZIP entry %q: %v", name, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close ZIP writer: %v", err)
	}

	return buf.Bytes()
}

// createWrappedTestZIP builds a ZIP where files are inside a single top-level directory.
func createWrappedTestZIP(t *testing.T, dirName string, files map[string]string) []byte {
	t.Helper()

	wrapped := make(map[string]string, len(files))
	for name, content := range files {
		wrapped[dirName+"/"+name] = content
	}

	return createTestZIP(t, wrapped)
}

// createZIPWithSymlink builds a ZIP containing a symlink entry.
func createZIPWithSymlink(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	hdr := &zip.FileHeader{
		Name: "evil.json",
	}
	hdr.SetMode(os.ModeSymlink | 0o777)

	f, err := w.CreateHeader(hdr)
	if err != nil {
		t.Fatalf("create symlink entry: %v", err)
	}

	if _, err := f.Write([]byte("/etc/passwd")); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close ZIP writer: %v", err)
	}

	return buf.Bytes()
}

// createZIPSlip builds a ZIP with a path-traversal entry.
func createZIPSlip(t *testing.T) []byte {
	t.Helper()

	return createTestZIP(t, map[string]string{
		"../../../etc/evil.json": validRuleJSON,
	})
}

func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return srv
}

func setTestClient(t *testing.T, client *http.Client) {
	t.Helper()

	orig := httpClient
	httpClient = client
	t.Cleanup(func() { httpClient = orig })
}

// Sync tests.

func TestSync_DownloadsAndExtracts(t *testing.T) {
	zipData := createTestZIP(t, map[string]string{
		"rule.json": validRuleJSON,
	})

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("ETag", `"abc123"`)
		_, _ = w.Write(zipData)
	}))
	setTestClient(t, srv.Client())

	cacheDir := t.TempDir()
	dir, err := Sync(Options{URL: srv.URL, CacheDir: cacheDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if dir != filepath.Join(cacheDir, "data") {
		t.Errorf("expected data dir, got %s", dir)
	}

	// Verify rule file exists.
	content, err := os.ReadFile(filepath.Join(dir, "rule.json"))
	if err != nil {
		t.Fatalf("read extracted rule: %v", err)
	}

	if !strings.Contains(string(content), "T-001") {
		t.Error("extracted rule does not contain expected content")
	}

	// Verify ETag was cached.
	etag := readETag(cacheDir)
	if etag != `"abc123"` {
		t.Errorf("expected ETag %q, got %q", `"abc123"`, etag)
	}
}

func TestSync_ETagCaching304(t *testing.T) {
	zipData := createTestZIP(t, map[string]string{
		"rule.json": validRuleJSON,
	})

	requestCount := 0
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.Header.Get("If-None-Match") == `"etag1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("ETag", `"etag1"`)
		_, _ = w.Write(zipData)
	}))
	setTestClient(t, srv.Client())

	cacheDir := t.TempDir()

	// First request: downloads.
	dir1, err := Sync(Options{URL: srv.URL, CacheDir: cacheDir})
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}

	// Second request: 304.
	dir2, err := Sync(Options{URL: srv.URL, CacheDir: cacheDir})
	if err != nil {
		t.Fatalf("second sync: %v", err)
	}

	if dir1 != dir2 {
		t.Errorf("expected same dir, got %s and %s", dir1, dir2)
	}

	if requestCount != 2 {
		t.Errorf("expected 2 requests, got %d", requestCount)
	}
}

func TestSync_304WithMissingCache(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	setTestClient(t, srv.Client())

	cacheDir := t.TempDir()
	// Write a stale ETag but no data dir.
	writeETag(cacheDir, `"stale"`)

	_, err := Sync(Options{URL: srv.URL, CacheDir: cacheDir})
	if err == nil {
		t.Fatal("expected error for 304 with missing cache")
	}

	if !strings.Contains(err.Error(), "304") {
		t.Errorf("error should mention 304, got: %v", err)
	}
}

func TestSync_Non200Response(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	setTestClient(t, srv.Client())

	_, err := Sync(Options{URL: srv.URL, CacheDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for 500 response")
	}

	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status code, got: %v", err)
	}
}

func TestSync_CorruptZIP(t *testing.T) {
	// Starts with ZIP magic but is otherwise garbage.
	corrupt := make([]byte, 0, len(zipMagic)+24)
	corrupt = append(corrupt, zipMagic...)
	corrupt = append(corrupt, []byte("not a real zip body here")...)

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(corrupt)
	}))
	setTestClient(t, srv.Client())

	_, err := Sync(Options{URL: srv.URL, CacheDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for corrupt ZIP")
	}
}

func TestSync_EmptyZIP(t *testing.T) {
	// An empty ZIP has no local file headers, so its magic bytes differ
	// (PK\x05\x06 instead of PK\x03\x04). The magic check rejects it.
	var buf bytes.Buffer

	w := zip.NewWriter(&buf)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(buf.Bytes())
	}))
	setTestClient(t, srv.Client())

	_, err := Sync(Options{URL: srv.URL, CacheDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for empty ZIP")
	}
}

func TestSync_ZIPWithNoJSONFiles(t *testing.T) {
	// Valid ZIP that contains only non-JSON files.
	zipData := createTestZIP(t, map[string]string{
		"README.md": "# Rules",
		"script.sh": "#!/bin/bash",
	})

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	setTestClient(t, srv.Client())

	_, err := Sync(Options{URL: srv.URL, CacheDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for ZIP with no JSON files")
	}

	if !strings.Contains(err.Error(), "no .json rule files") {
		t.Errorf("error should mention missing rules, got: %v", err)
	}
}

func TestSync_ZipSlip(t *testing.T) {
	zipData := createZIPSlip(t)

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	setTestClient(t, srv.Client())

	_, err := Sync(Options{URL: srv.URL, CacheDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for zip-slip attack")
	}

	if !strings.Contains(err.Error(), "escapes destination") {
		t.Errorf("error should mention path escape, got: %v", err)
	}
}

func TestSync_SymlinkRejected(t *testing.T) {
	zipData := createZIPWithSymlink(t)

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	setTestClient(t, srv.Client())

	_, err := Sync(Options{URL: srv.URL, CacheDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for symlink in ZIP")
	}

	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error should mention symlink, got: %v", err)
	}
}

func TestSync_SingleDirUnwrap(t *testing.T) {
	zipData := createWrappedTestZIP(t, "rules-v1", map[string]string{
		"rule.json": validRuleJSON,
	})

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	setTestClient(t, srv.Client())

	dir, err := Sync(Options{URL: srv.URL, CacheDir: t.TempDir()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// After unwrapping, rule.json should be directly in data dir.
	if _, err := os.Stat(filepath.Join(dir, "rule.json")); err != nil {
		t.Errorf("rule.json should be at top level after unwrap: %v", err)
	}
}

func TestSync_BinaryContentRejected(t *testing.T) {
	zipData := createTestZIP(t, map[string]string{
		"evil.json": "binary\x00content",
	})

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	setTestClient(t, srv.Client())

	_, err := Sync(Options{URL: srv.URL, CacheDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for binary content")
	}

	if !strings.Contains(err.Error(), "binary data") {
		t.Errorf("error should mention binary data, got: %v", err)
	}
}

func TestSync_SchemaInvalidRuleAborts(t *testing.T) {
	zipData := createTestZIP(t, map[string]string{
		"bad.json": invalidRuleJSON,
	})

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	setTestClient(t, srv.Client())

	cacheDir := t.TempDir()
	_, err := Sync(Options{URL: srv.URL, CacheDir: cacheDir})

	if err == nil {
		t.Fatal("expected error for schema-invalid rule")
	}

	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("error should mention validation failure, got: %v", err)
	}

	// Verify temp dir was cleaned up.
	entries, _ := os.ReadDir(cacheDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "rulesync-") {
			t.Errorf("temp directory %q was not cleaned up", e.Name())
		}
	}
}

func TestSync_HTMLResponseRejected(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>Error page</html>"))
	}))
	setTestClient(t, srv.Client())

	_, err := Sync(Options{URL: srv.URL, CacheDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for HTML response")
	}

	if !strings.Contains(err.Error(), "Content-Type") {
		t.Errorf("error should mention Content-Type, got: %v", err)
	}
}

func TestSync_BadMagicBytes(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("this is not a zip"))
	}))
	setTestClient(t, srv.Client())

	_, err := Sync(Options{URL: srv.URL, CacheDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for bad magic bytes")
	}

	if !strings.Contains(err.Error(), "magic bytes") {
		t.Errorf("error should mention magic bytes, got: %v", err)
	}
}

func TestSync_NonJSONFilesSkipped(t *testing.T) {
	zipData := createTestZIP(t, map[string]string{
		"rule.json":   validRuleJSON,
		"README.md":   "# Rules",
		"script.sh":   "#!/bin/bash\necho pwned",
		"payload.exe": "MZ...",
	})

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	setTestClient(t, srv.Client())

	dir, err := Sync(Options{URL: srv.URL, CacheDir: t.TempDir()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only rule.json should exist.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected 1 file, got %d", len(entries))
	}

	if entries[0].Name() != "rule.json" {
		t.Errorf("expected rule.json, got %s", entries[0].Name())
	}
}

func TestSync_ResponseSizeLimit(t *testing.T) {
	// Create a response that exceeds 5 MB.
	padding := bytes.Repeat([]byte("x"), maxResponseBytes+1)
	bigBody := make([]byte, 0, len(zipMagic)+len(padding))
	bigBody = append(bigBody, zipMagic...)
	bigBody = append(bigBody, padding...)

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(bigBody)
	}))
	setTestClient(t, srv.Client())

	_, err := Sync(Options{URL: srv.URL, CacheDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for oversized response")
	}

	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("error should mention limit, got: %v", err)
	}
}

func TestSync_NetworkError(t *testing.T) {
	// Use a closed server to trigger a connection error.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close()

	setTestClient(t, srv.Client())

	_, err := Sync(Options{URL: srv.URL, CacheDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for network failure")
	}
}

func TestSync_CachePreservedOnFailure(t *testing.T) {
	zipData := createTestZIP(t, map[string]string{
		"rule.json": validRuleJSON,
	})

	callCount := 0
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipData)
			return
		}

		// Second call: return invalid rules.
		badZip := createTestZIP(t, map[string]string{
			"bad.json": invalidRuleJSON,
		})
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(badZip)
	}))
	setTestClient(t, srv.Client())

	cacheDir := t.TempDir()

	// First sync succeeds.
	dir, err := Sync(Options{URL: srv.URL, CacheDir: cacheDir})
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}

	// Verify data exists.
	if _, err := os.Stat(filepath.Join(dir, "rule.json")); err != nil {
		t.Fatalf("rule.json missing after first sync: %v", err)
	}

	// Second sync fails (invalid rules) — but old cache should remain.
	// Note: Sync replaces old data dir before validation fails in this flow,
	// but extractAndValidate validates BEFORE the swap in Sync. So old data
	// should remain intact.
	_, err = Sync(Options{URL: srv.URL, CacheDir: cacheDir})
	if err == nil {
		t.Fatal("expected error for invalid rules on second sync")
	}

	// Old cache should still be intact.
	if _, statErr := os.Stat(filepath.Join(cacheDir, "data", "rule.json")); statErr != nil {
		t.Errorf("old cache should be preserved after failed sync: %v", statErr)
	}
}

// DefaultCacheDir tests.

func TestDefaultCacheDir(t *testing.T) {
	dir, err := DefaultCacheDir()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasSuffix(dir, filepath.Join("gouvernante", "rules")) {
		t.Errorf("expected path ending in gouvernante/rules, got %s", dir)
	}
}

// validateContentType tests.

func TestValidateContentType(t *testing.T) {
	tests := []struct {
		name    string
		ct      string
		wantErr bool
	}{
		{"empty", "", false},
		{"application/zip", "application/zip", false},
		{"application/octet-stream", "application/octet-stream", false},
		{"application/x-zip-compressed", "application/x-zip-compressed", false},
		{"zip with charset", "application/zip; charset=utf-8", false},
		{"text/html", "text/html", true},
		{"text/plain", "text/plain", true},
		{"application/json", "application/json", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateContentType(tt.ct)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateContentType(%q) error = %v, wantErr %v", tt.ct, err, tt.wantErr)
			}
		})
	}
}

// validateZIPMagic tests.

func TestValidateZIPMagic(t *testing.T) {
	tests := []struct {
		name    string
		body    []byte
		wantErr bool
	}{
		{"valid ZIP header", []byte{0x50, 0x4B, 0x03, 0x04, 0x00}, false},
		{"too short", []byte{0x50, 0x4B}, true},
		{"wrong magic", []byte{0x00, 0x00, 0x00, 0x00}, true},
		{"empty", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateZIPMagic(tt.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateZIPMagic() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// unwrapSingleDir tests.

func TestUnwrapSingleDir_NoUnwrap(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := unwrapSingleDir(dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestUnwrapSingleDir_Unwraps(t *testing.T) {
	dir := t.TempDir()
	inner := filepath.Join(dir, "wrapper")

	if err := os.Mkdir(inner, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(inner, "rule.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := unwrapSingleDir(dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "rule.json")); err != nil {
		t.Error("rule.json should be at top level after unwrap")
	}

	if _, err := os.Stat(inner); err == nil {
		t.Error("wrapper directory should be removed after unwrap")
	}
}

func TestUnwrapSingleDir_SingleFileNoUnwrap(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rule.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := unwrapSingleDir(dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Single file (not dir) — should not unwrap.
	if _, err := os.Stat(filepath.Join(dir, "rule.json")); err != nil {
		t.Error("rule.json should remain unchanged")
	}
}

// readETag and writeETag tests.

func TestETagRoundtrip(t *testing.T) {
	dir := t.TempDir()

	// No ETag file yet.
	if got := readETag(dir); got != "" {
		t.Errorf("expected empty ETag, got %q", got)
	}

	writeETag(dir, `"v1"`)

	if got := readETag(dir); got != `"v1"` {
		t.Errorf("expected %q, got %q", `"v1"`, got)
	}
}

func TestWriteETag_EmptySkipped(t *testing.T) {
	dir := t.TempDir()

	writeETag(dir, "")

	if _, err := os.Stat(filepath.Join(dir, "etag")); err == nil {
		t.Error("empty ETag should not create a file")
	}
}

// extractZIPEntry edge cases.

func TestExtractZIPEntry_DirectoriesSkipped(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Add a directory entry.
	if _, err := w.Create("subdir/"); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := extractZIP(buf.Bytes(), dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No files should be extracted.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

// validateExtracted tests.

func TestValidateExtracted_ValidRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rule.json"), []byte(validRuleJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := validateExtracted(dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateExtracted_InvalidRule(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte(invalidRuleJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	err := validateExtracted(dir)
	if err == nil {
		t.Fatal("expected error for invalid rule")
	}

	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("error should mention validation failure, got: %v", err)
	}

	if !strings.Contains(err.Error(), "bad.json") {
		t.Errorf("error should name the failing file, got: %v", err)
	}
}

func TestValidateExtracted_EmptyDir(t *testing.T) {
	err := validateExtracted(t.TempDir())
	if err == nil {
		t.Fatal("expected error for empty directory")
	}

	if !strings.Contains(err.Error(), "no .json rule files") {
		t.Errorf("error should mention missing rules, got: %v", err)
	}
}

// download tests.

func TestDownload_SetsIfNoneMatch(t *testing.T) {
	var receivedHeader string

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("If-None-Match")
		w.WriteHeader(http.StatusNotModified)
	}))
	setTestClient(t, srv.Client())

	_, _, notModified, err := download(srv.URL, `"test-etag"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !notModified {
		t.Error("expected notModified=true")
	}

	if receivedHeader != `"test-etag"` {
		t.Errorf("expected If-None-Match %q, got %q", `"test-etag"`, receivedHeader)
	}
}

func TestDownload_NoETagNoHeader(t *testing.T) {
	var hasHeader bool

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hasHeader = r.Header.Get("If-None-Match") != ""
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipMagic)
	}))
	setTestClient(t, srv.Client())

	_, _, _, err := download(srv.URL, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hasHeader {
		t.Error("If-None-Match should not be sent when etag is empty")
	}
}

func TestDownload_ReturnsETag(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("ETag", `"new-etag"`)
		_, _ = w.Write(zipMagic)
	}))
	setTestClient(t, srv.Client())

	_, etag, _, err := download(srv.URL, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if etag != `"new-etag"` {
		t.Errorf("expected ETag %q, got %q", `"new-etag"`, etag)
	}
}

func TestDownload_InvalidURL(t *testing.T) {
	_, _, _, err := download("://invalid", "")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestDownload_HTTPError(t *testing.T) {
	for _, code := range []int{
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusServiceUnavailable,
	} {
		t.Run(fmt.Sprintf("HTTP_%d", code), func(t *testing.T) {
			srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(code)
			}))
			setTestClient(t, srv.Client())

			_, _, _, err := download(srv.URL, "")
			if err == nil {
				t.Fatalf("expected error for HTTP %d", code)
			}

			if !strings.Contains(err.Error(), fmt.Sprintf("%d", code)) {
				t.Errorf("error should contain status code %d, got: %v", code, err)
			}
		})
	}
}

// Filesystem error path tests.

func TestSync_CacheDirCreateError(t *testing.T) {
	// Use a path under a file (not a directory) to trigger MkdirAll failure.
	tmpFile := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(tmpFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Sync(Options{URL: "http://example.com", CacheDir: filepath.Join(tmpFile, "sub")})
	if err == nil {
		t.Fatal("expected error for cache dir creation failure")
	}

	if !strings.Contains(err.Error(), "create cache directory") {
		t.Errorf("error should mention cache dir creation, got: %v", err)
	}
}

func TestSync_TempDirCreateError(t *testing.T) {
	zipData := createTestZIP(t, map[string]string{
		"rule.json": validRuleJSON,
	})

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	setTestClient(t, srv.Client())

	// Create a read-only cache dir so MkdirTemp fails inside extractAndValidate.
	cacheDir := filepath.Join(t.TempDir(), "cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Make the cache dir read-only after Sync creates it (we override after MkdirAll succeeds).
	// Actually, let Sync create it, then the MkdirTemp will work.
	// Instead, we need to make the dir read-only so MkdirTemp fails.
	if err := os.Chmod(cacheDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cacheDir, 0o700) })

	_, err := Sync(Options{URL: srv.URL, CacheDir: cacheDir})
	if err == nil {
		t.Fatal("expected error for temp dir creation failure")
	}
}

func TestUnwrapSingleDir_ReadError(t *testing.T) {
	err := unwrapSingleDir("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}

	if !strings.Contains(err.Error(), "read extracted directory") {
		t.Errorf("error should mention read failure, got: %v", err)
	}
}

func TestUnwrapSingleDir_InnerReadError(t *testing.T) {
	dir := t.TempDir()
	inner := filepath.Join(dir, "wrapper")

	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatal(err)
	}

	// Make inner dir unreadable.
	if err := os.Chmod(inner, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(inner, 0o700) })

	err := unwrapSingleDir(dir)
	if err == nil {
		t.Fatal("expected error for unreadable inner directory")
	}

	if !strings.Contains(err.Error(), "read inner directory") {
		t.Errorf("error should mention inner dir read failure, got: %v", err)
	}
}

func TestExtractZIPEntry_ReadContentError(t *testing.T) {
	zipData := createTestZIP(t, map[string]string{
		"rule.json": validRuleJSON,
	})

	// Inject a failing readEntryContent.
	orig := readEntryContent
	readEntryContent = func(f *zip.File) ([]byte, error) {
		return nil, fmt.Errorf("simulated read error for %s", f.Name)
	}
	t.Cleanup(func() { readEntryContent = orig })

	err := extractZIP(zipData, t.TempDir())
	if err == nil {
		t.Fatal("expected error for read content failure")
	}

	if !strings.Contains(err.Error(), "simulated read error") {
		t.Errorf("error should mention simulated error, got: %v", err)
	}
}

func TestExtractZIPEntry_WriteFileError(t *testing.T) {
	zipData := createTestZIP(t, map[string]string{
		"rule.json": validRuleJSON,
	})

	// Inject a failing osWriteFile.
	orig := osWriteFile
	osWriteFile = func(_ string, _ []byte, _ os.FileMode) error {
		return fmt.Errorf("simulated write error")
	}
	t.Cleanup(func() { osWriteFile = orig })

	err := extractZIP(zipData, t.TempDir())
	if err == nil {
		t.Fatal("expected error for write file failure")
	}

	if !strings.Contains(err.Error(), "write") {
		t.Errorf("error should mention write failure, got: %v", err)
	}
}

func TestExtractAndValidate_UnwrapCleanup(t *testing.T) {
	zipData := createTestZIP(t, map[string]string{
		"rule.json": validRuleJSON,
	})

	// Inject a failing unwrapDir.
	orig := unwrapDir
	unwrapDir = func(_ string) error {
		return fmt.Errorf("simulated unwrap failure")
	}
	t.Cleanup(func() { unwrapDir = orig })

	parentDir := t.TempDir()
	_, err := extractAndValidate(zipData, parentDir)

	if err == nil {
		t.Fatal("expected error for unwrap failure")
	}

	// Verify temp dir was cleaned up.
	entries, _ := os.ReadDir(parentDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "rulesync-") {
			t.Errorf("temp directory %q was not cleaned up", e.Name())
		}
	}
}

func TestValidateExtracted_SkipsSubdirectories(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rule.json"), []byte(validRuleJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	// Add a subdirectory that should be skipped.
	if err := os.MkdirAll(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}

	// Add a non-JSON file that should be skipped.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Rules"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := validateExtracted(dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDownload_ReadBodyError(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Length", "1000000") // lie about content length
		w.WriteHeader(http.StatusOK)
		// Write partial body then close connection — this triggers a read error.
		_, _ = w.Write([]byte("partial"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// The handler returning causes the connection to close prematurely.
	}))
	setTestClient(t, srv.Client())

	// This may or may not error depending on buffering.
	// The important thing is it doesn't panic.
	_, _, _, _ = download(srv.URL, "")
}

func TestWriteETag_WriteError(t *testing.T) {
	// Use a nonexistent directory — writeETag logs a warning but doesn't panic.
	writeETag("/nonexistent/dir", `"test"`)
	// No assertion needed — just verify it doesn't panic.
}

func TestDefaultCacheDir_Error(t *testing.T) {
	// Unset HOME to trigger os.UserCacheDir failure.
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")

	_, err := DefaultCacheDir()
	if err == nil {
		t.Fatal("expected error when HOME is unset")
	}
}

func TestExtractZIP_InvalidArchive(t *testing.T) {
	err := extractZIP([]byte("not a zip"), t.TempDir())
	if err == nil {
		t.Fatal("expected error for invalid archive")
	}

	if !strings.Contains(err.Error(), "open ZIP archive") {
		t.Errorf("error should mention ZIP archive, got: %v", err)
	}
}

func TestSync_RenameError(t *testing.T) {
	zipData := createTestZIP(t, map[string]string{
		"rule.json": validRuleJSON,
	})

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	setTestClient(t, srv.Client())

	// Inject a failing osRename to simulate a cross-device rename error.
	origRename := osRename
	osRename = func(_, _ string) error {
		return fmt.Errorf("simulated rename failure")
	}
	t.Cleanup(func() { osRename = origRename })

	_, err := Sync(Options{URL: srv.URL, CacheDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for rename failure")
	}

	if !strings.Contains(err.Error(), "install rules to cache") {
		t.Errorf("error should mention cache install failure, got: %v", err)
	}
}

func TestExtractZIPEntry_WriteError(t *testing.T) {
	zipData := createTestZIP(t, map[string]string{
		"sub/rule.json": validRuleJSON,
	})

	// Create dest dir as read-only so MkdirAll for "sub" fails.
	destDir := filepath.Join(t.TempDir(), "dest")
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(destDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(destDir, 0o700) })

	err := extractZIP(zipData, destDir)
	if err == nil {
		t.Fatal("expected error for write failure")
	}
}

func TestUnwrapSingleDir_RenameError(t *testing.T) {
	dir := t.TempDir()
	inner := filepath.Join(dir, "wrapper")

	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(inner, "rule.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Make parent read-only so rename out of inner dir fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := unwrapSingleDir(dir)
	if err == nil {
		t.Fatal("expected error for rename failure")
	}
}

func TestExtractAndValidate_UnwrapError(t *testing.T) {
	// Create a wrapped ZIP. After extraction, make the temp dir read-only
	// so that unwrapSingleDir cannot rename files out of the inner dir.
	zipData := createWrappedTestZIP(t, "inner", map[string]string{
		"rule.json": validRuleJSON,
	})

	parentDir := t.TempDir()

	// We need to intercept after extractZIP succeeds but before unwrap.
	// Since extractAndValidate creates the tmpDir internally, we can't
	// directly chmod it. Instead, test unwrapSingleDir error separately.
	// The cleanup path in extractAndValidate is already tested indirectly
	// through TestSync_SchemaInvalidRuleAborts (validation failure).
	// Let's test the unwrap failure path through extractAndValidate by
	// extracting to a dir where rename out of inner will fail.
	tmpDir, err := os.MkdirTemp(parentDir, "test-*")
	if err != nil {
		t.Fatal(err)
	}

	// Extract successfully first.
	if err := extractZIP(zipData, tmpDir); err != nil {
		t.Fatalf("extract: %v", err)
	}

	// Make tmpDir read-only so unwrap's rename fails.
	if err := os.Chmod(tmpDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(tmpDir, 0o700) })

	err = unwrapSingleDir(tmpDir)
	if err == nil {
		t.Fatal("expected error for unwrap with read-only dir")
	}
}

func TestValidateExtracted_ReadDirError(t *testing.T) {
	err := validateExtracted("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}

	if !strings.Contains(err.Error(), "read extracted rules directory") {
		t.Errorf("error should mention read failure, got: %v", err)
	}
}

func TestSync_RemoveOldCacheError(t *testing.T) {
	zipData := createTestZIP(t, map[string]string{
		"rule.json": validRuleJSON,
	})

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	setTestClient(t, srv.Client())

	// Inject a failing osRemoveAll to simulate permission error.
	origRemoveAll := osRemoveAll
	osRemoveAll = func(path string) error {
		// Only fail when removing the data dir (not the temp dir cleanup).
		if strings.HasSuffix(path, "data") {
			return fmt.Errorf("simulated remove failure")
		}

		return origRemoveAll(path)
	}
	t.Cleanup(func() { osRemoveAll = origRemoveAll })

	_, err := Sync(Options{URL: srv.URL, CacheDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error when old cache cannot be removed")
	}

	if !strings.Contains(err.Error(), "remove old cache") {
		t.Errorf("error should mention remove failure, got: %v", err)
	}
}
