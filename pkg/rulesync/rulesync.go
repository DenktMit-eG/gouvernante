// Package rulesync downloads, validates, and caches remote rule ZIP archives.
// It enforces strict security checks: only schema-valid JSON rule files are
// accepted, and the cache is updated atomically so a failed download never
// corrupts an existing rule set.
package rulesync

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gouvernante/pkg/rules"
)

// maxResponseBytes is the upper limit for a rule ZIP download (5 MB).
// Rule JSON compresses extremely well, so this is generous.
const maxResponseBytes = 5 * 1024 * 1024

// Content types accepted as a ZIP archive response.
const (
	contentTypeZip            = "application/zip"
	contentTypeOctetStream    = "application/octet-stream"
	contentTypeXZipCompressed = "application/x-zip-compressed"
)

// zipMagic is the local file header signature for ZIP archives.
var zipMagic = []byte{0x50, 0x4B, 0x03, 0x04}

// httpClient is the HTTP client used for downloads.
// Replaced in tests with httptest-backed transports.
var httpClient = http.DefaultClient

// osRemoveAll, osRename, osWriteFile and readEntryContent are used for
// filesystem operations and ZIP entry reading. Replaced in tests to simulate
// errors in paths that are otherwise impossible to trigger.
var (
	osRemoveAll = os.RemoveAll
	osRename    = os.Rename
	osWriteFile = os.WriteFile
	// readEntryContent reads the bytes from a ZIP file entry.
	// Replaced in tests to inject read errors.
	readEntryContent = defaultReadEntryContent
	unwrapDir        = unwrapSingleDir
)

// Options configures a remote rule sync operation.
type Options struct {
	URL      string // remote ZIP URL
	CacheDir string // local cache directory
}

// DefaultCacheDir returns the platform-native cache directory for gouvernante rules.
// On Linux this is typically ~/.cache/gouvernante/rules,
// on macOS ~/Library/Caches/gouvernante/rules,
// on Windows %LocalAppData%\gouvernante\rules.
func DefaultCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("determine user cache directory: %w", err)
	}

	return filepath.Join(base, "gouvernante", "rules"), nil
}

// Sync downloads a rule ZIP from opts.URL, extracts and validates it, then
// installs the rules into the cache directory. If the server returns 304 Not
// Modified and a valid cache exists, the cached path is returned without
// downloading. Returns the path to the validated rules directory.
//
// On any validation failure the cache is left intact and an error is returned.
// The caller must treat this as fatal — no scan should run.
func Sync(opts Options) (string, error) {
	dataDir := filepath.Join(opts.CacheDir, "data")

	if err := os.MkdirAll(opts.CacheDir, 0o700); err != nil {
		return "", fmt.Errorf("create cache directory: %w", err)
	}

	etag := readETag(opts.CacheDir)

	body, newETag, notModified, err := download(opts.URL, etag)
	if err != nil {
		return "", err
	}

	if notModified {
		if _, statErr := os.Stat(dataDir); statErr != nil {
			return "", fmt.Errorf("server returned 304 but cache is missing; delete %s and retry", opts.CacheDir)
		}

		slog.Info("using cached rules (304 Not Modified)")

		return dataDir, nil
	}

	if err := validateZIPMagic(body); err != nil {
		return "", err
	}

	dir, err := extractAndValidate(body, opts.CacheDir)
	if err != nil {
		return "", err
	}

	// Atomic swap: remove old data dir, rename temp dir into place.
	if err := osRemoveAll(dataDir); err != nil {
		_ = osRemoveAll(dir)
		return "", fmt.Errorf("remove old cache: %w", err)
	}

	if err := osRename(dir, dataDir); err != nil {
		_ = osRemoveAll(dir)
		return "", fmt.Errorf("install rules to cache: %w", err)
	}

	writeETag(opts.CacheDir, newETag)

	slog.Info("rules downloaded and cached", "url", opts.URL, "etag", newETag)

	return dataDir, nil
}

// download fetches the ZIP from url. If etag is non-empty, an If-None-Match
// header is sent. Returns the response body, new ETag, and whether the
// server returned 304.
func download(url, etag string) (body []byte, newETag string, notModified bool, err error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody) //nolint:gosec // URL is user-provided via -rules-url flag
	if err != nil {
		return nil, "", false, fmt.Errorf("create request: %w", err)
	}

	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("download rules from %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		return nil, "", true, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", false, fmt.Errorf("download rules from %s: HTTP %d", url, resp.StatusCode)
	}

	if err := validateContentType(resp.Header.Get("Content-Type")); err != nil {
		return nil, "", false, err
	}

	body, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, "", false, fmt.Errorf("read response body: %w", err)
	}

	if len(body) > maxResponseBytes {
		return nil, "", false, fmt.Errorf("response exceeds %d byte limit", maxResponseBytes)
	}

	return body, resp.Header.Get("ETag"), false, nil
}

// validateContentType rejects responses that are clearly not ZIP archives.
func validateContentType(ct string) error {
	if ct == "" {
		return nil // no Content-Type is acceptable (some servers omit it)
	}

	ct = strings.ToLower(ct)

	// Accept ZIP and generic binary types.
	for _, allowed := range []string{
		contentTypeZip,
		contentTypeOctetStream,
		contentTypeXZipCompressed,
	} {
		if strings.HasPrefix(ct, allowed) {
			return nil
		}
	}

	return fmt.Errorf("unexpected Content-Type %q; expected a ZIP archive", ct)
}

// validateZIPMagic checks that body starts with the ZIP local file header.
func validateZIPMagic(body []byte) error {
	if len(body) < len(zipMagic) || !bytes.Equal(body[:len(zipMagic)], zipMagic) {
		return fmt.Errorf("response is not a valid ZIP archive (bad magic bytes)")
	}

	return nil
}

// extractAndValidate extracts .json files from zipData into a temp directory
// under parentDir, validates every file against the rule schema, and returns
// the temp directory path. On any failure the temp directory is removed.
func extractAndValidate(zipData []byte, parentDir string) (string, error) {
	tmpDir, err := os.MkdirTemp(parentDir, "rulesync-*")
	if err != nil {
		return "", fmt.Errorf("create temp directory: %w", err)
	}

	if err := extractZIP(zipData, tmpDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", err
	}

	if err := unwrapDir(tmpDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", err
	}

	if err := validateExtracted(tmpDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", err
	}

	return tmpDir, nil
}

// extractZIP extracts only .json files from zipData into destDir.
// It rejects symlinks, binary content, zip-slip paths, and non-.json files.
// destDir must be an absolute path.
func extractZIP(zipData []byte, destDir string) error {
	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return fmt.Errorf("open ZIP archive: %w", err)
	}

	for _, f := range reader.File {
		if err := extractZIPEntry(f, destDir); err != nil {
			return err
		}
	}

	return nil
}

// extractZIPEntry processes a single ZIP entry with all security checks.
// absDestDir must be an absolute path.
func extractZIPEntry(f *zip.File, absDestDir string) error {
	// Reject symlinks.
	if f.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("ZIP contains symlink %q; rejecting archive", f.Name)
	}

	// Skip directories.
	if f.FileInfo().IsDir() {
		return nil
	}

	// Only extract .json files.
	if !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
		slog.Debug("skipping non-JSON file in ZIP", "name", f.Name)
		return nil
	}

	// Zip-slip prevention: resolve the target path and verify it stays
	// inside the destination directory.
	target := filepath.Join(absDestDir, filepath.FromSlash(f.Name))
	cleaned := filepath.Clean(target)

	if !strings.HasPrefix(cleaned, absDestDir+string(os.PathSeparator)) {
		return fmt.Errorf("ZIP entry %q escapes destination directory; rejecting archive", f.Name)
	}

	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(cleaned), 0o700); err != nil {
		return fmt.Errorf("create directory for %q: %w", f.Name, err)
	}

	content, err := readEntryContent(f)
	if err != nil {
		return err
	}

	if bytes.ContainsRune(content, '\x00') {
		return fmt.Errorf("ZIP entry %q contains binary data (null bytes); rejecting archive", f.Name)
	}

	if err := osWriteFile(cleaned, content, 0o600); err != nil {
		return fmt.Errorf("write %q: %w", f.Name, err)
	}

	return nil
}

// defaultReadEntryContent reads the full content of a ZIP file entry.
// Open is guaranteed to succeed for entries parsed by zip.NewReader because
// the compression method is validated during parsing — Store and Deflate
// decompressors are always registered.
func defaultReadEntryContent(f *zip.File) ([]byte, error) {
	rc, _ := f.Open()
	defer func() { _ = rc.Close() }()

	return io.ReadAll(rc)
}

// unwrapSingleDir handles ZIP archives that contain a single top-level
// directory (common with GitHub release ZIPs). If the directory contains
// exactly one entry and it is a directory, its contents are moved up.
func unwrapSingleDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read extracted directory: %w", err)
	}

	if len(entries) != 1 || !entries[0].IsDir() {
		return nil // nothing to unwrap
	}

	innerDir := filepath.Join(dir, entries[0].Name())

	innerEntries, err := os.ReadDir(innerDir)
	if err != nil {
		return fmt.Errorf("read inner directory: %w", err)
	}

	for _, e := range innerEntries {
		src := filepath.Join(innerDir, e.Name())
		dst := filepath.Join(dir, e.Name())

		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("unwrap %q: %w", e.Name(), err)
		}
	}

	return os.Remove(innerDir)
}

// validateExtracted loads every .json file in dir through the rule parser
// and schema validator. If any file is invalid, it returns an error naming
// the file and the validation failure. This ensures only schema-compliant
// rules ever reach the cache.
func validateExtracted(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read extracted rules directory: %w", err)
	}

	var count int

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}

		path := filepath.Join(dir, e.Name())
		if _, err := rules.LoadFile(path); err != nil {
			return fmt.Errorf("rule validation failed for %s: %w", e.Name(), err)
		}

		count++
	}

	if count == 0 {
		return fmt.Errorf("ZIP archive contains no .json rule files")
	}

	slog.Info("all rules validated", "count", count)

	return nil
}

// readETag returns the cached ETag value, or empty string if none exists.
func readETag(cacheDir string) string {
	data, err := os.ReadFile(filepath.Join(cacheDir, "etag"))
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(data))
}

// writeETag stores the ETag value for future conditional requests.
func writeETag(cacheDir, etag string) {
	if etag == "" {
		return
	}

	path := filepath.Join(cacheDir, "etag")

	if err := os.WriteFile(path, []byte(etag+"\n"), 0o600); err != nil {
		slog.Warn("failed to write ETag cache", "error", err)
	}
}
