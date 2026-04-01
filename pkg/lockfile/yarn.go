package lockfile

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ParseYarnLock parses yarn.lock (v1 classic format).
//
// Entries look like:
//
//	axios@^1.7.0:
//	  version "1.7.8"
//	  resolved "https://..."
//	  integrity sha512-...
func ParseYarnLock(path string) ([]PackageEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var entries []PackageEntry
	seen := make(map[string]bool)
	var currentNames []string

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" || line[0] == '#' {
			continue
		}

		// Top-level entry (no leading whitespace, ends with colon).
		if line[0] != ' ' && line[0] != '\t' && strings.HasSuffix(strings.TrimSpace(line), ":") {
			currentNames = parseYarnEntryHeader(line)

			continue
		}

		// Indented "version" line.
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "version ") && len(currentNames) > 0 {
			version := strings.TrimPrefix(trimmed, "version ")
			version = strings.Trim(version, "\"'")

			for _, name := range currentNames {
				dedupKey := name + "@" + version
				if !seen[dedupKey] {
					seen[dedupKey] = true
					entries = append(entries, PackageEntry{Name: name, Version: version})
				}
			}

			currentNames = nil
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}

	return entries, nil
}

// parseYarnEntryHeader parses entry headers like:
//
//	axios@^1.7.0, axios@~1.7.0:
//	"@scope/pkg@^1.0.0":
func parseYarnEntryHeader(line string) []string {
	line = strings.TrimSuffix(strings.TrimSpace(line), ":")
	parts := strings.Split(line, ",")
	seen := make(map[string]bool)

	var names []string

	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, "\"'")

		// Split on last @ to get package name (skip @ for scoped packages).
		idx := strings.LastIndex(part, "@")
		if idx <= 0 {
			continue
		}

		name := part[:idx]
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}

	return names
}
