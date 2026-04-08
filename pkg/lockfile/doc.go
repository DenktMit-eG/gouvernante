// Package lockfile provides parsers for npm ecosystem lockfile formats.
//
// Supported formats:
//   - pnpm-lock.yaml (v6 through v9)
//   - package-lock.json (v1, v2, v3)
//   - yarn.lock (v1 classic)
//
// Parsers use the Go standard library where possible; the pnpm parser uses
// goccy/go-yaml. No npm ecosystem tooling is invoked.
package lockfile
