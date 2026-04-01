// Package lockfile provides parsers for npm ecosystem lockfile formats.
//
// Supported formats:
//   - pnpm-lock.yaml (v6 through v9)
//   - package-lock.json (v1, v2, v3)
//   - yarn.lock (v1 classic)
//
// All parsers are hand-written using only the Go standard library to avoid
// depending on the npm ecosystem that is being scanned.
package lockfile
