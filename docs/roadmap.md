---
tags:
  - roadmap
  - planning
---

# Roadmap

!!! tldr "TL;DR"

    What gouvernante can do today, what is defined in the schema but not yet
    implemented, and what is planned for future releases.

!!! tip "Who is this for?"

    **Audience:** All — users evaluating the tool, contributors looking for work.

---

## Implemented

| Feature | Status | Details |
|---------|--------|---------|
| Lockfile scanning (pnpm, npm, yarn) | Done | Parses `pnpm-lock.yaml`, `package-lock.json`, `yarn.lock` |
| Package version matching (exact, wildcard, semver ranges) | Done | `=1.14.1`, `1.14.1`, `*`, `>=1.0.0 <2.0.0`, `^1.7.0`, `~2.0.0` (via Masterminds/semver v3) |
| package.json scanning | Done | Extracts `dependencies` and `devDependencies`; pinned versions match directly, range expressions checked against compromised versions |
| Dropper package detection | Done | Any version of a dropper package is a finding |
| Host indicator: file existence | Done | Checks `os.Stat()` on expanded paths |
| node_modules scanning | Done | Checks installed packages in project and global node_modules |
| pnpm store/cache scanning | Done | Scans ~/.local/share/pnpm, ~/.cache/pnpm, $PNPM_HOME |
| nvm cache and globals | Done | Scans $NVM_DIR cache and per-version global node_modules |
| npm cache scanning | Done | Scans _cacache blobs for indexed package names and versions |
| Dynamic npm prefix detection | Done | Uses `$NPM_CONFIG_PREFIX` env var and well-known OS paths |
| Host indicator: file hashes (sha256, sha1, md5, sha512) | Done | When a file indicator matches and carries `hashes`, the scanner computes file hashes and reports whether they match a known-bad variant |
| Host indicator: network | Schema only | C2 domains/IPs stored for analyst reference, not actively checked |
| Host indicator: process | Schema only | Process names stored, not checked against running processes |
| Host indicator: registry | Schema only | Windows registry keys stored, not checked |
| Host indicator: environment | Schema only | Environment variable names stored, not checked |
| JSON rule format with schema validation | Done | `pkg/rules/schema.json` (draft-07) |
| Go-side validation (`Validate()`) | Done | Mirrors all schema constraints for programmatic rule construction |
| Schema fidelity testing | Done | 18 valid + 18 invalid fixtures, bidirectional round-trip |
| Cross-platform build | Done | linux/darwin amd64+arm64, windows amd64 |
| Woodpecker CI with Codeberg releases | Done | `.woodpecker.yml` |
| Text and JSON output | Done | `-json` flag |
| Exit codes for CI/CD | Done | 0=clean, 1=error, 2=findings |

## Not Yet Implemented

These features are defined in the schema or referenced in documentation but
not yet active in the scanner.

### Host indicator: network connections

**Schema:** Supported — `type: "network"` with `value` field for host:port or IP.

**Current behavior:** Network indicators are stored in rules for analyst reference but silently skipped during scanning.

**What's needed:** Inspect active network connections (equivalent to `netstat`/`ss`) and/or DNS cache for connections to known C2 domains and IPs. This is a significantly larger scope than file checks — it involves OS-specific APIs and potentially elevated permissions.

### Host indicator: running processes

**Schema:** Supported — `type: "process"` with `value` field.

**Current behavior:** Silently skipped.

**What's needed:** Enumerate running processes and match against known malicious process names. OS-specific: `/proc` on Linux, `ps` on macOS, Windows process APIs.

### Host indicator: Windows registry

**Schema:** Supported — `type: "registry"` with `value` field.

**Current behavior:** Silently skipped.

**What's needed:** Query Windows registry keys. Only applicable on Windows — should be a no-op on other platforms.

### Host indicator: environment variables

**Schema:** Supported — `type: "environment"` with `value` field.

**Current behavior:** Silently skipped.

**What's needed:** Check if specific environment variables exist (e.g., exfiltration staging tokens). Simple to implement via `os.Getenv()`.

### Yarn cache scanning

The yarn cache (`~/.yarn/cache`, `~/.cache/yarn`) is not scanned yet.
Same `bytes.Contains` approach as npm cache would work.

### CSV import helper

**Planned:** A helper tool or subcommand to convert CSV feeds (e.g., from Wiz Security's public indicators) into the canonical JSON rule format.

### Bun lockfile support

**Schema:** `bun` is a valid `lockfile_ecosystems` value.

**What's needed:** A parser for `bun.lock` in `pkg/lockfile/`.

---

## Contributing

Pick any item from the "Not Yet Implemented" list. The easiest starting points are:

1. **Environment variable checks** — straightforward `os.Getenv()`, minimal code.
2. **Bun lockfile parser** — follow the [Adding Parsers](developer-guide/adding-parsers.md) guide.

For larger items (network, process, registry), open an issue to discuss the approach before starting.
