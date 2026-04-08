# gouvernante

A static Go binary for detecting npm supply chain compromises. Scans lockfiles against configurable JSON rules and checks the host filesystem for known indicators of compromise (IOCs).

## Why

npm supply chain attacks are becoming routine. Existing tools (npm audit, Grype, Trivy) are advisory-driven and lag behind zero-day incidents. When a new attack hits, you need a scanner that:

- Does not depend on the npm ecosystem (running `node` to detect a Node supply chain attack is self-defeating)
- Can be configured with new rules in minutes, not days
- Checks both lockfiles and host artifacts in a single pass
- Ships as a single static binary with minimal, vetted dependencies

## Quick start

```bash
# Build (binaries are written to dist/binaries/gouvernante-<os>-<arch>)
# Copy the binary for your platform onto your PATH as "gouvernante"
make build

# Scan a project directory (auto-detects lockfiles)
gouvernante -rules /path/to/rules -dir /path/to/project

# Scan a specific lockfile
gouvernante -rules /path/to/rules -lockfile /path/to/pnpm-lock.yaml

# Recursively scan a monorepo for all lockfiles
gouvernante -rules /path/to/rules -dir /path/to/monorepo -recursive

# Include host IOC checks
gouvernante -rules /path/to/rules -dir /path/to/project -host

# JSON output
gouvernante -rules /path/to/rules -dir /path/to/project -json

# Write report to file
gouvernante -rules /path/to/rules -dir /path/to/project -output auto

# Enable debug-level trace logging
gouvernante -rules /path/to/rules -dir /path/to/project -trace
```

## Supported lockfile formats

| Format              | File                  | Status    |
|---------------------|-----------------------|-----------|
| npm v1/v2/v3        | `package-lock.json`   | Supported |
| pnpm v6/v7/v8/v9    | `pnpm-lock.yaml`      | Supported |
| Yarn Classic (v1)   | `yarn.lock`           | Supported |
| package.json        | `package.json`        | Supported |

## Exit codes

| Code | Meaning                      |
|------|------------------------------|
| 0    | No findings                  |
| 1    | Error (bad args, parse fail) |
| 2    | Findings detected            |

## Rule format

Rules are JSON files following the [canonical schema](pkg/rules/schema.json). See [docs/architecture/rule-format.md](docs/architecture/rule-format.md) for the full specification.

Each rule file contains a `schema_version` and a `rules` array. A rule combines:

- **package_rules** -- which package+version combinations are compromised
- **dropper_packages** -- auxiliary packages installed by the attack
- **host_indicators** -- filesystem artifacts left by the compromise (files, paths, hashes)
- **remediation** -- what to do if a match is found

## Development

```bash
make fmt        # Format code (gofumpt + goimports)
make lint       # Run golangci-lint with strict config
make test       # Run tests with race detector
make cover      # Run tests with coverage report
make all        # fmt + lint + cover + build + test-integration
```

See [docs/developer-guide/code-style.md](docs/developer-guide/code-style.md) for the full development guide.

## Documentation
To build the docs site locally and read it nicely formatted in your browser, run in this project root directory:

```bash
docker compose -f docker-compose.docs.yml up
```

Open [http://localhost:8000/](http://localhost:8000/) with live-reload. Stop with `Ctrl+C`.

- [Architecture overview](docs/architecture/overview.md)
- [Rule format specification](docs/architecture/rule-format.md)
- [Developer guide](docs/developer-guide/writing-rules.md)
- [Operations guide](docs/operations-guide/running-scans.md)
- [Decision log](docs/reference/decision-log/index.md)
- [License](LICENSE)
