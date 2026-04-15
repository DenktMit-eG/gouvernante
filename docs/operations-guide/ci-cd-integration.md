---
tags:
  - operations
  - ci-cd
  - automation
---

# CI/CD Integration

!!! tldr "TL;DR"

    - Exit code `2` means findings were detected — use it to fail builds.
    - Use `-json` for machine-parseable output in pipelines.
    - Distribute rules by cloning a rules repository or fetching from an artifact store at build time.
    - The scanner is a static Go binary with no runtime dependencies — copy it anywhere.

!!! tip "Who is this for?"

    **Audience:** Platform engineers and DevOps teams adding supply chain scanning to pipelines.
    **Reading time:** ~8 minutes.

---

## Exit Code Strategy

The scanner's exit codes map directly to CI pass/fail logic:

| Exit Code | CI Behavior |
|-----------|-------------|
| `0` | Pass — no findings. |
| `1` | Fail — scanner error (bad config, missing rules). Treat as pipeline infrastructure failure. |
| `2` | Fail — findings detected. Block the build or deployment. |

In most CI systems, any non-zero exit code fails the step. This means both errors and findings will block the pipeline by default, which is the correct behavior.

## GitHub Actions

Using `-rules-url` (recommended — no separate clone step needed):

```yaml
name: Supply Chain Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Download gouvernante
        run: |
          curl -sL https://github.com/DenktMit-eG/gouvernante/releases/latest/download/gouvernante-linux-amd64 \
            -o /usr/local/bin/gouvernante
          chmod +x /usr/local/bin/gouvernante

      - name: Run scan
        run: |
          gouvernante \
            -rules-url https://denktmit-eg.github.io/gouvernante/rules/rules.zip \
            -dir . -recursive -json -output auto

      - name: Upload scan report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: gouvernante-report
          path: gouvernante-*.json
```

Key points:

- The scanner downloads and caches rules automatically — no separate `git clone` step.
- ETag-based caching ensures rules are only re-downloaded when they change.
- The **Run scan** step will exit `2` and fail the job if findings are detected, or `1` if the rules download or validation fails.
- The **Upload scan report** step runs `if: always()` so the JSON report is available even when the scan fails.

## GitLab CI

```yaml
supply-chain-scan:
  stage: test
  image: golang:1.25-alpine
  before_script:
    - wget -qO /usr/local/bin/gouvernante \
        https://github.com/DenktMit-eG/gouvernante/releases/latest/download/gouvernante-linux-amd64
    - chmod +x /usr/local/bin/gouvernante
  script:
    - gouvernante
        -rules-url https://denktmit-eg.github.io/gouvernante/rules/rules.zip
        -dir . -recursive -json -output gouvernante-report.json
  artifacts:
    when: always
    paths:
      - gouvernante-report.json
    expire_in: 30 days
  allow_failure: false
```

Setting `allow_failure: false` (the default) ensures that exit code `2` blocks the pipeline. Exit code `1` (rules download or validation failure) also blocks the pipeline.

## Generic Shell Script

For Jenkins, Buildkite, CircleCI, or any system that runs shell commands:

```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_DIR="/tmp/gouvernante-rules"
REPORT_FILE="gouvernante-report.json"

# 1. Fetch latest rules (shallow clone of the gouvernante repo; use rules/incidents/)
git clone --depth 1 https://codeberg.org/DenktMit-eG/gouvernante.git "$RULES_DIR" 2>/dev/null \
  || (cd "$RULES_DIR" && git pull --ff-only)
RULES_DIR="$RULES_DIR/rules/incidents"

# 2. Run the scan
gouvernante -rules "$RULES_DIR" -dir . -recursive -json -output "$REPORT_FILE"
EXIT_CODE=$?

# 3. Handle results
case $EXIT_CODE in
  0)
    echo "Supply chain scan: CLEAN"
    ;;
  1)
    echo "Supply chain scan: ERROR — check scanner configuration"
    exit 1
    ;;
  2)
    echo "Supply chain scan: FINDINGS DETECTED"
    echo "Review report: $REPORT_FILE"
    exit 2
    ;;
esac
```

!!! note

    If you use `set -e`, the script will exit immediately on a non-zero return. To capture the exit code for branching, either disable `set -e` before the scan command or use `|| true` and inspect `${PIPESTATUS[0]}`.

## Heuristic Scanning in CI

The `-heuristic` flag can run alongside or independently of rule-based scanning. It does not require a rules directory, making it useful as a standalone zero-config check:

```yaml
      - name: Heuristic scan
        run: |
          gouvernante -heuristic -dir . -recursive -json -output heuristic-report.json
```

For maximum coverage, run both scans:

```yaml
      - name: Rule-based scan
        run: |
          gouvernante -rules /tmp/rules -dir . -recursive -json -output rule-report.json

      - name: Heuristic scan
        run: |
          gouvernante -heuristic -dir . -recursive -json -output heuristic-report.json
```

## JSON Output for Machine Parsing

Always use `-json` in CI pipelines. The JSON output is stable and scriptable:

```bash
# Count findings (JSON output is {"findings": [...], "summary": {...}})
gouvernante -rules /tmp/rules -dir . -json 2>/dev/null | jq '.findings | length'

# Extract critical findings only
gouvernante -rules /tmp/rules -dir . -json 2>/dev/null | jq '[.findings[] | select(.severity == "critical")]'

# Fail only on critical severity
gouvernante -rules /tmp/rules -dir . -json -output report.json || true
CRITICAL=$(jq '[.findings[] | select(.severity == "critical")] | length' report.json)
if [ "$CRITICAL" -gt 0 ]; then
  echo "Critical supply chain findings detected"
  exit 2
fi
```

## Rules Distribution in CI

The scanner is only as effective as the freshness of its rules. Every CI run should use the latest rules.

### Option 1: Use `-rules-url` (Recommended)

The simplest approach: point the scanner at a hosted rules ZIP. The scanner handles downloading, caching, and ETag-based conditional requests automatically:

```bash
gouvernante -rules-url https://denktmit-eg.github.io/gouvernante/rules/rules.zip \
  -dir . -recursive -json -output auto
```

In CI, you can optionally set `-rules-cache` to a path that is cached between builds:

```yaml
      # GitHub Actions example
      - name: Run scan
        run: |
          gouvernante -rules-url https://denktmit-eg.github.io/gouvernante/rules/rules.zip \
            -rules-cache ${{ runner.temp }}/gouvernante-rules \
            -dir . -recursive -json -output auto
```

Advantages:

- **Zero setup.** No `git clone`, no separate fetch step, no artifact store configuration.
- **Efficient.** ETag-based caching means unchanged rules are never re-downloaded.
- **Safe.** Every downloaded rule file is validated against the JSON schema before use. Invalid rules are rejected and the scanner exits with code 1, failing the CI pipeline.

### Option 2: Clone the gouvernante Repository

Clone this repository and point `-rules` at its `rules/incidents/` directory. Useful when you want to pin to a specific commit or tag:

```bash
git clone --depth 1 https://codeberg.org/DenktMit-eG/gouvernante.git /tmp/gouvernante
gouvernante -rules /tmp/gouvernante/rules/incidents -dir . -recursive
```

Advantages:

- Rules are versioned alongside the scanner and auditable via git history.
- Teams can pin to a tag (`git clone --branch v0.3.0`) for reproducibility.
- Works offline after the initial clone — no HTTP round-trip on every run.

### Option 3: Fetch from an Artifact Store

Store rules as a tarball in your artifact registry (Artifactory, S3, GCS):

```bash
curl -sL https://artifacts.your-org.com/gouvernante-rules/latest.tar.gz | tar xz -C /tmp/rules
```

Advantages:

- Works in air-gapped environments.
- Can be signed and verified.

### Option 4: Bundle Rules in the Scanner Image

If you build a custom Docker image for CI, copy the rules directory into the image:

```dockerfile
FROM golang:1.25-alpine
COPY gouvernante /usr/local/bin/gouvernante
COPY rules/ /opt/gouvernante-rules/
```

!!! warning

    Bundled rules become stale the moment the image is built. This option is only suitable when you rebuild the image frequently (e.g., on every rules repo push).

---

## Self-Assessment

- [ ] Can you explain why exit code `2` (not `1`) represents detected findings?
- [ ] Can you modify the GitHub Actions example to fail only on critical-severity findings?
- [ ] Do you know how to ensure your CI pipeline uses the latest rules on every run?

## Next Steps

- **All CLI flags** --> [Running Scans](running-scans.md)
- **Respond when a scan finds something** --> [New npm Compromise Runbook](runbooks/new-npm-compromise.md)
