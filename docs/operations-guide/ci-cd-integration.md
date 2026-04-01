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
          curl -sL https://github.com/your-org/gouvernante/releases/latest/download/gouvernante-linux-amd64 \
            -o /usr/local/bin/gouvernante
          chmod +x /usr/local/bin/gouvernante

      - name: Fetch latest rules
        run: |
          git clone --depth 1 https://github.com/your-org/gouvernante-rules.git /tmp/rules

      - name: Run scan
        run: |
          gouvernante -rules /tmp/rules -dir . -json -output auto

      - name: Upload scan report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: gouvernante-report
          path: gouvernante-*.json
```

Key points:

- The **Fetch latest rules** step ensures every build uses the most current rules.
- The **Run scan** step will exit `2` and fail the job if findings are detected.
- The **Upload scan report** step runs `if: always()` so the JSON report is available even when the scan fails.

## GitLab CI

```yaml
supply-chain-scan:
  stage: test
  image: golang:1.22-alpine
  before_script:
    - wget -qO /usr/local/bin/gouvernante \
        https://github.com/your-org/gouvernante/releases/latest/download/gouvernante-linux-amd64
    - chmod +x /usr/local/bin/gouvernante
    - git clone --depth 1 https://github.com/your-org/gouvernante-rules.git /tmp/rules
  script:
    - gouvernante -rules /tmp/rules -dir . -json -output gouvernante-report.json
  artifacts:
    when: always
    paths:
      - gouvernante-report.json
    expire_in: 30 days
  allow_failure: false
```

Setting `allow_failure: false` (the default) ensures that exit code `2` blocks the pipeline.

## Generic Shell Script

For Jenkins, Buildkite, CircleCI, or any system that runs shell commands:

```bash
#!/usr/bin/env bash
set -euo pipefail

RULES_DIR="/tmp/gouvernante-rules"
REPORT_FILE="gouvernante-report.json"

# 1. Fetch latest rules
git clone --depth 1 https://github.com/your-org/gouvernante-rules.git "$RULES_DIR" 2>/dev/null \
  || (cd "$RULES_DIR" && git pull --ff-only)

# 2. Run the scan
gouvernante -rules "$RULES_DIR" -dir . -json -output "$REPORT_FILE"
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

## JSON Output for Machine Parsing

Always use `-json` in CI pipelines. The JSON output is stable and scriptable:

```bash
# Count findings (JSON output is a flat array of finding objects)
gouvernante -rules /tmp/rules -dir . -json 2>/dev/null | jq 'length'

# Extract critical findings only
gouvernante -rules /tmp/rules -dir . -json 2>/dev/null | jq '[.[] | select(.severity == "critical")]'

# Fail only on critical severity
gouvernante -rules /tmp/rules -dir . -json -output report.json || true
CRITICAL=$(jq '[.[] | select(.severity == "critical")] | length' report.json)
if [ "$CRITICAL" -gt 0 ]; then
  echo "Critical supply chain findings detected"
  exit 2
fi
```

## Rules Distribution in CI

The scanner is only as effective as the freshness of its rules. Every CI run should use the latest rules.

### Option 1: Clone a Rules Repository (Recommended)

Maintain rules in a dedicated Git repository. Clone it at build time:

```bash
git clone --depth 1 https://github.com/your-org/gouvernante-rules.git /tmp/rules
```

Advantages:

- Rules are versioned and auditable.
- Teams can pin to a tag (`git clone --branch v2026.04.01`) for reproducibility.
- Pull requests on the rules repo provide peer review.

### Option 2: Fetch from an Artifact Store

Store rules as a tarball in your artifact registry (Artifactory, S3, GCS):

```bash
curl -sL https://artifacts.your-org.com/gouvernante-rules/latest.tar.gz | tar xz -C /tmp/rules
```

Advantages:

- Works in air-gapped environments.
- Can be signed and verified.

### Option 3: Bundle Rules in the Scanner Image

If you build a custom Docker image for CI, copy the rules directory into the image:

```dockerfile
FROM golang:1.22-alpine
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
