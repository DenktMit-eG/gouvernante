---
tags:
  - reference
  - ci-cd
  - exit-codes
---

# Exit Codes

!!! tldr "TL;DR"

    - **0** — scan completed, no findings.
    - **1** — configuration or runtime error (missing flags, bad rule files, parse failures).
    - **2** — scan completed, one or more findings detected.

    Use exit code 2 as your CI/CD gate: it means the scan ran successfully
    and found something bad.

!!! tip "Who is this for?"

    **Audience:** CI/CD engineers, platform teams, and anyone scripting gouvernante.
    **Reading time:** ~3 minutes.

---

## Exit code reference

| Code | Meaning | Action |
|------|---------|--------|
| **0** | Clean scan. No compromised packages or host indicators found. | Pipeline passes. |
| **1** | Error. The scanner could not complete — missing `-rules` flag, unreadable rule files, lockfile parse failure, or other runtime error. | Fix the configuration. This is not a security finding. |
| **2** | Findings detected. The scan completed and matched one or more rules against packages in lockfiles or host indicators. | Investigate immediately. Block the pipeline. |

---

## CI/CD usage

### GitHub Actions

```yaml
- name: Supply chain scan
  run: |
    gouvernante -rules ./rules -dir . -json -output auto
  # Exit code 2 fails the step automatically.
  # Exit code 1 also fails — bad config should not pass silently.
```

If you need to distinguish between "error" and "findings detected":

```yaml
- name: Supply chain scan
  id: scan
  run: |
    gouvernante -rules ./rules -dir . -json -output auto || echo "exit_code=$?" >> "$GITHUB_OUTPUT"
  continue-on-error: true

- name: Check scan result
  run: |
    if [ "${{ steps.scan.outputs.exit_code }}" = "2" ]; then
      echo "::error::Supply chain findings detected"
      exit 1
    elif [ "${{ steps.scan.outputs.exit_code }}" = "1" ]; then
      echo "::error::Scanner configuration error"
      exit 1
    fi
```

### Shell script

```bash
#!/usr/bin/env bash
set -euo pipefail

gouvernante -rules ./rules -dir . -json -output report.json
exit_code=$?

case $exit_code in
  0)
    echo "Clean — no findings."
    ;;
  1)
    echo "ERROR: scanner failed to run. Check configuration." >&2
    exit 1
    ;;
  2)
    echo "ALERT: supply chain findings detected. See report.json" >&2
    exit 2
    ;;
  *)
    echo "ERROR: unexpected exit code $exit_code" >&2
    exit 1
    ;;
esac
```

!!! warning "Do not ignore exit code 1"

    Exit code 1 means the scanner did not run correctly. A misconfigured scan
    that silently passes is worse than no scan at all. Treat both 1 and 2 as
    pipeline failures.

---

## Next Steps

- **Wire into your pipeline** --> [CI/CD Integration](../operations-guide/ci-cd-integration.md)
- **Understand the CLI flags** --> [CLI Cheatsheet](cli-cheatsheet.md)
- **Investigate findings** --> [New npm Compromise Runbook](../operations-guide/runbooks/new-npm-compromise.md)
