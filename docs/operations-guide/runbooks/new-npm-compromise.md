---
tags:
  - operations
  - runbooks
  - incident-response
---

# Runbook: New NPM Compromise

!!! tldr "TL;DR"

    - Trigger: a new npm supply chain attack is publicly reported.
    - Gather IOCs from the advisory, write a rule, test it, distribute it, scan everything.
    - Target: first organization-wide scan within 1 hour of disclosure.

!!! tip "Who is this for?"

    **Audience:** Security engineers responding to a newly reported npm supply chain attack.
    **Reading time:** ~10 minutes.

---

## What Happened

A new npm supply chain attack has been reported. Sources may include:

- Hacker News or Twitter/X post.
- GitHub security advisory.
- Vendor security blog (Snyk, Socket, Phylum, etc.).
- npm security notice.
- Internal detection or report.

The attack may involve compromised releases of legitimate packages, newly published malicious packages (typosquats), or dropper packages installed via postinstall scripts.

## Root Cause

An attacker has published malicious code to the npm registry, either by compromising a maintainer's account, injecting code into the build pipeline, or registering a new package designed to deceive.

## How to Fix

### Step 1: Open an Incident Channel

**Who:** First responder.

1. Create an incident channel (Slack, Teams, etc.).
2. Post the source link (advisory URL, tweet, blog post).
3. Tag the security team.

### Step 2: Gather IOCs

**Who:** Security team.

From the advisory, extract:

| IOC Type | What to Look For | Example |
|----------|-----------------|---------|
| Compromised package | Package name + affected versions | `axios` versions `1.7.8`, `1.7.9`, `1.8.1` |
| Dropper packages | Packages installed by the attack | `plain-crypto-js` |
| Host artifacts | Files dropped on disk | `/tmp/ld.py`, `~/.node_modules/.cache/sentry.js` |
| Hashes | SHA-256 of known malicious files | `a1b2c3d4...` |

If the advisory is incomplete, check:

- The package's npm page for recently published versions.
- The package's GitHub repository for suspicious commits.
- Community threads for additional IOCs.

### Step 3: Write the Rule

**Who:** Security team.

Create a new rule file. Here is a minimal example based on a hypothetical advisory reporting that `example-utils` versions `2.3.1` and `2.3.2` were compromised, dropping a file at `/tmp/.node-cache`:

```json
{
  "schema_version": "1.0.0",
  "rules": [
    {
      "id": "SSC-2026-005",
      "title": "Compromised example-utils releases",
      "kind": "compromised-release",
      "ecosystem": "npm",
      "severity": "critical",
      "summary": "Versions 2.3.1 and 2.3.2 of example-utils contain a postinstall script that exfiltrates environment variables.",
      "aliases": [],
      "references": [
        "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"
      ],
      "package_rules": [
        {
          "package_name": "example-utils",
          "affected_versions": ["=2.3.1", "=2.3.2"],
          "lockfile_ecosystems": ["npm", "pnpm", "yarn"],
          "notes": "Compromised via maintainer account takeover."
        }
      ],
      "dropper_packages": [],
      "host_indicators": [
        {
          "type": "file",
          "path": "/tmp",
          "file_name": ".node-cache",
          "oses": ["linux", "darwin"],
          "hashes": [],
          "confidence": "high",
          "notes": "Exfiltration staging file created by postinstall script."
        }
      ],
      "remediation": {
        "summary": "Pin example-utils to version 2.3.0 or upgrade to 2.3.3 once published.",
        "steps": ["Pin example-utils to 2.3.0", "Upgrade to 2.3.3 once published"]
      },
      "metadata": {
        "published_at": "2026-04-01T12:00:00Z",
        "last_updated_at": "2026-04-01T12:00:00Z"
      }
    }
  ]
}
```

Save this as `rules/SSC-2026-005.json`.

### Step 4: Test the Rule

**Who:** Security team.

Create or obtain a lockfile that contains the compromised package, then verify detection:

```bash
# Test against a known-affected lockfile
gouvernante -rules ./rules -lockfile ./test/affected-lockfile.json
echo "Exit code: $?"
# Expected: 2 (findings detected)

# Test against a clean lockfile
gouvernante -rules ./rules -lockfile ./test/clean-lockfile.json
echo "Exit code: $?"
# Expected: 0 (clean)

# Test host indicators (if applicable)
gouvernante -rules ./rules -lockfile ./test/affected-lockfile.json -host
```

If the exit code does not match expectations, review the rule for typos in package names or version expressions.

### Step 5: Distribute the Rule

**Who:** Security team.

Push to the rules repository:

```bash
cd /path/to/gouvernante-rules
cp /path/to/SSC-2026-005.json .
git add SSC-2026-005.json
git commit -m "SSC-2026-005: compromised example-utils 2.3.1, 2.3.2"
git push origin main
```

Notify all teams in the incident channel:

> New gouvernante rule published: SSC-2026-005 (compromised example-utils).
> Pull latest rules and scan your projects immediately.
> `git -C /path/to/gouvernante-rules pull && gouvernante -rules /path/to/gouvernante-rules -dir . -host`

### Step 6: Scan All Projects

**Who:** Engineering teams.

Each team pulls the latest rules and scans:

```bash
git -C /path/to/gouvernante-rules pull --ff-only
gouvernante -rules /path/to/gouvernante-rules -dir /path/to/project -host -json -output auto
```

For organizations with centralized CI, trigger pipeline re-runs across all repositories.

### Step 7: Triage Findings

**Who:** Engineering teams, with security team support.

For each finding:

1. **Confirm the version is actually resolved** in the lockfile (not just declared in `package.json`).
2. **Check if postinstall scripts ran** — if `node_modules` was populated with this version, assume code execution occurred.
3. **Check host indicators** — if `-host` reported findings, the machine may be actively compromised.
4. **Escalate** if host IOCs are confirmed: isolate the machine, rotate credentials, follow your compromised-host procedure.

### Step 8: Remediate

**Who:** Engineering teams.

```bash
# Pin to a safe version
npm install example-utils@2.3.0

# Or remove the package if not needed
npm uninstall example-utils

# Regenerate lockfile
npm install

# Verify clean scan
gouvernante -rules /path/to/gouvernante-rules -dir . -host
echo "Exit code: $?"
# Expected: 0
```

### Step 9: Close the Loop

**Who:** Security team.

1. Collect scan results from all teams.
2. Confirm all affected projects have remediated and verified clean scans.
3. Update the incident channel with final status.
4. Close the incident.

## Timeline Targets

| Step | Owner | Target Time |
|------|-------|-------------|
| Attack reported | First responder | 0-5 min |
| Gather IOCs | Security team | 5-15 min |
| Write rule | Security team | 10-20 min |
| Test rule | Security team | 5-10 min |
| Distribute rule | Security team | 5 min |
| Scan all projects | Engineering teams | 15-30 min |
| Triage & remediate | Engineering teams | Varies |
| Verify clean scan | Engineering teams | 5 min per project |

**Target: first organization-wide scan under 1 hour from disclosure.**

## Responsibility Matrix

| Activity | Security Team | Engineering Teams |
|----------|:---:|:---:|
| Monitor for new attacks | Owns | Informs |
| Write and test rules | Owns | -- |
| Distribute rules | Owns | Pulls |
| Run scans | Supports | Owns |
| Triage findings | Advises | Owns |
| Remediate | Advises | Owns |
| Verify clean scan | Reviews | Owns |

## Post-Incident

- Update the rule with any additional IOCs discovered during response.
- Conduct a retrospective: how long from disclosure to first scan? Where were the bottlenecks?
- Update this runbook if the process can be improved.

---

## Self-Assessment

- [ ] Can you write a minimal rule from an advisory containing a package name and affected versions?
- [ ] Do you know the difference between a finding in a lockfile and a host indicator finding?
- [ ] Can you explain why testing against both an affected and a clean lockfile matters?

## Next Steps

- **Handle false positives** --> [False Positive Triage](false-positive-triage.md)
- **Understand rule format in depth** --> [Rule Format](../../architecture/rule-format.md)
- **Set up automated scanning** --> [CI/CD Integration](../ci-cd-integration.md)
