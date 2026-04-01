---
tags:
  - operations
  - runbooks
---

# Runbooks

!!! tldr "TL;DR"

    - Runbooks are step-by-step procedures for specific operational scenarios.
    - Each runbook has a trigger condition, a severity level, and a clear sequence of actions.
    - Use the index table below to find the right runbook for your situation.

!!! tip "Who is this for?"

    **Audience:** Security engineers, on-call responders, and engineering teams handling scanner-related incidents.
    **Reading time:** ~3 minutes.

---

## Runbook Index

| Runbook | Trigger | Severity |
|---------|---------|----------|
| [New NPM Compromise](new-npm-compromise.md) | New npm supply chain attack reported (advisory, social media, security blog) | Critical |
| [False Positive Triage](false-positive-triage.md) | Scanner reports a finding but the package is not actually compromised | Medium |

## Runbook Template

All runbooks follow a consistent structure. When writing a new runbook, use this template:

### What Happened

Describe the trigger condition: what event or observation initiates this runbook? Be specific enough that an on-call engineer can recognize the situation immediately.

### Root Cause

Explain why this situation occurs. This helps responders understand the problem rather than blindly following steps.

### How to Fix

Provide numbered steps from detection to resolution. Each step should include:

- **Who** performs the action.
- **What** command to run or action to take.
- **What to expect** as output or result.
- **What to do if** the expected result does not occur.

### Verification

Describe how to confirm the issue is resolved. Typically this is a clean scanner run (exit code `0`).

---

## Self-Assessment

- [ ] Can you identify which runbook to use when a new attack is reported vs. when a scan produces a false positive?
- [ ] Do you know the standard structure of a runbook in this project?

## Next Steps

- **Respond to an attack now** --> [New NPM Compromise](new-npm-compromise.md)
- **Handle a false positive** --> [False Positive Triage](false-positive-triage.md)
- **Understand the full incident flow** --> [New npm Compromise Runbook](../runbooks/new-npm-compromise.md)
