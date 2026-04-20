# gouvernante

A static Go binary for detecting npm supply chain compromises. Scans lockfiles
against configurable JSON rules and checks host filesystems for known IOCs.

!!! tldr "TL;DR"

    Grab the [latest binary for your platform](https://github.com/DenktMit-eG/gouvernante/releases/latest) and scan your project using the official rules feed:

    ```bash
    gouvernante -rules-url https://denktmit-eg.github.io/gouvernante/rules/rules.zip -dir /path/to/your/project -host -output report.txt
    ```

---

## Where do you want to go?

!!! info "I'm new and want to understand what this does"

    Core concepts, how the scanner works, and your first scan in 2 minutes.

    **[Quickstart →](getting-started/quickstart.md)**

!!! tip "I need to write a rule for a new incident"

    A new supply chain attack just dropped. Follow the step-by-step guide.

    **[Writing Rules →](developer-guide/writing-rules.md)**

!!! abstract "I want to integrate this into CI/CD"

    Automated supply chain scanning on every build.

    **[CI/CD Integration →](operations-guide/ci-cd-integration.md)**

!!! quote "A new attack just hit and I need to respond now"

    Step-by-step: gather IOCs, write rule, distribute, scan everything.

    **[New npm Compromise Runbook →](operations-guide/runbooks/new-npm-compromise.md)**

---


