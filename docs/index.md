# gouvernante

A static Go binary for detecting npm supply chain compromises. Scans lockfiles
against configurable JSON rules and checks host filesystems for known IOCs.

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

## Contributing to this documentation

```bash
docker compose -f docker-compose.docs.yml up
```

Open [http://localhost:8000/](http://localhost:8000/) with live-reload. Stop with `Ctrl+C`.
