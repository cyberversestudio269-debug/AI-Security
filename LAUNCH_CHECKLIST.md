# AI Risk Scanner launch checklist

**Last updated:** 2026-11-16
**Scope:** Global-ready product engineering and ISO readiness; not a certification or legal-compliance claim.

Use this together with [the ISO readiness assessment](./docs/iso-readiness.md), which has the standards references and detailed gap notes.

## Current status

- [x] Local web pilot: accounts, target ownership challenge, offline scan, questionnaire, findings, and PDF report.
- [x] Public HTTPS target checks: DNS resolution, reject non-public addresses, pin the selected address, and refuse redirects.
- [x] Browser sessions use HttpOnly, SameSite cookies; the browser no longer stores the session token in JavaScript storage.
- [x] Users can delete their active account, targets, scans, and sessions; deletion is blocked while a scan is active.
- [x] Retention command exists for completed/failed scans and expired sessions.
- [x] Production startup checks require PostgreSQL, secure cookies, and the live judge API key.
- [x] ISO standards gap assessment written in `docs/iso-readiness.md`.
- [x] 12 unit tests pass on Python 3.8.10 and Python 3.12.10.
- [x] Python 3.12.10 local virtual environment passes all 12 unit tests and `pip check`.
- [x] Local demo responds at `http://127.0.0.1:8000`.
- [ ] GitHub Actions workflow targeting Python 3.12 has not yet run.
- [ ] Not ready for public production deployment or ISO certification.

## Phase 1 — Before an invite-only pilot

### Runtime and release process

- [ ] Install/use a supported Python runtime (the available Python 3.8 is end-of-life).
- [ ] Run the test suite on Python 3.12 and confirm the GitHub Actions workflow passes.
- [ ] Review and update pinned dependencies; add automated vulnerability/dependency update checks.
- [ ] Add reviewed database migrations; stop relying on automatic table creation for production.
- [ ] Add a release process with code review, separate staging/production configuration, and rollback steps.

### Service and data security

- [ ] Select the hosting provider, data region, database, subprocessors, and deployment architecture.
- [ ] Deploy only to a private staging environment behind HTTPS; verify secure cookies, TLS, backups, and monitoring.
- [ ] Add email verification, account recovery, authentication throttling, and operational access reviews.
- [ ] Replace in-process scan execution with a durable, isolated job queue, with deadlines, cancellation, per-account/global quotas, and recovery after restart.
- [ ] Add API/edge rate limits, abuse alerts, scan cost limits, and an operator emergency stop.
- [ ] Define and publish what scan prompts, target credentials, replies, questionnaire answers, and reports are sent to/stored by each provider.
- [ ] Decide a retention period with customers and qualified privacy advice. Schedule the retention command using the approved period; include backups and logs in the retention policy.
- [ ] Test account deletion, scan deletion, backup recovery, log redaction, tenant isolation, and secret handling.
- [ ] Review target egress restrictions and prove that the scanner cannot reach internal services or follow target-controlled redirects.
- [ ] Add written rules of engagement for each customer: authorization, exact endpoint/path scope, permitted tests, request budget, time window, contact, and stop procedure. Domain ownership alone is not test authorization.

### Privacy, legal, and customer operations

- [ ] Choose the first customer markets and map applicable privacy/security laws with qualified counsel; “global” is not a single legal regime.
- [ ] Establish controller/processor roles, privacy notice, terms, customer data-processing terms, subprocessor list, transfer mechanisms where applicable, deletion process, and incident contact.
- [ ] Define support, complaints, customer notification, security incident response, and vulnerability reporting procedures.
- [ ] Obtain written customer approval before each live scan; keep live testing disabled until scope and authorization are recorded.

### Scanner quality

- [ ] Version the attack library, judge prompt, model/provider, and report format.
- [ ] Compare findings with expert manual reviews; track false positives, missed findings, disagreement, repeatability, and scan cost.
- [ ] Keep heuristic judging limited to the offline demo; clearly mark demo output and uncertain results.
- [ ] Add human review for uncertain/high-impact findings and make framework/legal mappings explicitly advisory.

## Phase 2 — Pilot acceptance

- [ ] Run 2–3 supervised pilots with organizations that own the targets or have provided explicit written permission.
- [ ] Review data handling and every report with the customer; redact sensitive evidence where possible.
- [ ] Record findings confirmed/rejected by reviewers, false positives, missed findings, time to useful remediation, and repeat usage.
- [ ] Fix critical security and accuracy issues before expanding the pilot.
- [ ] Obtain a customer-approved retention and deletion schedule before storing their scan data.

## Phase 3 — Public launch and certification readiness

- [ ] Complete an independent application/cloud security assessment and address material findings.
- [ ] Demonstrate production monitoring, incident response, recovery, change management, supplier reviews, access reviews, and secure releases.
- [ ] Operate a scoped ISO/IEC 27001 information security management system and ISO/IEC 42001 AI management system, including risk/impact assessment, assigned owners, documented processes, evidence, audits, management reviews, and corrective actions.
- [ ] Add ISO/IEC 27701, 27017, and/or 27018 work only when the company's privacy role and cloud-processing scope make them applicable.
- [ ] Engage an accredited certification body if formal certification is desired; do not claim certification before it is granted.
- [ ] Expand to a new legal jurisdiction only after its privacy, transfer, consumer, and security obligations have been reviewed.

## Resume here

1. Push the reviewed project files and verify the GitHub Actions Python 3.12 workflow passes.
2. Update dependency pins if CI or vulnerability checks require it.
3. Implement versioned database migrations and a durable scan worker before inviting external pilot users.

## Local demo server

The local Uvicorn server at `http://127.0.0.1:8000` is running for this demo. It is reachable only from this computer, is not a customer deployment, and does not run scans unless someone starts one in the UI. Stop it with `Ctrl+C` in its server terminal or ask the assistant to stop it.
