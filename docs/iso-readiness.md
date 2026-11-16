# ISO alignment and readiness assessment

**Status:** working gap assessment for the current prototype, prepared 2026-11-15. It is not a conformity assessment, legal opinion, or certification.

ISO management-system standards apply to an organization's defined scope, people, processes, suppliers, evidence, and continual-improvement system—not just source code. This document records product controls and the separate organizational work still required. Obtain the applicable standards from ISO and have a qualified auditor or adviser confirm any formal scope or interpretation.

## Applicable standards

| Standard | Relevance to this service |
| --- | --- |
| [ISO/IEC 27001:2022](https://www.iso.org/standard/27001) | Primary information security management system (ISMS) framework for the organization operating the scanner. |
| [ISO/IEC 42001:2023](https://www.iso.org/standard/42001) | AI management system for the responsible provision and use of the scanner's AI-enabled service, including its judge. |
| [ISO/IEC 27701:2025](https://www.iso.org/standard/27701) | Privacy information management when the company acts as a PII controller or processor. It does not replace jurisdiction-specific privacy-law analysis. |
| [ISO/IEC 27017:2026](https://www.iso.org/standard/27017) | Cloud-specific security guidance and shared responsibilities for the hosted service and its cloud providers. |
| [ISO/IEC 27018:2025](https://www.iso.org/standard/27018) | Public-cloud PII-processing controls when the service provider processes personal information on behalf of customers. |

These are complementary, not a requirement to certify to every standard. The appropriate scope depends on the company's role, hosting model, data, contracts, and markets. ISO catalog status and edition should be rechecked before a formal audit.

## Product control snapshot

Status definitions: **Partial** means a feature exists but does not demonstrate an effective, operated control. **Gap** means a needed control is not implemented or evidenced. **Implemented** is limited to the specific behavior tested; it does not imply certification.

| Area | Current evidence | Status / next action |
| --- | --- | --- |
| Account authentication | Passwords use scrypt; server stores hashes of random session tokens; 12-hour sessions are HttpOnly, SameSite=Strict cookies; browser JavaScript no longer receives or stores the token. | Partial: add verified account recovery, authentication throttling, session security review, and access review procedures. |
| Tenant isolation | Targets and scans are queried by owner; tests cover cross-account scan access. | Partial: test every object/API route and operational access path; document review evidence. |
| Target authorization | HTTPS/public-address validation, DNS or hosted-file challenge, pinned target address, and redirect rejection exist. | Partial: domain control alone does not prove permission for every endpoint. Require documented scope, purpose, rate, window, and contact before a real scan; review outbound network controls. |
| Browser security | Same-origin UI, CSP, common response headers, and secure cookies in staging/production configuration exist. | Partial: deploy behind HTTPS, configure trusted proxy/HSTS, independently review browser/session protections, and test the production configuration. |
| Scan execution | A single in-process background task runs each account's scan. | Gap: use a durable, isolated worker/queue with timeouts, concurrency budgets, cancellation, and recovery. |
| Data handling | Raw chatbot replies and questionnaire answers are stored in the database; target API keys are passed to the running job but not saved in scan records. Users can delete their account and active scan/target records; active scans block deletion. A maintenance command can purge expired completed/failed scans and expired sessions. | Partial: publish an accurate data-flow/subprocessor notice, minimize stored content, choose and schedule an approved retention period, cover backups/logs, restrict staff access, and review encryption. |
| Database lifecycle | SQLite is the local default; SQLAlchemy creates tables at application startup. PostgreSQL URL support exists. | Gap: production database, versioned migrations, access controls, backup/restore drills, and separate environments are required. |
| Abuse and availability controls | Target-count and one-running-scan-per-account limits exist. | Gap: edge/API rate limits, account and global quotas, abuse monitoring, provider spend limits, and alerting. |
| AI evaluation | A 20-test library, optional Anthropic judge, heuristic demo mode, and report disclaimer exist. | Partial: version prompts/models, measure judge accuracy and false results against human review, preserve test provenance, define human escalation, and monitor model/provider changes. Never use heuristic results for customer decisions. |
| Audit and incident response | Application logging exists. | Gap: define access-controlled audit events, log retention, secret/PII redaction, incident ownership, response exercises, and customer notification procedures. |
| Secure development | Python unit tests cover selected pilot flows. | Gap: current local runtime is Python 3.8 (end-of-life); validate on a supported runtime, add dependency/vulnerability updates, code review, release controls, security testing, and evidence retention. |
| Organization-wide ISMS/AIMS | No operational management-system evidence is part of this codebase. | Gap: assign accountable owners; define scope, risk/impact assessments, policies, suppliers, competence, objectives, internal audits, management reviews, corrective actions, and continual improvement. |

## Release gates

### Before an invite-only customer pilot

- [ ] Select the service and data-processing scope, hosting provider/region, subprocessors, and customer roles.
- [ ] Have written rules of engagement for each target: owner, exact endpoints, allowed tests, request budget, time window, emergency contact, and stop procedure.
- [ ] Use and test on a supported Python runtime. The current development environment is Python 3.8, which is end-of-life; do not deploy it. See the [Python version status](https://devguide.python.org/versions/).
- [ ] Replace the local SQLite database with a managed, access-controlled database; establish migrations, backup, restore, and a tested recovery process.
- [ ] Add verified account recovery and authentication throttling; independently review browser sessions and CSRF protections.
- [ ] Add a durable worker queue, scan timeouts, quotas, isolation, and an operator kill switch.
- [ ] Approve and schedule a retention period for completed scan data; configure corresponding backup and log retention. The maintenance command exists but is not scheduled automatically.
- [ ] Define self-service deletion for accounts, targets, scans, reports, logs, and backups; active application records can be deleted, but backups/logs need an operational policy.
- [ ] Keep live scanning disabled until a server-side judge key is configured; protect secrets with the host's secret manager and set provider spend limits.
- [ ] Review target isolation/egress, permissions, logs, raw-result handling, and privacy notices with a security professional.
- [ ] Run access-control, authorization, privacy, dependency, and backup-recovery tests; document unresolved risks and obtain accountable approval to pilot.
- [ ] Provide pilot terms, privacy notice, data-processing terms where applicable, subprocessors, support/escalation contact, and incident-notification process, reviewed for the pilot markets.

### Before public launch or certification audit

- [ ] Operate a formal, scoped ISMS and AIMS; maintain risk registers, risk treatment, applicable control selection/Statement of Applicability where required, objectives, owners, evidence, internal audits, management reviews, and corrective actions.
- [ ] Establish a privacy information management process: data inventory, purposes/roles, lawful basis where applicable, user requests, international transfers, subprocessors, retention, deletion, and breach processes.
- [ ] Complete an independent application/cloud security assessment and remediate material findings.
- [ ] Demonstrate production monitoring, incident response, disaster recovery, change management, supplier review, access recertification, and secure software release over time.
- [ ] Obtain jurisdiction-specific legal advice for each market. “Global” is not one privacy-law regime; legal obligations depend on where the company and users are, what data is handled, and the service's role.
- [ ] Engage an accredited certification body if the company decides to seek certification. Do not advertise ISO certification or compliance based solely on this app or checklist.

## AI governance evidence to build

- Maintain an inventory of AI components (including the judge), owners, model/provider/version, intended use, data sent, retention, and fallback behavior.
- Assess risks and impacts for customers and affected people; document mitigations, residual risk acceptance, human review, and prohibited uses.
- Version and evaluate attack tests, grading instructions, model settings, and reports. Track reproducibility, judge disagreements, false positives/negatives, and changes to providers.
- Make AI use and limitations clear to operators; preserve human review for uncertain or high-impact findings.
- Track AI-related incidents, provider changes, complaints, and corrective actions.

This list is a practical backlog, not a complete clause-by-clause interpretation of any paid ISO standard.
