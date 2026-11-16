# AI Risk Scanner pilot

A local web pilot for testing AI chatbots you own or are explicitly authorized to assess. It includes account sign-in, target ownership proof, a short policy questionnaire, scans, and downloadable PDF reports.

## Run locally

Use Python 3.12, matching the GitHub Actions test workflow. Create a local virtual environment from the tracked requirements; the environment and local data are intentionally excluded from Git.

```powershell
cd "C:\AI Security\Project"
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
uvicorn api:app --reload
```

Open <http://127.0.0.1:8000>. Create an account and run **Run offline demo** to try the workflow without API keys or contacting an external target.

For live scans, set the judge key in the server's environment before starting Uvicorn:

```powershell
$env:ANTHROPIC_API_KEY = "your API key"
uvicorn api:app --reload
```

Live scans send target replies to Anthropic for grading. If the chatbot requires authentication, enter its API key in the scan form; the pilot uses it only in memory for that scan and does not save it.

For production configuration, set `APP_ENV=production`, use PostgreSQL, and provide `ANTHROPIC_API_KEY`. The app refuses production startup with SQLite, without secure cookies, or without the live-judge key. These checks are only basic safeguards, not production approval. Serve behind HTTPS, and do not use `--reload` in production.

## Verify a target

Add an HTTPS chat-completions endpoint. The pilot rejects IP-literal and non-public targets, and verifies control of the endpoint's exact DNS hostname before a live scan:

- **DNS:** publish the displayed TXT value at `_ai-risk-scanner.<hostname>`.
- **File:** host the displayed value at `https://<hostname>/.well-known/ai-risk-scanner-verification.txt`.

The scanner re-resolves and pins a public IP for each request and does not follow redirects. Verification is required before scanning. Only test systems you own or have written permission to test.

## Database

By default, the pilot uses a local SQLite database (`ai_risk_scanner.db`, ignored by Git). To use PostgreSQL, set `DATABASE_URL` before starting the API:

```powershell
$env:DATABASE_URL = "postgresql+psycopg://user:password@localhost:5432/ai_risk_scanner"
uvicorn api:app --reload
```

## Tests

```powershell
python -m unittest discover -s tests -v
```

The GitHub Actions workflow targets Python 3.12. The local test suite passes on Python 3.12.10; require a passing CI run before release.

## Data retention

The retention period is an operator/customer policy decision, not a universal ISO-mandated number. After approving a period for the deployment, schedule this command to run regularly against the production database:

```powershell
python maintenance.py purge-expired --retention-days 30
```

Replace `30` with the retention period approved for the applicable contract and jurisdictions. It removes completed/failed scans older than that period and expired login sessions; it does not purge active scans, target registrations, logs, or database backups.

## Existing CLI

The original command-line demo remains available:

```powershell
python scanner.py --authorized --demo
```

`attack_library_v0.1.json` contains 20 tests. Framework mappings are first-draft references, not legal advice. The heuristic judge is only suitable for the offline demo; it is not reliable enough for customer assessments.

## Pilot limitations

This is a local pilot, not a production SaaS. Browser sessions use HttpOnly cookies and users can delete active account data, but the service still has no email verification or recovery, database migrations, durable job queue, distributed rate limiting, or configured retention for backups and logs. Scans run in the API process and raw replies are stored in the database. Production startup requires PostgreSQL, secure cookies, and `ANTHROPIC_API_KEY`, but these checks alone do not make a deployment production-ready. Do not expose the app publicly until the open release gates in [docs/iso-readiness.md](./docs/iso-readiness.md) are closed.

## Standards readiness

See [docs/iso-readiness.md](./docs/iso-readiness.md) for the standards selected, current gaps, and launch gates. This is a working product assessment—not an ISO certification, legal opinion, or claim of compliance. ISO certification requires an organization-wide management system and an independent audit.

Use [LAUNCH_CHECKLIST.md](./LAUNCH_CHECKLIST.md) to track the remaining pilot and public-launch work when resuming later.
