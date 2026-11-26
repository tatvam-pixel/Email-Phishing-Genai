# PhishGuard AI: agent rules

Project: CIA-P Gen AI app (phishing and suspicious URL detector), 3-day LITE scope. Steps: docs/STEPS_LITE.md. Contracts and schema: docs/design.md and db/schema.sql.

## Precedence
The "Deviations" and "Lite scoring policy" sections of docs/STEPS_LITE.md > docs/design.md > docs/cia-p-brief.md. On a conflict, follow the higher one and mention it in your reply.
- Do NOT read docs/cia-p-brief.md, docs/STEPS_FULL.md or docs/archive/. Never build anything listed under "Backlog".
- Read design.md only the sections a step names (for example section 3 errors, section 5 Gemini, section 6 webhooks, section 7 status codes).
- API keys travel in the X-API-Key header, not Authorization: Bearer.

Stack: Python 3.13 locally (deploys on 3.13), Flask via APIFlask, SQLAlchemy 2 Core + psycopg, pytest. Postgres on Supabase. google-genai. Vercel serverless (no background threads, no local storage, no shared in-memory state).

## Workflow (every session)
1. Do ONLY the step ID I name in docs/STEPS_LITE.md.
2. Read only the files that step names or needs. Do not scan the whole repo.
3. Plan in 8 bullets or fewer (files to change, new dependencies). Wait for my approval.
4. Implement with tests. Run pytest.
5. Tick the step in docs/STEPS_LITE.md.
6. Final reply in 8 lines or fewer: files changed, test result, what was not done, decisions I did not specify.
Do not paste code or long explanations into chat.

## Rules
1. db/schema.sql is never edited. Schema changes go in db/migrations/NNN_*.sql only when a step says so. On any other conflict or gap, STOP and report.
2. Never store, log or print raw API keys, webhook secrets, passwords, connection strings or env values. Never read .env. API keys are stored as SHA-256 hashes; webhook secrets are stored encrypted.
3. Gemini only explains backend evidence. It never sets score, confidence or classification.
4. A threat-database no-match never means safe. low_risk is shown as "No strong indicators found".
5. Every outbound call has a timeout. User-supplied destinations pass ssrf.validate_outbound_url. No redirects. Never fetch the URL being scanned.
6. Errors use the design.md section 3 shape and section 7 status codes.
7. A new dependency must be named in the plan. Pin versions to what you installed and tested. Runtime packages only in requirements.txt.
8. Tests: no real network (mock HTTP), use TEST_DATABASE_URL, refuse to run against DATABASE_URL. All SQL parameterized.
9. No refactors outside the current step.
10. Ask before destructive operations: dropping tables, deleting data, replacing migrations, force-pushing.
