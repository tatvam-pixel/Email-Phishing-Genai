# PhishGuard AI: agent rules

Project: CIA-P Gen AI app (phishing and suspicious URL detector). Source of truth: docs/design.md and db/schema.sql (enums, scoring, contracts). Steps: docs/STEPS.md.

## Precedence
docs/design.md > docs/STEPS.md > docs/cia-p-brief.md. If they conflict, follow the higher one and mention the conflict in your reply.
- Do NOT read docs/cia-p-brief.md in full. Read only section 2 (mandatory requirements) when a step needs it.
- The brief's "first task: audit, no coding yet" is already done (design.md and schema.sql are the audit). Skip it.
- Ignore the brief's phase plan (section 14) and report format. Use the steps and the workflow below.
- API keys travel in the X-API-Key header (design.md section 3), not Authorization: Bearer. Bearer is for dashboard JWTs only.
- Do not read anything under docs/archive/.

Stack: Python 3.11, Flask via APIFlask, SQLAlchemy 2 Core + psycopg, pytest. Postgres on Supabase. React + Vite + Tailwind. google-genai. Vercel serverless (no background threads, no local storage, no shared in-memory state).

## Workflow (every session)
1. Do ONLY the step ID I name in docs/STEPS.md.
2. Read only the files that step names or needs. Do not scan the whole repo.
3. Plan in 8 bullets or fewer (files to change, new dependencies). Wait for my approval.
4. Implement with tests. Run pytest.
5. Tick the step in docs/STEPS.md.
6. Final reply in 8 lines or fewer: files changed, test result, what was not done, decisions I did not specify.
Do not paste code or long explanations into chat.

## Rules
1. design.md and schema.sql are law. On a conflict or gap, STOP and report. Never edit them silently.
2. Never store, log or print raw API keys, webhook secrets, passwords or env values. Never read .env. API keys are stored as SHA-256 hashes; webhook secrets are stored encrypted.
3. Gemini only explains backend evidence. It never sets score, confidence or classification.
4. Accessibility failures (403, 429, CAPTCHA, timeout) add no risk points. A threat-database no-match never means safe.
5. Every outbound call has a timeout. User-supplied destinations pass ssrf.validate_outbound_url. No redirects. Never fetch the URL being scanned.
6. Errors use the design.md section 3 shape and section 7 status codes.
7. A new dependency must be named in the plan. Pin versions.
8. Tests: no real network (mock HTTP), use TEST_DATABASE_URL, refuse to run against DATABASE_URL.
9. No refactors outside the current step.
10. Ask before destructive operations: dropping tables, deleting data, replacing migrations, force-pushing.
