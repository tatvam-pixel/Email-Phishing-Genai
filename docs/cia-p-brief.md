# CIA-P Brief — PhishGuard AI
## Implementation requirements for Antigravity

**Course:** BTIN337 — Gen AI Applications (CIA-P)  
**Project:** PhishGuard AI — Phishing and Suspicious URL Detection Assistant  
**Purpose:** This document is the implementation brief. Antigravity must inspect the existing repository and supplied SQL schema before changing code.

---

## 1. Product objective

Build a functional security application that analyses suspicious URLs and potentially malicious messages, presents evidence-based risk assessments, explains findings, and recommends safe next steps.

This is **not a generic Gemini chatbot**. Detection must use deterministic rules, an ML classifier, and threat-intelligence signals where available. Gemini is an explanation layer. The backend owns evidence aggregation, scoring, and final classification.

## 2. Mandatory CIA-P requirements

All are release requirements:

1. A working application, not merely a UI prototype.
2. Deployment on Vercel or another faculty-approved free hosting platform. The Flask backend may be deployed separately.
3. Direct Gemini or Grok API integration. Planned provider: Gemini. Calls must originate from the backend.
4. REST API endpoints usable by external applications.
5. Webhooks with valid JSON payloads and appropriate HTTP status handling.
6. Structured API-key authentication and authorization, including scopes and rate limits.
7. API documentation covering endpoints, authentication, request/response examples, status codes, and webhooks.
8. Modular implementation that can be reviewed and iteratively updated after faculty feedback.

Do not mark a requirement complete because a screen or button exists. Verify its end-to-end behavior.

## 3. Scope

### Required user features

**URL scanning**
- Accept one URL, validate it, and normalize it.
- Extract URL/domain features and run explainable rules.
- Run the ML classifier when available.
- Query configured threat-intelligence services when credentials/quota permit.
- Return classification, score where justified, evidence, explanation, recommendations, and limitations.

**Message scanning**
- Accept pasted email, SMS, or chat text.
- Detect message-level indicators: urgency, account-suspension threats, password/OTP requests, financial impersonation, and suspicious links.
- Extract and analyse URLs through the URL pipeline.
- Show message-level evidence separately from URL-level evidence.
- Do not claim sender or SPF/DKIM/DMARC verification unless the relevant headers were supplied and actually checked.

**Results and history**
- Show classification, risk score (if available), confidence (if available), evidence, explanation, limitations, and recommendations.
- Authenticated users can view only their own history.
- Apply explicit guest-scan limits and retention.

**Developer capabilities**
- User authentication using one chosen auth approach.
- Create, list, and revoke API keys.
- Show raw API key only once; store only its hash.
- Register HTTPS webhook endpoints and select subscribed events.
- Show delivery status and useful usage information.
- Publish API documentation with working examples.

### Out of scope for the first release

Do not build browser extensions, mobile apps, inbox monitoring, broad crawlers, malware download/execution, automatic remediation, complex enterprise analytics, or multiple LLM providers. Do not automatically visit arbitrary submitted URLs without a hardened inspection design.

## 4. Recommended stack

| Layer | Technology |
|---|---|
| Frontend | React + Vite |
| Styling | Tailwind CSS |
| Backend | Python + Flask |
| Database | PostgreSQL via Supabase |
| ML | Scikit-learn |
| GenAI | Gemini API |
| Threat intelligence | Google Safe Browsing; VirusTotal optional |
| Frontend hosting | Vercel |
| Backend hosting | Free Python-compatible host approved by faculty |
| API | REST, versioned under `/api/v1` |

Adapt to the existing repository if it already has a working, justified alternative. Keep credentials in environment variables/deployment secrets.

## 5. Detection pipeline

Implement this sequence:

1. **Validate input:** For URL scans, permit only `http` and `https`; reject malformed URLs and unsupported schemes.
2. **Parse and normalize:** Extract hostname, path, query, subdomains, registered domain, and encoding safely.
3. **Rule analysis:** Consider IP-address hosts, unusual URL/hostname length, excessive subdomains, misleading `@` usage, encoded characters, suspicious separators, shorteners, typosquatting, and brand impersonation.
4. **ML analysis:** Use a reproducible feature pipeline. Record model version and probability.
5. **Threat intelligence:** Query Google Safe Browsing; VirusTotal is optional. Handle quota, timeout, and provider errors distinctly from a clean result.
6. **Evidence aggregation:** Use a documented, versioned backend scoring policy.
7. **Gemini explanation:** Give Gemini structured evidence and request a strict JSON explanation, evidence-linked reasons, limitations, and recommendations.
8. **Validate AI output:** Reject unsupported claims and nonexistent evidence references. Fall back to a deterministic explanation if Gemini fails.
9. **Persist and respond:** Store scan/evidence and return a stable API response.

### Classifications

Use exactly:
- `low_risk`
- `suspicious`
- `high_risk`
- `inconclusive`

Risk score range: 0–100. If classification is `inconclusive`, `risk_score` must be `null`.

Never make these assumptions:
- HTTPS means safe.
- HTTP means phishing.
- An inaccessible, blocked, rate-limited, or login-protected site is malicious.
- No threat-intelligence match proves safety.
- A confident LLM statement is evidence.
- A failed reputation lookup is a clean result.

Keep accessibility status separate from security classification. URL detection must still work without live website access.

## 6. URL inspection and SSRF security

All submitted URLs and webhook destinations are untrusted.

- Do not fetch arbitrary URLs from the backend without a deliberately designed isolated inspection service.
- Block loopback, private, link-local, multicast, reserved, and internal IP ranges.
- Resolve and validate DNS; defend against DNS rebinding.
- Revalidate every redirect destination and cap redirect count.
- Reject unsupported schemes, embedded credentials, malformed hosts, and disallowed ports.
- Use strict timeouts, response-size limits, content-type restrictions, and network egress controls.
- Never download or execute suspicious content.
- Apply equivalent protections to webhook registration and delivery.
- An `https://` prefix check alone is not sufficient validation.

If safe live inspection is not implemented, perform static URL analysis and clearly state that the site was not visited.

## 7. Gemini requirements

- Call Gemini from Flask only. Never call it directly from browser code.
- Keep the API key in backend environment variables.
- Send structured evidence; treat user-supplied text as untrusted data and defend against prompt injection.
- Require JSON output matching a defined schema.
- Each reason must cite valid evidence IDs such as `E1` and `E2`.
- Filter claims that cite nonexistent evidence or invent reputation checks, domain ownership, email authentication, malware findings, or browsing observations.
- Handle timeouts, quotas, rate limits, malformed output, and provider errors.
- The scanner must remain useful if Gemini is unavailable.
- Record model name, validation status, latency, and fallback status.

The backend — not Gemini — determines score and classification.

## 8. Database schema reference

The supplied PostgreSQL schema v1 defines ten tables. Inspect the actual SQL before modifying it:

1. `users` — identity and password hash.
2. `api_keys` — key prefix/hash, scopes, limits, expiry, revocation, last use.
3. `scans` — input metadata, status/stage, classification, score, confidence, accessibility, retention.
4. `scan_urls` — URL records, including extracted URLs from message scans.
5. `scan_evidence` — findings with stable per-scan references such as `E1`.
6. `ai_analyses` — Gemini explanation, reasons, recommendations, limitations, validation metadata.
7. `api_usage_logs` — request metadata and performance.
8. `rate_limit_counters` — fixed-window counters.
9. `webhooks` — HTTPS destinations, encrypted signing secret, subscribed events.
10. `webhook_deliveries` — payload, attempts, status, and retry schedule.

### Database rules

- Do not silently redesign or replace the supplied schema. Audit it first and explain every proposed change.
- Use migrations for changes; do not repeatedly run ad hoc production SQL.
- Keep RLS enabled. If Flask uses a Supabase service-role key or privileged DB role, it must stay server-side and never reach the browser.
- Decide between Supabase Auth and custom Flask auth. If using Supabase Auth, avoid accidentally maintaining a second independent password system in `users.password_hash`.
- Generate scan IDs and API keys using a cryptographically secure random generator.
- Store only API-key hashes; display the raw key only once.
- HMAC webhook signing requires access to the original secret at signing time. Encrypt it at rest; keep the encryption key outside the database.
- Retention must cover sensitive copies such as `scans.input_text`, `scan_urls.url`, normalized URLs, message content, logs, and webhook payloads as appropriate.
- Set explicit guest expiry and implement actual scheduled cleanup. SQL comments alone do not implement retention.
- Add indexes for real query patterns and foreign-key cleanup paths where needed.

## 9. REST API

Use `/api/v1` for application routes. Suggested initial endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/v1/auth/register` | Register, if custom auth is chosen |
| POST | `/api/v1/auth/login` | Login, if custom auth is chosen |
| POST | `/api/v1/scan/url` | Submit URL scan |
| POST | `/api/v1/scan/message` | Submit message scan |
| GET | `/api/v1/scan/{scan_id}` | Retrieve scan |
| GET | `/api/v1/history` | Current user's history |
| DELETE | `/api/v1/history/{scan_id}` | Delete owned scan, if supported |
| POST | `/api/v1/api-keys` | Create key |
| GET | `/api/v1/api-keys` | List keys without raw secrets |
| DELETE | `/api/v1/api-keys/{key_id}` | Revoke owned key |
| POST | `/api/v1/webhooks` | Register webhook |
| GET | `/api/v1/webhooks` | List webhooks |
| DELETE | `/api/v1/webhooks/{webhook_id}` | Disable/delete webhook |
| GET | `/api/v1/usage` | Usage information, if implemented |
| GET | `/api/v1/health` | Health check |

The final API must support URL scanning, message scanning, result retrieval, API-key management, and webhook management.

### Authentication and authorization

- Browser users use a secure session or the selected auth provider.
- External clients use API keys, e.g. `Authorization: Bearer <API_KEY>`.
- Validate hash, expiry, revocation, scope, and ownership.
- Enforce ownership on every scan/history/key/webhook request.
- Enforce per-key and guest rate limits.
- Never return raw keys after creation or put secrets in URLs/logs/errors.

### HTTP status codes

Use consistently:
- `200` successful retrieval/operation.
- `201` resource created.
- `202` asynchronous scan accepted.
- `400` malformed request.
- `401` missing/invalid authentication.
- `403` insufficient permission/scope.
- `404` missing or non-visible resource.
- `409` state conflict.
- `422` valid JSON but invalid field values/input.
- `429` rate limit exceeded.
- `500` unexpected server error.
- `503` required dependency temporarily unavailable.

Return consistent JSON error objects with a machine-readable code and safe message. Never expose stack traces or secrets.

### Scan response contract

At minimum return:
- `scan_id`, `input_type`, `status`
- `classification`, `risk_score` (nullable), `confidence` (nullable)
- `accessibility_status`
- `evidence` with stable evidence references
- `ai_analysis` or explicit fallback
- `limitations`
- `created_at` and `completed_at` when applicable

For async work, return `202` with a scan ID and retrieval path. Do not claim completion prematurely.

## 10. Webhooks

Support:
- `scan.completed`
- `scan.failed`
- `api_key.revoked`

Requirements:
- HTTPS destinations only, with SSRF-safe validation.
- User-selectable event subscriptions.
- Unique event ID and JSON payload containing event ID, type, creation time, and relevant resource data.
- HMAC-SHA256 signature and documented verification procedure.
- Bounded connect/read timeouts.
- Persist attempts and response status.
- Retry transient failures with bounded exponential backoff; abandon after a configured maximum.
- Make deliveries idempotent using event ID.
- Do not include secrets or unnecessary raw message content.
- Create event/delivery records transactionally (outbox pattern) so crashes do not silently lose events.
- Deliver in a background worker; do not keep the scan request waiting for webhook delivery.

## 11. Frontend requirements

Suggested visual direction: responsive dark navy/charcoal interface, blue primary actions, red high-risk, amber suspicious/inconclusive, green low-risk, accessible contrast.

Required screens:
1. Landing/home and URL scanner.
2. URL scan loading/progress and report.
3. Message scanner and report.
4. Login/register, if accounts are used.
5. User dashboard and scan history.
6. Developer dashboard.
7. API-key management.
8. Webhook configuration and delivery status.
9. API documentation.

Show evidence and limitations, not only a large score. Distinguish inconclusive from low risk. Do not use fake metrics or nonfunctional buttons. Display provider failures clearly.

## 12. Security, privacy, and quality

- Passwords: Argon2id or bcrypt if custom password storage is retained.
- API keys: secure random generation and one-way hash storage.
- Webhook secrets: authenticated encryption at rest; encryption key outside DB.
- Secrets: environment variables/deployment secret store; never commit `.env`.
- CORS: restrict to deployed frontend origin.
- Validate and size-limit inputs; use parameterized DB access.
- Enforce authentication, authorization, ownership, scopes, and rate limits server-side.
- Protect against SSRF, DNS rebinding, unsafe redirects, and webhook abuse.
- Do not log passwords, keys, webhook secrets, or unnecessary raw message bodies.
- Sanitize/truncate provider error details.
- Apply a documented retention/deletion policy.
- Use production-safe error handling and secure headers.
- Test rules, parsing, scoring, schemas, authentication, ownership, scan flow, and webhook lifecycle.
- Evaluate ML with precision, recall, F1, confusion matrix, and false-positive rate. Accuracy alone is inadequate.
- Store model and scoring-policy versions.
- Document local setup, environment variables, tests, deployment, and demo steps.

## 13. Suggested repository structure

Adapt to the existing repository; do not create duplicate roots.

```text
phishguard-ai/
├── frontend/
│   └── src/{components,pages,services,hooks,context}/
├── backend/
│   ├── app/{routes,services,models,ml,middleware,utils}/
│   ├── tests/
│   ├── migrations/
│   ├── config.py
│   ├── requirements.txt
│   └── run.py
├── docs/{architecture,api,webhook,security}.md
├── .env.example
└── README.md
```

## 14. Phased implementation plan

**Phase 0 — Audit**
- Inspect repository, SQL, README, and design documents.
- Identify existing features and gaps.
- Audit schema/security and deployment constraints.
- Produce a plan before editing.
- Exit: written audit, no destructive changes.

**Phase 1 — Flask foundation and deterministic URL scanner**
- App structure, configuration, health endpoint, validation, safe parsing, rules, evidence, scoring, tests.
- Exit: URL scan works without Gemini, DB, or threat-intelligence availability.

**Phase 2 — Database**
- PostgreSQL integration, migrations, persistence, scan retrieval, guest retention, correct RLS.
- Exit: scans persist and ownership is enforced.

**Phase 3 — ML and threat intelligence**
- Reproducible features/model, evaluation, provider integration, timeout/quota/error handling.
- Exit: signals are independently testable; provider failure never becomes a safe verdict.

**Phase 4 — Gemini and message scanning**
- Strict JSON schema, evidence-reference validation, fallback, message indicators, extracted URL analysis.
- Exit: useful results remain available when Gemini is down.

**Phase 5 — Authentication, API keys, history**
- Chosen auth system, history, key lifecycle, scopes, expiry, ownership, rate limits.
- Exit: revoked/expired/under-scoped keys are rejected.

**Phase 6 — Webhooks and API documentation**
- Registration, SSRF validation, signing, outbox, retries, delivery status, API/webhook docs.
- Exit: a test consumer receives and verifies a signed event and retry behavior is testable.

**Phase 7 — Frontend, deployment, final verification**
- Complete real UI flows, production configuration, deploy frontend/backend, smoke tests, README, demo checklist.
- Exit: reviewer can scan URL/message, authenticate, call API, configure webhook, and read docs.

## 15. Acceptance checklist

- [ ] URL scan returns a structured result.
- [ ] Message scan returns message findings and extracted URL findings.
- [ ] Inconclusive result has `risk_score: null`.
- [ ] Inaccessible/blocked sites are not automatically called phishing.
- [ ] Gemini outage does not break scanning.
- [ ] Gemini reasons cite real evidence IDs only.
- [ ] ML evaluation includes precision, recall, F1, confusion matrix, and false-positive rate.
- [ ] Scan persistence and ownership checks work.
- [ ] API-key creation, validation, scopes, and revocation work.
- [ ] Guest and API-key rate limits work.
- [ ] External clients can call documented scan endpoints.
- [ ] Webhook JSON is signed and verifiable.
- [ ] Webhook retries and delivery status work.
- [ ] Webhook destination validation prevents SSRF.
- [ ] API docs include authentication, schemas, examples, and status codes.
- [ ] No secrets are present in frontend bundles or Git.
- [ ] Frontend and backend are deployed and tested.
- [ ] Tests pass; README explains setup and demonstration.

## 16. Instructions to Antigravity

1. Inspect before editing. Read the repository, supplied SQL, README, and design docs.
2. Do not assume the repository is empty. Preserve working code.
3. Do not rewrite everything. Make small, reviewable changes.
4. Do not invent credentials, datasets, model metrics, test results, or deployment success.
5. Do not use mock data in production paths.
6. Never expose Gemini, Supabase service-role, database, or webhook secrets to the frontend.
7. Do not disable RLS, SSRF protection, authentication, ownership checks, or signature verification as a demo shortcut.
8. Gemini must never own the final score/classification.
9. Do not claim safety based only on HTTPS, accessibility, or absence of a reputation match.
10. Add tests with each backend feature.
11. Keep README, API docs, `.env.example`, and implementation synchronized.
12. After each phase, report files changed, behavior added, commands run, actual test results, limitations, security concerns, and next task.
13. Stop at phase boundaries for review. Do not move forward if exit criteria fail.
14. Ask before destructive operations: dropping tables, deleting data, replacing migrations, or force-pushing Git history.

### Antigravity's first task — no coding yet

Return an audit containing:
- Existing repository structure and stack.
- Existing features versus missing CIA-P requirements.
- Review of the supplied SQL schema with concrete issues and proposed migration changes.
- Security risks: SSRF, RLS, secrets, API-key handling, webhook delivery, retention.
- A phased plan mapped to the acceptance checklist.
- Decisions/blockers requiring user input.

Do not begin implementation until this audit is complete.

## 17. Decisions to confirm, not guess

- Supabase Auth or custom Flask auth.
- Faculty-approved free backend host.
- Whether an ML dataset/model already exists.
- Justified thresholds for the three scored classifications.
- Guest scan limits and retention period.
- Whether live URL inspection is in scope; if yes, design isolated SSRF-safe inspection first.
- Whether VirusTotal is needed in addition to Google Safe Browsing.
- Synchronous versus background scan processing.
- Final API schemas and webhook signature header format.

Defer decisions that do not block the current phase. Do not let optional features delay the deterministic URL scanner and core CIA-P requirements.
