# PhishGuard AI: implementation steps

Next step: **2.3**

Tags: [P] use Planning mode. [F] Fast mode is fine. [H] human step, not for the agent.
"design §x" means a section of docs/design.md. Tick `[x]` when a step is done and committed.

Run one step (or one bundle) per fresh conversation. Suggested bundles, to save overhead: 1.1-1.3, 2.1-2.2, 3.1-3.2, 3.3-3.4, 4.4-4.5, 5.1-5.2, 6.1-6.2, 7.1-7.3, 8.1-8.2, 8.3-8.4. Never more than two steps in one session.

---

## Phase 1: Skeleton

- [x] 1.1 [F] Scaffold: backend/app/__init__.py (create_app), config.py (env vars, fail fast unless ENV=test), requirements.txt (pinned), .env.example (names only), tests/conftest.py. Done: pytest runs.
- [x] 1.2 [P] Errors: errors.py with the design §3 error shape and §7 codes; handlers for 400/401/403/404/405/409/422/429 and unexpected errors (no stack traces); X-Request-Id on every response and error body. Done: tests for 404, 405, 500 shapes.
- [x] 1.3 [F] APIFlask app: GET /api/v1/health (status, version, time; no DB), /docs, /openapi.json, ApiKeyAuth scheme (header X-API-Key). Done: test passes, /docs loads locally.
- [x] 1.4 [P] Vercel files per Vercel's CURRENT Flask docs (look them up), vercel.json if required, README run steps. Done: [H] I deploy; live /api/v1/health returns 200.

## Phase 2: Data layer

- [x] 2.1 [P] db.py: SQLAlchemy engine for serverless (Supabase transaction pooler, no persistent pool, prepared statements off; verify in docs). scripts/migrate.py: schema_migrations table, applies db/schema.sql once as 000_baseline, then db/migrations/*.sql in order, idempotent. Done: runs twice cleanly on the test DB.
- [x] 2.2 [P] Test fixtures: connect to TEST_DATABASE_URL, apply migrations, truncate between tests; refuse if it is empty or equals DATABASE_URL. Done: test proving the refusal.
- [ ] 2.3 [P] repositories/: api_keys.py, rate_limits.py, usage_logs.py implemented; scans.py, webhooks.py, deliveries.py as typed stubs. Done: repository tests pass.

## Phase 3: Authentication

- [ ] 3.1 [P] security/api_keys.py: generate_key() returns raw key ("pg_live_" + token_urlsafe(24)), 12-char prefix, SHA-256 hex hash. Done: unit tests (format, uniqueness, hash stable).
- [ ] 3.2 [P] @require_api_key(scope) reading X-API-Key; missing/unknown/revoked/expired all return an identical 401; valid key without scope returns 403; updates last_used_at. Done: tests for each case.
- [ ] 3.3 [P] Rate limit per key via rate_limit_counters (INSERT ... ON CONFLICT pattern in schema.sql); 429 with Retry-After; X-RateLimit-Limit and X-RateLimit-Remaining headers. Done: test exceeding the limit.
- [ ] 3.4 [P] Usage logging for every /api/v1 request that carries a key (api_key_id null if invalid). Done: rows asserted in tests.
- [ ] 3.5 [P] Bootstrap: `flask create-user --email`; hidden admin routes guarded by X-Admin-Secret (constant-time compare): POST/GET/DELETE /api/v1/admin/api-keys (raw key returned once); GET /api/v1/me/key (scope scan:read). Done: tests incl. proof the raw key is in neither DB nor logs.

## Phase 4: Detection core (offline, pure)

- [ ] 4.1 [P] services/url_normalizer.py: only http/https, scheme required, max 2048 chars, lowercase host, strip fragment, handle trailing dot/port/userinfo; raise InvalidUrl for javascript:, file:, data:, ftp:, "not-a-url". Done: table-driven tests.
- [ ] 4.2 [F] backend/app/data/: brands.json (brand to official registered domains), popular_domains.txt (~200 well-known), shared_hosting_suffixes.txt, shorteners.txt, risky_tlds.txt, sensitive_tokens.txt. Done: files load in a test.
- [ ] 4.3 [P] services/url_features.py using tldextract with its bundled suffix list and NO network or cache writes (suffix_list_urls=()). Done: feature tests (IP host, subdomain depth, punycode, registered domain).
- [ ] 4.4 [P] services/rule_scorer.py rules U01-U07 from design §4.2, returning evidence items (indicator, severity, points, description, details). Severity: points >= 25 high, 10-24 medium, 1-9 low, <= 0 info. Done: tests per rule.
- [ ] 4.5 [P] Rules U08-U14 and N01. U04 and U05 must not fire for the real brand domain. Done: design §4.9 example A gives R=55, example B gives R=0; plus shortener, github.io, paypa1.com, uppercase, long URL.
- [ ] 4.6 [P] scoring/aggregator.py: PURE function for design §4.3-4.6. Done: tests for every branch, all three variants of example A, example B, TI match, boundaries 25, 40, 69, 70.

## Phase 5: Scan API

- [ ] 5.1 [P] repositories/scans.py: persist scans, scan_urls, scan_evidence in ONE transaction; public id "scn_" + token_urlsafe(16). Done: repository tests.
- [ ] 5.2 [P] services/scan_service.py: validate, extract, score, aggregate, assign evidence refs E1.., build limitations (page not inspected; TI not checked when applicable; no-match never means safe), score_policy_version "v1", accessibility_status "not_attempted". Done: service tests.
- [ ] 5.3 [P] POST /api/v1/scan/url (scope scan:write; body url, include_ai_analysis). Success response shape in design §6/§7 style: success, scan_id, status, result{classification, risk_score, confidence, accessibility_status, threat_intel_status, evidence[], limitations[], ai_explanation null}. Invalid URL returns 422. Done: integration tests; OpenAPI schemas and examples.
- [ ] 5.4 [P] GET /api/v1/scan/{id} (scope scan:read); a key can read scans from keys of the same user, anything else returns 404. Done: ownership tests.

## Phase 6: Webhooks

- [ ] 6.1 [P] security/ssrf.py validate_outbound_url(url, resolver=...): https only, port 443, no userinfo, resolve ALL A/AAAA, reject non-global addresses (private, loopback, link-local, multicast, reserved, CGNAT, 169.254.169.254, IPv4-mapped IPv6). Done: tests with an injected resolver, including mixed public/private records.
- [ ] 6.2 [P] security/crypto.py (Fernet using WEBHOOK_ENC_KEY) and a signing helper: HMAC-SHA256 over "{timestamp}.{raw_body}". Done: test against a known vector.
- [ ] 6.3 [P] POST /api/v1/webhooks (https only, allowed events, max 3 per user, returns 201 and the whsec_ secret once), GET list, DELETE (scope webhooks:manage, owner only). Done: tests.
- [ ] 6.4 [P] services/webhook_sender.py: payload and headers per design §6, 5s timeout, no redirects, one webhook_deliveries row per event per webhook (unique webhook_id + event_id), retry schedule +1m/+5m/+30m then abandoned, disable after 10 consecutive failures. Done: state-transition tests.
- [ ] 6.5 [P] Emit scan.completed and scan.failed from scan_service after commit; api_key.revoked from the admin revoke route. POST /api/v1/internal/cron/webhooks (CRON_SECRET bearer) processes due retries; add Vercel cron config. Done: tests.
- [ ] 6.6 [P] GET /api/v1/webhooks/{id}/deliveries and POST /api/v1/webhook-deliveries/{id}/redeliver. Done: tests.

## Phase 7: Documentation gate

- [ ] 7.1 [P] Complete OpenAPI: tags, descriptions, schemas, examples, all error responses (400/401/403/404/422/429) on every route. scripts/export_openapi.py writes docs/openapi.json; a test fails if the committed file is stale.
- [ ] 7.2 [F] docs/api.md: auth, rate limits, scanning, webhooks (payload, headers, signature verification in Python and Node.js, curl), error codes, versioning.
- [ ] 7.3 [F] scripts/demo.sh (BASE_URL, API_KEY): health, scan, retrieve, and a call without a key that must return 401. Done: [H] run against the live site, then tag v0.1.

## Phase 8: Threat intelligence and Gemini

- [ ] 8.1 [P] services/threat_intel.py: first read Google's CURRENT Safe Browsing docs and terms and state the chosen API in the plan. 3s timeout; statuses no_match, match, error, quota_exceeded; never raises. THREAT_INTEL_ENABLED=false records not_checked. Done: mocked tests (match, no match, timeout, 429, 5xx, malformed).
- [ ] 8.2 [P] Integrate into scan_service: match applies the design §4.4 override; no_match adds an info item and the confidence bonus; error and quota_exceeded add a limitation. Done: tests.
- [ ] 8.3 [P] services/gemini_service.py: read the CURRENT google-genai docs and free-tier model list; model from GEMINI_MODEL; input JSON and system rules per design §5; submitted text wrapped in <untrusted_input>; JSON response schema; 8s timeout. Done: mocked tests.
- [ ] 8.4 [P] services/ai_validator.py (pure): schema check; drop reasons with no or unknown evidence refs; drop text claiming the page was visited or inspected unless accessibility_status is accessible; drop risk-level statements; fallback explanation from evidence; validation_status validated/filtered/fallback/skipped. Done: tests for each rule.
- [ ] 8.5 [P] Integrate and persist ai_analyses; honour include_ai_analysis=false; Gemini failure never fails the scan; add baseline recommendations from the backend. Done: tests incl. a prompt-injection URL that leaves classification and score unchanged. [H] then tag v0.2.

## Phase 9: ML (optional if short on time)

- [ ] 9.1 [H] Choose and download datasets into ml/data/ (gitignored). Hand-build ml/data/hard_legit.csv (about 100 legitimate URLs with login/account/long paths).
- [ ] 9.2 [P] ml/train.py: reuse backend/app/services/url_features.py (no training/serving skew); split by source (and time if available); gradient boosting or random forest with calibration; model file under about 10 MB; requirements-ml.txt separate from runtime requirements.
- [ ] 9.3 [P] ml/evaluate.py writing ml/reports/eval.md: precision, recall, F1, confusion matrix, ROC AUC, false-positive rate on hard_legit.csv and popular-domain URLs, second-dataset result if available.
- [ ] 9.4 [P] backend/app/ml/predictor.py: loads model.joblib once, returns (probability, model_version), returns None when missing or broken. Wire into scan_service (ml_probability, ml_model_version, ml evidence item). Done: tests incl. missing-model path. Runtime requirements: scikit-learn, numpy, joblib, pinned to the training versions.

## Phase 10: Message scanner (optional if short on time)

- [ ] 10.1 [P] services/message_analyzer.py: MS01-MS08 from design §4.8 with pattern files (include UPI collect and KYC scam patterns). Done: tests per signal.
- [ ] 10.2 [P] URL extraction (cap 10, validate, run each through the URL pipeline) and message aggregation per design §4.8. Done: tests incl. no-URL message comes out inconclusive unless S >= 70.
- [ ] 10.3 [P] POST /api/v1/scan/message (scope scan:write; message max 5000 chars, channel email|sms|chat, optional sender); retention_expires_at = now + 7 days; add the purge to the cron endpoint; Gemini gets the message only inside <untrusted_input>, truncated to 4000 chars. Done: tests incl. prompt injection and oversize input.

## Phase 11: Accounts

- [ ] 11.1 [P] Decide first: own auth or Supabase Auth. Own: POST /api/v1/auth/register, /login (argon2id, short-lived JWT in the Authorization: Bearer header, no cookies), GET /auth/me; generic login errors. Done: tests.
- [ ] 11.2 [P] Shared principal object so handlers accept a JWT (dashboard) or an API key (integrations); ownership enforced everywhere (cross-user access returns 404). Done: IDOR tests.
- [ ] 11.3 [P] Guest routes POST /api/v1/public/scan/url and /public/scan/message: no credentials, rate limited by HMAC(IP) with IP_HASH_KEY (10 per minute), raw IP never stored. Done: tests.
- [ ] 11.4 [P] GET /api/v1/history (limit up to 100, offset, filters by classification, date range, domain) and DELETE /api/v1/history/{id}. Done: tests.
- [ ] 11.5 [P] User-facing POST/GET/DELETE /api/v1/api-keys (raw key shown once); webhook routes accept a JWT; CORS allowlist of FRONTEND_ORIGIN only. Done: tests.

## Phase 12: Frontend (React + Vite + Tailwind, follow each tool's current setup docs)

- [ ] 12.1 [P] frontend/ scaffold, VITE_API_BASE, src/services/api.js client. No secrets in frontend code.
- [ ] 12.2 [P] Home and Result pages using the guest endpoint. low_risk shows "No strong indicators found" (never "Safe"); inconclusive shows "Not enough evidence"; null score shows "Not available". Show evidence, limitations, AI explanation, copy and export report. Spinner only, no fake progress.
- [ ] 12.3 [P] Message Scanner page (tabs, 5000-char counter, optional sender, extracted links, signals, assessment).
- [ ] 12.4 [P] Login/register, dashboard, history with filters, delete.
- [ ] 12.5 [P] Developer pages: API keys (key shown once), webhooks (secret shown once, delivery log, redeliver), link to /docs.
- [ ] 12.6 [H] Deploy frontend as a second Vercel project (root frontend/); set FRONTEND_ORIGIN on the backend. Tag v0.3.

## Phase 13: Hardening and delivery

- [ ] 13.1 [P] Security review in a FRESH session, ideally a different model, read-only: produce docs/security-review.md covering SSRF, secrets in logs/DB/bundles, auth and IDOR, rate-limit bypass, input validation and prompt injection, AI text rendering in the frontend, CORS and headers, pip-audit and npm audit, data retention. Report file and line, severity, fix.
- [ ] 13.2 [P] Fix findings, one small session per finding.
- [ ] 13.3 [P] GitHub Actions: ruff, pytest with coverage against a Postgres service container applying db/schema.sql, frontend lint and build; dummy secrets only.
- [ ] 13.4 [P] Close coverage gaps (aggregator, SSRF, API key auth, AI validator, webhook sender) and add tests/data/urls.csv as a rules-only regression set.
- [ ] 13.5 [P] README.md, docs/architecture.md, docs/limitations.md (incl. privacy notes), docs/demo-script.md. State only what the code does and what ml/reports/eval.md measured.
- [ ] 13.6 [H] Final deployment checklist: env vars in both Vercel projects, cron configured and run once, scripts/demo.sh against live, webhook to a real receiver, cold start and longest scan time within the function limit, docs/openapi.json matches live /openapi.json, rotate any leaked secret. Update the Google Sheet and tag v1.0.

---

## If time runs short, cut in this order
Phase 12 polish (12.3-12.5), Phase 10, Phase 9, own-auth in Phase 11. Never cut Phases 1-8, step 13.1, or the tests for auth, webhooks and SSRF.
