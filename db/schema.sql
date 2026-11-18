-- PhishGuard AI - PostgreSQL schema v1
-- Target: Supabase / PostgreSQL 14+
-- Run once in the SQL editor, or split into migrations (Alembic / Flask-Migrate).
-- Enumerations here must match design.md section 2 exactly.

begin;

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
create table users (
  id            uuid primary key default gen_random_uuid(),
  email         text not null,
  password_hash text not null,                 -- argon2id or bcrypt; never plaintext
  full_name     text,
  created_at    timestamptz not null default now()
);
create unique index users_email_lower_uq on users (lower(email));

-- ---------------------------------------------------------------------------
-- api_keys  (raw key is shown once at creation and never stored)
-- ---------------------------------------------------------------------------
create table api_keys (
  id                 uuid primary key default gen_random_uuid(),
  user_id            uuid not null references users(id) on delete cascade,
  name               text not null,
  key_prefix         text not null,            -- first 12 chars, safe to display, e.g. 'pg_live_a1b2'
  key_hash           text not null unique,     -- SHA-256 hex of the full key (keys are high-entropy, fast hash is fine)
  scopes             text[] not null default array['scan:write','scan:read'],
  rate_limit_per_min integer not null default 30 check (rate_limit_per_min > 0),
  expires_at         timestamptz,
  revoked_at         timestamptz,
  last_used_at       timestamptz,
  created_at         timestamptz not null default now(),
  constraint api_keys_scopes_valid
    check (scopes <@ array['scan:write','scan:read','webhooks:manage']::text[])
);
create index api_keys_user_idx on api_keys (user_id);

-- ---------------------------------------------------------------------------
-- scans  (one row per URL scan or message scan)
-- ---------------------------------------------------------------------------
create table scans (
  id                   uuid primary key default gen_random_uuid(),
  public_id            text not null unique,   -- 'scn_' + 22 url-safe chars; the only id the API exposes
  user_id              uuid references users(id) on delete cascade,        -- null for guests
  api_key_id           uuid references api_keys(id) on delete set null,    -- null for browser scans
  client_ip_hash       text,                   -- HMAC of client IP for guest rate limiting; never the raw IP
  input_type           text not null check (input_type in ('url','message')),
  input_text           text,                   -- URL as submitted, or message body; purged after retention
  message_channel      text check (message_channel in ('email','sms','chat')),
  mode                 text not null default 'sync' check (mode in ('sync','async')),
  scan_status          text not null default 'pending'
                         check (scan_status in ('pending','processing','completed','failed')),
  current_stage        text
                         check (current_stage in ('validating','extracting','threat_intel','ml',
                                                  'aggregating','ai_explanation','reporting')),
  classification       text check (classification in ('low_risk','suspicious','high_risk','inconclusive')),
  risk_score           numeric(5,2) check (risk_score between 0 and 100),   -- null when inconclusive
  confidence           numeric(3,2) check (confidence between 0 and 1),
  score_policy_version text,                   -- e.g. 'v1'; lets old scans be interpreted correctly
  accessibility_status text not null default 'not_attempted'
                         check (accessibility_status in ('not_attempted','accessible','blocked',
                                                         'rate_limited','auth_required','unreachable')),
  error_code           text,
  retention_expires_at timestamptz,
  created_at           timestamptz not null default now(),
  completed_at         timestamptz,
  constraint scans_message_has_channel
    check (input_type <> 'message' or message_channel is not null),
  constraint scans_completed_has_result
    check (scan_status <> 'completed' or classification is not null),
  constraint scans_score_matches_class
    check (
      (classification is null)
      or (classification = 'inconclusive' and risk_score is null)
      or (classification in ('low_risk','suspicious','high_risk') and risk_score is not null)
    )
);
create index scans_user_created_idx on scans (user_id, created_at desc);
create index scans_apikey_created_idx on scans (api_key_id, created_at desc);

-- ---------------------------------------------------------------------------
-- scan_urls  (one row for a URL scan; one per extracted link for a message scan)
-- ---------------------------------------------------------------------------
create table scan_urls (
  id                  uuid primary key default gen_random_uuid(),
  scan_id             uuid not null references scans(id) on delete cascade,
  position            smallint not null default 0,
  url                 text not null,
  normalized_url      text not null,           -- lowercase host, no fragment; consider redacting query values
  host                text not null,
  registered_domain   text,                    -- from tldextract, e.g. 'evil.xyz'
  is_shortener        boolean not null default false,
  rule_score          numeric(5,2),
  ml_probability      numeric(4,3) check (ml_probability between 0 and 1),
  ml_model_version    text,
  threat_intel_status text not null default 'not_checked'
                        check (threat_intel_status in ('not_checked','no_match','match','error','quota_exceeded')),
  classification      text check (classification in ('low_risk','suspicious','high_risk','inconclusive')),
  risk_score          numeric(5,2) check (risk_score between 0 and 100),
  unique (scan_id, position)
);
create index scan_urls_domain_idx on scan_urls (registered_domain);

-- ---------------------------------------------------------------------------
-- scan_evidence  (actual findings; Gemini may only cite these via evidence_ref)
-- ---------------------------------------------------------------------------
create table scan_evidence (
  id            uuid primary key default gen_random_uuid(),
  scan_id       uuid not null references scans(id) on delete cascade,
  scan_url_id   uuid references scan_urls(id) on delete cascade,   -- null for message-level findings
  evidence_ref  text not null,                 -- 'E1', 'E2', ... stable within a scan
  source        text not null check (source in ('rule','ml','threat_intel','message_rule','system')),
  indicator     text not null,                 -- e.g. 'ip_host', 'brand_lookalike', 'inspection_blocked'
  severity      text not null check (severity in ('info','low','medium','high')),
  points        integer not null default 0,    -- contribution to the rule score; 0 for info items
  description   text not null,
  details       jsonb not null default '{}'::jsonb,
  unique (scan_id, evidence_ref)
);
create index scan_evidence_scan_idx on scan_evidence (scan_id);

-- ---------------------------------------------------------------------------
-- ai_analyses  (Gemini explanation after backend validation)
-- ---------------------------------------------------------------------------
create table ai_analyses (
  id                   uuid primary key default gen_random_uuid(),
  scan_id              uuid not null unique references scans(id) on delete cascade,
  model_name           text not null,
  summary              text not null,
  reasons              jsonb not null default '[]'::jsonb,   -- [{ "text": "...", "evidence_refs": ["E1"] }]
  recommendations      jsonb not null default '[]'::jsonb,
  limitations          jsonb not null default '[]'::jsonb,
  validation_status    text not null
                         check (validation_status in ('validated','filtered','fallback','skipped')),
  dropped_reason_count integer not null default 0,
  latency_ms           integer,
  created_at           timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- api_usage_logs
-- ---------------------------------------------------------------------------
create table api_usage_logs (
  id               bigint generated always as identity primary key,
  api_key_id       uuid references api_keys(id) on delete set null,   -- null when the key was missing/invalid
  request_id       text not null,
  method           text not null,
  endpoint         text not null,
  status_code      integer not null,
  response_time_ms integer,
  ip_hash          text,
  created_at       timestamptz not null default now()
);
create index api_usage_key_time_idx on api_usage_logs (api_key_id, created_at desc);

-- ---------------------------------------------------------------------------
-- rate_limit_counters  (fixed-window limiter that works across serverless instances)
--   insert into rate_limit_counters (bucket, window_start, request_count)
--   values ($1, date_trunc('minute', now()), 1)
--   on conflict (bucket, window_start)
--   do update set request_count = rate_limit_counters.request_count + 1
--   returning request_count;
-- ---------------------------------------------------------------------------
create table rate_limit_counters (
  bucket        text not null,                 -- 'key:<api_key_id>' or 'ip:<ip_hash>'
  window_start  timestamptz not null,
  request_count integer not null default 0,
  primary key (bucket, window_start)
);

-- ---------------------------------------------------------------------------
-- webhooks
-- ---------------------------------------------------------------------------
create table webhooks (
  id                   uuid primary key default gen_random_uuid(),
  user_id              uuid not null references users(id) on delete cascade,
  endpoint_url         text not null check (endpoint_url like 'https://%'),
  secret_encrypted     text not null,          -- Fernet / AES-GCM ciphertext. HMAC needs the raw secret, so a hash is NOT enough.
  subscribed_events    text[] not null,
  is_active            boolean not null default true,
  consecutive_failures integer not null default 0,
  disabled_reason      text,
  created_at           timestamptz not null default now(),
  constraint webhooks_events_valid
    check (cardinality(subscribed_events) > 0
           and subscribed_events <@ array['scan.completed','scan.failed','api_key.revoked']::text[])
);
create index webhooks_user_idx on webhooks (user_id);

-- ---------------------------------------------------------------------------
-- webhook_deliveries  (one row per event per webhook; unique event_id gives idempotency)
-- ---------------------------------------------------------------------------
create table webhook_deliveries (
  id              uuid primary key default gen_random_uuid(),
  webhook_id      uuid not null references webhooks(id) on delete cascade,
  scan_id         uuid references scans(id) on delete set null,
  event_id        text not null,               -- 'evt_' + random; same value in payload and X-PhishGuard-Event-Id header
  event_type      text not null check (event_type in ('scan.completed','scan.failed','api_key.revoked')),
  payload         jsonb not null,
  delivery_status text not null default 'pending'
                    check (delivery_status in ('pending','retrying','succeeded','abandoned')),
  attempt_count   integer not null default 0,
  response_status integer,
  last_error      text,
  last_attempt_at timestamptz,
  next_retry_at   timestamptz,
  created_at      timestamptz not null default now(),
  unique (webhook_id, event_id)
);
create index webhook_deliveries_due_idx
  on webhook_deliveries (next_retry_at) where delivery_status = 'retrying';
create index webhook_deliveries_webhook_idx on webhook_deliveries (webhook_id, created_at desc);

-- ---------------------------------------------------------------------------
-- Row Level Security
-- Supabase exposes tables through its REST API with the public anon key.
-- Enabling RLS with no policies means only your backend's server-side DB role
-- (which bypasses RLS) can read or write these tables.
-- ---------------------------------------------------------------------------
alter table users               enable row level security;
alter table api_keys            enable row level security;
alter table scans               enable row level security;
alter table scan_urls           enable row level security;
alter table scan_evidence       enable row level security;
alter table ai_analyses         enable row level security;
alter table api_usage_logs      enable row level security;
alter table rate_limit_counters enable row level security;
alter table webhooks            enable row level security;
alter table webhook_deliveries  enable row level security;

commit;

-- ---------------------------------------------------------------------------
-- Retention jobs (run from a protected cron endpoint, not on every request)
--   update scans set input_text = null
--     where input_text is not null and retention_expires_at < now();
--   delete from rate_limit_counters where window_start < now() - interval '1 day';
--   delete from api_usage_logs      where created_at   < now() - interval '90 days';
-- ---------------------------------------------------------------------------
