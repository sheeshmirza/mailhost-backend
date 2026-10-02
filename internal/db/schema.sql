CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS accounts (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_keys (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id   uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name         text NOT NULL DEFAULT 'Default Key',
    permission   text NOT NULL DEFAULT 'full_access',
    last_four    text NOT NULL DEFAULT '',
    key_hash     bytea NOT NULL UNIQUE,
    last_used_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS name text NOT NULL DEFAULT 'Default Key';
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS permission text NOT NULL DEFAULT 'full_access';
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS last_four text NOT NULL DEFAULT '';
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS last_used_at timestamptz;
UPDATE api_keys SET permission = 'full_access' WHERE permission IS NULL OR permission = '';
CREATE INDEX IF NOT EXISTS api_keys_account_created_idx ON api_keys (account_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_logs (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id    uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    actor         text NOT NULL,
    action        text NOT NULL,
    resource_type text NOT NULL,
    resource_id   text NOT NULL,
    ip_address    text,
    user_agent    text,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_logs_account_created_idx ON audit_logs (account_id, created_at DESC);

CREATE TABLE IF NOT EXISTS domains (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id          uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name                text NOT NULL,
    status              text NOT NULL DEFAULT 'pending',
    verification_token  text NOT NULL,
    dkim_selector       text NOT NULL,
    dkim_private_key    bytea NOT NULL,
    dkim_public_key     text NOT NULL,
    inbound_webhook_url text,
    webhook_secret      bytea NOT NULL,
    verified_at         timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, name)
);
-- A domain may be claimed by many accounts, but only one can verify it.
CREATE UNIQUE INDEX IF NOT EXISTS domains_verified_name_idx ON domains (name) WHERE status = 'verified';
CREATE INDEX IF NOT EXISTS domains_account_created_idx ON domains (account_id, created_at DESC);

CREATE TABLE IF NOT EXISTS aliases (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id   uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    domain_id    uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    local_part   text NOT NULL,
    destinations text[] NOT NULL DEFAULT '{}',
    store_copy   boolean NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (domain_id, local_part)
);
CREATE INDEX IF NOT EXISTS aliases_account_created_idx ON aliases (account_id, created_at DESC);

CREATE TABLE IF NOT EXISTS smtp_credentials (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id    uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    domain_id     uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    email         text NOT NULL,
    name          text NOT NULL DEFAULT 'SMTP Credential',
    password_hash bytea NOT NULL,
    last_used_at  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS smtp_credentials_account_idx ON smtp_credentials (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS smtp_credentials_email_idx ON smtp_credentials (lower(email));

CREATE TABLE IF NOT EXISTS emails (
    id         uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    domain_id  uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    batch_id   uuid,
    from_addr  text NOT NULL,
    subject    text NOT NULL,
    message_id text NOT NULL,
    raw        bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS emails_account_created_idx ON emails (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS emails_batch_idx ON emails (batch_id) WHERE batch_id IS NOT NULL;

-- An idempotency key lets clients safely retry a timed-out API request without
-- creating another message. Entries are retained for a bounded period by the
-- maintenance loop, rather than growing without limit.
CREATE TABLE IF NOT EXISTS idempotency_keys (
    account_id   uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    key_hash     bytea NOT NULL,
    request_hash bytea NOT NULL,
    response     jsonb NOT NULL,
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, key_hash)
);
CREATE INDEX IF NOT EXISTS idempotency_keys_expiry_idx ON idempotency_keys (expires_at);

-- One row per recipient; this is the delivery queue.
CREATE TABLE IF NOT EXISTS deliveries (
    id              uuid PRIMARY KEY,
    email_id        uuid NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    account_id      uuid NOT NULL,
    domain_id       uuid NOT NULL,
    recipient       text NOT NULL,
    status          text NOT NULL,
    priority        smallint NOT NULL DEFAULT 0, -- 0 transactional, 1 bulk
    attempts        int NOT NULL DEFAULT 0,
    last_error      text,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    locked_until    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS deliveries_due_idx ON deliveries (priority, next_attempt_at) WHERE status IN ('queued', 'deferred', 'scheduled');
CREATE INDEX IF NOT EXISTS deliveries_stale_idx ON deliveries (locked_until) WHERE status = 'sending';
CREATE INDEX IF NOT EXISTS deliveries_email_idx ON deliveries (email_id);
CREATE INDEX IF NOT EXISTS deliveries_account_status_idx ON deliveries (account_id, status);
CREATE INDEX IF NOT EXISTS deliveries_account_created_idx ON deliveries (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS deliveries_email_status_idx ON deliveries (email_id, status);

-- Per-email event timeline, partitioned monthly so retention is a cheap DROP of old partitions.
CREATE TABLE IF NOT EXISTS events (
    id          bigserial,
    account_id  uuid NOT NULL,
    domain_id   uuid NOT NULL,
    email_id    uuid NOT NULL,
    delivery_id uuid NOT NULL,
    type        text NOT NULL,
    detail      text,
    created_at  timestamptz NOT NULL DEFAULT now()
) PARTITION BY RANGE (created_at);
CREATE TABLE IF NOT EXISTS events_default PARTITION OF events DEFAULT;
CREATE INDEX IF NOT EXISTS events_email_idx ON events (email_id);
-- Edge windows in analytics read raw events; this avoids a partition-wide scan.
CREATE INDEX IF NOT EXISTS events_account_created_type_idx ON events (account_id, created_at, type);

-- Hourly analytics counters. Writers pick a random shard so hot accounts don't contend on one row.
CREATE TABLE IF NOT EXISTS event_rollups (
    account_id uuid NOT NULL,
    bucket     timestamptz NOT NULL,
    domain_id  uuid NOT NULL,
    type       text NOT NULL,
    shard      smallint NOT NULL,
    count      bigint NOT NULL,
    PRIMARY KEY (account_id, bucket, domain_id, type, shard)
);

CREATE TABLE IF NOT EXISTS suppressions (
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    address    text NOT NULL,
    reason     text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, address)
);
CREATE INDEX IF NOT EXISTS suppressions_account_created_idx ON suppressions (account_id, created_at DESC);

CREATE TABLE IF NOT EXISTS inbound_emails (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id  uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    domain_id   uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    mail_from   text NOT NULL,
    rcpt_to     text[] NOT NULL,
    from_header text NOT NULL,
    subject     text NOT NULL,
    message_id  text NOT NULL,
    text_body   text NOT NULL,
    html_body   text NOT NULL,
    attachments jsonb NOT NULL DEFAULT '[]',
    size        int NOT NULL,
    raw         bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS inbound_account_created_idx ON inbound_emails (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS inbound_account_domain_created_idx ON inbound_emails (account_id, domain_id, created_at DESC);

-- Domain tracking & security configurations
ALTER TABLE domains ADD COLUMN IF NOT EXISTS open_tracking boolean NOT NULL DEFAULT true;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS click_tracking boolean NOT NULL DEFAULT true;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS tls text NOT NULL DEFAULT 'opportunistic';
ALTER TABLE domains ADD COLUMN IF NOT EXISTS region text NOT NULL DEFAULT 'us-east-1';

-- API key domain scoping
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS domain_id uuid REFERENCES domains(id) ON DELETE CASCADE;

-- Emails metadata & scheduling
ALTER TABLE emails ADD COLUMN IF NOT EXISTS tags jsonb NOT NULL DEFAULT '[]';
ALTER TABLE emails ADD COLUMN IF NOT EXISTS scheduled_at timestamptz;
ALTER TABLE emails ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'queued';
ALTER TABLE emails ADD COLUMN IF NOT EXISTS template_id uuid;
CREATE INDEX IF NOT EXISTS emails_account_status_created_idx ON emails (account_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS emails_scheduled_idx ON emails (scheduled_at) WHERE scheduled_at IS NOT NULL;

-- Delivery tracking metrics
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS open_count int NOT NULL DEFAULT 0;
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS click_count int NOT NULL DEFAULT 0;
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS first_opened_at timestamptz;
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS last_opened_at timestamptz;
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS first_clicked_at timestamptz;
ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS last_clicked_at timestamptz;

-- Audiences
CREATE TABLE IF NOT EXISTS audiences (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audiences_account_idx ON audiences (account_id, created_at DESC);

-- Contacts (global or audience-bound)
CREATE TABLE IF NOT EXISTS contacts (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id   uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    audience_id  uuid REFERENCES audiences(id) ON DELETE SET NULL,
    email        text NOT NULL,
    first_name   text NOT NULL DEFAULT '',
    last_name    text NOT NULL DEFAULT '',
    unsubscribed boolean NOT NULL DEFAULT false,
    traits       jsonb NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, email)
);
CREATE INDEX IF NOT EXISTS contacts_account_idx ON contacts (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS contacts_email_idx ON contacts (account_id, lower(email));
CREATE INDEX IF NOT EXISTS contacts_audience_idx ON contacts (audience_id) WHERE audience_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS contacts_aud_created_idx ON contacts (account_id, audience_id, created_at DESC) WHERE audience_id IS NOT NULL;

-- Segments
CREATE TABLE IF NOT EXISTS segments (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name       text NOT NULL,
    filter     jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS segments_account_idx ON segments (account_id, created_at DESC);

-- Contact Segment Memberships
CREATE TABLE IF NOT EXISTS contact_segments (
    contact_id uuid NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    segment_id uuid NOT NULL REFERENCES segments(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (contact_id, segment_id)
);
CREATE INDEX IF NOT EXISTS contact_segments_segment_idx ON contact_segments (segment_id);

-- Topics (Subscription preferences)
CREATE TABLE IF NOT EXISTS topics (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id  uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    visibility  text NOT NULL DEFAULT 'public', -- 'public' or 'private'
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS topics_account_idx ON topics (account_id, created_at DESC);

-- Contact Topic Subscriptions
CREATE TABLE IF NOT EXISTS contact_topics (
    contact_id uuid NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    topic_id   uuid NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    status     text NOT NULL DEFAULT 'subscribed', -- 'subscribed' or 'unsubscribed'
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (contact_id, topic_id)
);
CREATE INDEX IF NOT EXISTS contact_topics_topic_idx ON contact_topics (topic_id);

-- Templates (Versioned with draft and published states)
CREATE TABLE IF NOT EXISTS templates (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id          uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name                text NOT NULL,
    alias               text,
    subject             text NOT NULL DEFAULT '',
    html                text NOT NULL DEFAULT '',
    text                text NOT NULL DEFAULT '',
    variables           jsonb NOT NULL DEFAULT '[]',
    status              text NOT NULL DEFAULT 'draft', -- 'draft' or 'published'
    published_subject   text NOT NULL DEFAULT '',
    published_html      text NOT NULL DEFAULT '',
    published_text      text NOT NULL DEFAULT '',
    published_variables jsonb NOT NULL DEFAULT '[]',
    published_at        timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, name)
);
CREATE INDEX IF NOT EXISTS templates_account_idx ON templates (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS templates_alias_idx ON templates (account_id, alias) WHERE alias IS NOT NULL;

-- Broadcasts (Bulk marketing campaigns)
CREATE TABLE IF NOT EXISTS broadcasts (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id       uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    segment_id       uuid REFERENCES segments(id) ON DELETE SET NULL,
    audience_id      uuid REFERENCES audiences(id) ON DELETE SET NULL,
    topic_id         uuid REFERENCES topics(id) ON DELETE SET NULL,
    name             text NOT NULL,
    from_addr        text NOT NULL,
    subject          text NOT NULL,
    reply_to         text[] NOT NULL DEFAULT '{}',
    preview_text     text NOT NULL DEFAULT '',
    html             text NOT NULL DEFAULT '',
    text             text NOT NULL DEFAULT '',
    status           text NOT NULL DEFAULT 'draft', -- 'draft', 'queued', 'sending', 'sent', 'cancelled'
    scheduled_at     timestamptz,
    sent_at          timestamptz,
    recipients_count int NOT NULL DEFAULT 0,
    sent_count       int NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS broadcasts_account_idx ON broadcasts (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS broadcasts_status_idx ON broadcasts (status);

-- Automations (Event-driven workflows)
CREATE TABLE IF NOT EXISTS automations (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id     uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name           text NOT NULL,
    status         text NOT NULL DEFAULT 'draft', -- 'draft', 'active', 'paused'
    trigger_type   text NOT NULL, -- 'event', 'contact.created', 'email.opened', 'email.clicked'
    trigger_config jsonb NOT NULL DEFAULT '{}',
    steps          jsonb NOT NULL DEFAULT '[]',
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS automations_account_idx ON automations (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS automations_status_idx ON automations (status);

-- Automation Runs
CREATE TABLE IF NOT EXISTS automation_runs (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id         uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    automation_id      uuid NOT NULL REFERENCES automations(id) ON DELETE CASCADE,
    contact_id         uuid REFERENCES contacts(id) ON DELETE SET NULL,
    contact_email      text NOT NULL,
    event_name         text NOT NULL,
    event_data         jsonb NOT NULL DEFAULT '{}',
    status             text NOT NULL DEFAULT 'running', -- 'running', 'completed', 'failed', 'waiting'
    current_step_index int NOT NULL DEFAULT 0,
    next_execution_at  timestamptz,
    step_results       jsonb NOT NULL DEFAULT '[]',
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS automation_runs_account_idx ON automation_runs (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS automation_runs_automation_idx ON automation_runs (automation_id);
CREATE INDEX IF NOT EXISTS automation_runs_waiting_idx ON automation_runs (status, next_execution_at) WHERE status = 'waiting';

-- Custom Events
CREATE TABLE IF NOT EXISTS custom_events (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id    uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name          text NOT NULL,
    contact_email text NOT NULL,
    data          jsonb NOT NULL DEFAULT '{}',
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS custom_events_account_idx ON custom_events (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS custom_events_name_idx ON custom_events (account_id, name);

-- Webhooks (Account-wide or event-specific endpoints)
CREATE TABLE IF NOT EXISTS webhooks (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id     uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    url            text NOT NULL,
    events         text[] NOT NULL DEFAULT '{}',
    status         text NOT NULL DEFAULT 'active', -- 'active' or 'disabled'
    signing_secret text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS webhooks_account_idx ON webhooks (account_id, created_at DESC);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id      uuid NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type      text NOT NULL,
    payload         jsonb NOT NULL,
    status          text NOT NULL DEFAULT 'queued',
    attempts        int NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    locked_until    timestamptz,
    last_error      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS webhook_deliveries_due_idx
    ON webhook_deliveries (next_attempt_at, created_at)
    WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS webhook_deliveries_stale_idx
    ON webhook_deliveries (locked_until)
    WHERE status = 'sending';

-- Template Versions (Rollback history & immutable audit trail)
CREATE TABLE IF NOT EXISTS template_versions (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id    uuid NOT NULL REFERENCES templates(id) ON DELETE CASCADE,
    account_id     uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    version_number int NOT NULL,
    subject        text NOT NULL DEFAULT '',
    html           text NOT NULL DEFAULT '',
    text           text NOT NULL DEFAULT '',
    variables      jsonb NOT NULL DEFAULT '[]',
    published_by   text NOT NULL DEFAULT 'system',
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (template_id, version_number)
);
CREATE INDEX IF NOT EXISTS template_versions_template_idx ON template_versions (template_id, version_number DESC);

-- Dedicated IPs & Auto-Warming Infrastructure
CREATE TABLE IF NOT EXISTS dedicated_ips (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id     uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    ip_address     inet NOT NULL UNIQUE,
    status         text NOT NULL DEFAULT 'warming', -- 'warming', 'active', 'paused'
    warmup_day     int NOT NULL DEFAULT 1,
    daily_quota    int NOT NULL DEFAULT 50,
    sent_today     int NOT NULL DEFAULT 0,
    last_reset_at  timestamptz NOT NULL DEFAULT now(),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS dedicated_ips_account_created_idx ON dedicated_ips (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS dedicated_ips_account_idx ON dedicated_ips (account_id);

CREATE TABLE IF NOT EXISTS ip_warming_schedules (
    day         int PRIMARY KEY,
    daily_quota int NOT NULL,
    description text NOT NULL
);

-- Multi-Tenant RBAC: Organization Members
CREATE TABLE IF NOT EXISTS organization_members (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    user_id    uuid,
    email      text NOT NULL,
    role       text NOT NULL DEFAULT 'user', -- 'administrator', 'developer', or a user-defined role
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, email)
);
CREATE INDEX IF NOT EXISTS org_members_account_created_idx ON organization_members (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS org_members_account_idx ON organization_members (account_id);
ALTER TABLE organization_members ALTER COLUMN role SET DEFAULT 'user';
UPDATE organization_members SET role = 'administrator' WHERE lower(role) IN ('owner', 'admin');
ALTER TABLE organization_members ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE organization_members ALTER COLUMN user_id DROP DEFAULT;

-- User Accounts & Authentication (Mailhost self-service user management)
CREATE TABLE IF NOT EXISTS users (
    id                          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email                       text NOT NULL UNIQUE,
    password_hash               text NOT NULL,
    name                        text NOT NULL DEFAULT '',
    avatar_url                  text NOT NULL DEFAULT '',
    email_verified              boolean NOT NULL DEFAULT false,
    verification_token          text NOT NULL DEFAULT '',
    verification_token_expires_at timestamptz,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_token text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_token_expires_at timestamptz;
CREATE INDEX IF NOT EXISTS users_email_idx ON users (lower(email));
CREATE INDEX IF NOT EXISTS users_verification_token_idx ON users (verification_token) WHERE verification_token != '';

CREATE TABLE IF NOT EXISTS user_sessions (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_id   uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token_hash   bytea NOT NULL UNIQUE,
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);
CREATE INDEX IF NOT EXISTS user_sessions_user_idx ON user_sessions (user_id);
CREATE INDEX IF NOT EXISTS user_sessions_token_idx ON user_sessions (token_hash);
CREATE INDEX IF NOT EXISTS user_sessions_expires_idx ON user_sessions (expires_at);

-- Password Resets
CREATE TABLE IF NOT EXISTS password_resets (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email      text NOT NULL,
    token_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS password_resets_token_idx ON password_resets (token_hash);
CREATE INDEX IF NOT EXISTS password_resets_user_idx ON password_resets (user_id);

-- Mailboxes (User folders for IMAP & POP3)
CREATE TABLE IF NOT EXISTS mailboxes (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id   uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    email        text NOT NULL,
    name         text NOT NULL DEFAULT 'INBOX',
    uid_validity bigint NOT NULL DEFAULT 1,
    next_uid     bigint NOT NULL DEFAULT 1,
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, email, name)
);
CREATE INDEX IF NOT EXISTS mailboxes_account_email_idx ON mailboxes (account_id, lower(email));

-- Mailbox Messages (Messages stored within mailboxes for IMAP & POP3)
CREATE TABLE IF NOT EXISTS mailbox_messages (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    uid        bigint NOT NULL,
    size       int NOT NULL,
    flags      text[] NOT NULL DEFAULT '{}',
    date       timestamptz NOT NULL DEFAULT now(),
    raw        bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (mailbox_id, uid)
);
CREATE INDEX IF NOT EXISTS mailbox_messages_mailbox_uid_idx ON mailbox_messages (mailbox_id, uid);
CREATE INDEX IF NOT EXISTS mailbox_messages_mailbox_created_idx ON mailbox_messages (mailbox_id, created_at DESC);

-- Relationship constraints for legacy columns that were originally created without foreign keys.
-- Keep these checks idempotent so existing installations are upgraded safely under the migration lock.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'deliveries_account_fk') THEN
        ALTER TABLE deliveries ADD CONSTRAINT deliveries_account_fk FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'deliveries_domain_fk') THEN
        ALTER TABLE deliveries ADD CONSTRAINT deliveries_domain_fk FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'events_account_fk') THEN
        ALTER TABLE events ADD CONSTRAINT events_account_fk FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'events_domain_fk') THEN
        ALTER TABLE events ADD CONSTRAINT events_domain_fk FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'events_email_fk') THEN
        ALTER TABLE events ADD CONSTRAINT events_email_fk FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'events_delivery_fk') THEN
        ALTER TABLE events ADD CONSTRAINT events_delivery_fk FOREIGN KEY (delivery_id) REFERENCES deliveries(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'event_rollups_account_fk') THEN
        ALTER TABLE event_rollups ADD CONSTRAINT event_rollups_account_fk FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'event_rollups_domain_fk') THEN
        ALTER TABLE event_rollups ADD CONSTRAINT event_rollups_domain_fk FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'organization_members_user_fk') THEN
        ALTER TABLE organization_members ADD CONSTRAINT organization_members_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
    END IF;
END $$;



