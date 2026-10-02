-- init_db.sql
-- Initial schema for the SIEM platform's structured storage (PostgreSQL).
-- Idempotent: safe to run multiple times against the same database.
--
-- Run automatically on first container start via docker-entrypoint-initdb.d,
-- or manually with:
--   docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f - < scripts/init_db.sql

BEGIN;

-- Needed for gen_random_uuid() on PostgreSQL 15.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL PRIMARY KEY,
    username        VARCHAR(64)  NOT NULL UNIQUE,
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    role            VARCHAR(32)  NOT NULL DEFAULT 'analyst'
                        CHECK (role IN ('admin', 'analyst', 'viewer')),
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- rules  (detection rule configuration)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rules (
    id                    BIGSERIAL PRIMARY KEY,
    rule_name             VARCHAR(128) NOT NULL UNIQUE,
    description           TEXT,
    threshold             INTEGER      NOT NULL CHECK (threshold > 0),
    window_minutes        INTEGER      NOT NULL CHECK (window_minutes > 0),
    enabled               BOOLEAN      NOT NULL DEFAULT TRUE,
    dedup_window_minutes  INTEGER      NOT NULL DEFAULT 10
                            CHECK (dedup_window_minutes > 0),
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- events  (normalized log events)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    id              BIGSERIAL PRIMARY KEY,
    event_id        UUID         NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    "timestamp"     TIMESTAMPTZ  NOT NULL,
    source_ip       INET,
    event_type      VARCHAR(64)  NOT NULL,
    -- Matches consumers.schemas.Severity exactly (Issue #6 canonical schema).
    severity        VARCHAR(16)  NOT NULL
                        CHECK (severity IN ('INFO', 'MEDIUM', 'HIGH', 'CRITICAL')),
    source          VARCHAR(128) NOT NULL,
    raw_message     TEXT,
    -- Enrichment fields (GeoIP, ASN, etc.) live here so the schema can
    -- absorb new enrichment sources without a migration.
    metadata        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- alerts  (triggered detection results)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id              BIGSERIAL PRIMARY KEY,
    rule_name       VARCHAR(128) NOT NULL REFERENCES rules(rule_name)
                        ON UPDATE CASCADE ON DELETE RESTRICT,
    source_ip       INET,
    -- Matches consumers.schemas.Severity exactly (Issue #6 canonical schema).
    severity        VARCHAR(16)  NOT NULL
                        CHECK (severity IN ('INFO', 'MEDIUM', 'HIGH', 'CRITICAL')),
    triggered_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    event_count     INTEGER      NOT NULL CHECK (event_count > 0),
    window_start    TIMESTAMPTZ  NOT NULL,
    window_end      TIMESTAMPTZ  NOT NULL,
    status          VARCHAR(16)  NOT NULL DEFAULT 'OPEN'
                        CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')),
    resolved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CHECK (window_end >= window_start),
    CONSTRAINT uq_alerts_ip_rule_window_start
        UNIQUE (source_ip, rule_name, window_start)
);

-- ---------------------------------------------------------------------------
-- Indexes (query performance)
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_events_timestamp
    ON events ("timestamp");

CREATE INDEX IF NOT EXISTS idx_events_source_ip
    ON events (source_ip);

CREATE INDEX IF NOT EXISTS idx_events_event_type
    ON events (event_type);

-- Speeds up ad-hoc queries/containment checks against enrichment data.
CREATE INDEX IF NOT EXISTS idx_events_metadata_gin
    ON events USING GIN (metadata);

CREATE INDEX IF NOT EXISTS idx_alerts_triggered_at
    ON alerts (triggered_at);

CREATE INDEX IF NOT EXISTS idx_alerts_source_ip
    ON alerts (source_ip);

CREATE INDEX IF NOT EXISTS idx_alerts_status
    ON alerts (status);

CREATE INDEX IF NOT EXISTS idx_alerts_rule_name
    ON alerts (rule_name);

CREATE INDEX IF NOT EXISTS idx_alerts_status_severity
    ON alerts (status, severity);

-- ---------------------------------------------------------------------------
-- updated_at auto-touch trigger (users, rules, alerts)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_rules_updated_at ON rules;
CREATE TRIGGER trg_rules_updated_at
    BEFORE UPDATE ON rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_alerts_updated_at ON alerts;
CREATE TRIGGER trg_alerts_updated_at
    BEFORE UPDATE ON alerts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMIT;