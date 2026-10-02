-- Issue #17: AlertStorageService
--
-- Idempotent migration for an existing database.
-- Mirror these changes in scripts/init_db.sql.

BEGIN;

-- ============================================================
-- 1. Alert resolution timestamp
-- ============================================================

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;


-- ============================================================
-- 2. Configurable per-rule deduplication window
-- ============================================================

ALTER TABLE rules
    ADD COLUMN IF NOT EXISTS
        dedup_window_minutes INTEGER
        NOT NULL
        DEFAULT 10;


DO $$
BEGIN

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname =
            'ck_rules_dedup_window_positive'
    ) THEN

        ALTER TABLE rules
            ADD CONSTRAINT
                ck_rules_dedup_window_positive
            CHECK (
                dedup_window_minutes > 0
            );

    END IF;


    -- ========================================================
    -- 3. Replace the old Issue #12 uniqueness rule
    -- ========================================================
    --
    -- Existing constraint:
    --
    -- rule_name + source_ip +
    -- window_start + window_end
    --
    -- Issue #17 needs:
    --
    -- source_ip + rule_name + window_start
    --
    -- because AlertStorageService uses:
    --
    -- ON CONFLICT (
    --     source_ip,
    --     rule_name,
    --     window_start
    -- )

    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname =
            'uq_alerts_rule_source_window'
    ) THEN

        ALTER TABLE alerts
            DROP CONSTRAINT
                uq_alerts_rule_source_window;

    END IF;


    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname =
            'uq_alerts_ip_rule_window_start'
    ) THEN

        ALTER TABLE alerts
            ADD CONSTRAINT
                uq_alerts_ip_rule_window_start
            UNIQUE (
                source_ip,
                rule_name,
                window_start
            );

    END IF;

END $$;


-- ============================================================
-- 4. Dashboard query indexes
-- ============================================================

CREATE INDEX IF NOT EXISTS
    ix_alerts_triggered_at
ON alerts (
    triggered_at DESC
);

CREATE INDEX IF NOT EXISTS
    ix_alerts_status_severity
ON alerts (
    status,
    severity
);

COMMIT;