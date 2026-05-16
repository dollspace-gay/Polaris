-- Issue #116 / M5 #44 PR 2: mobile_devices table.
--
-- Stores per-moderator device tokens for push-notification fan-out.
-- One row per (moderator, device) pair; a moderator with both an
-- iPhone and an iPad has two rows.
--
-- Per AC-8 / REQ-8: push payloads carry NO PII — only the incident
-- ID as a deep-link target. This table holds the token-to-moderator
-- mapping that lets the push subsystem route incident events to the
-- right device WITHOUT embedding moderator identity in the payload.
--
-- Tokens are opaque platform-issued identifiers. They rotate on app
-- reinstall, OS upgrade, or vendor-determined intervals; the registration
-- endpoint (#116 PR 2) UPSERTs on (moderator_id, platform, token).
--
-- Token-stale handling: when APNs/FCM rejects a token, the push
-- subsystem sets revoked_at = now() but keeps the row for audit;
-- a future cron prunes rows where revoked_at < now() - 30 days.

CREATE TABLE mobile_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    moderator_id UUID NOT NULL REFERENCES moderators(id),
    platform TEXT NOT NULL
        CHECK (platform IN ('ios', 'android', 'ntfy')),
    push_token TEXT NOT NULL,
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Uniqueness: same token can't register twice. The endpoint
    -- UPSERTs against this constraint to handle reinstalls cleanly.
    CONSTRAINT mobile_devices_unique_token UNIQUE (platform, push_token)
);

-- Fast "give me all live devices for moderator X" — the fan-out
-- subscriber's primary access pattern.
CREATE INDEX mobile_devices_moderator_idx
    ON mobile_devices (moderator_id)
    WHERE revoked_at IS NULL;

-- For the 30-day prune cron (future PR).
CREATE INDEX mobile_devices_revoked_at_idx
    ON mobile_devices (revoked_at)
    WHERE revoked_at IS NOT NULL;

INSERT INTO _polaris_schema_version (version, description)
    VALUES (31, 'mobile_devices (#116 / M5 #44 PR 2)');
