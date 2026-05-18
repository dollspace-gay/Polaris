-- Per-labeler health columns on `upstream_labelers`.
--
-- Polaris's discovery worker writes ~300 rows into `upstream_labelers`
-- from the PLC export; many of those point at hosts that are dead
-- (rotated-out `*.bsky.network` personal labelers, expired
-- `*.ngrok-free.app` tunnels, `localhost:3000` from a developer's
-- dotfile that ended up in their service record). The supervisor used
-- to spawn one `UpstreamLabelerConsumer` per enabled row uncondition-
-- ally, which produced ~100 NXDOMAIN attempts per second once the
-- consumers entered their reconnect loops. That DNS pressure starved
-- glibc's resolver and timed out the on-demand `queryLabels` backfill
-- for healthy labelers — the third-party labels panel surfaced only
-- 5-8 labels because the backfill was racing against its own DNS
-- storm.
--
-- The fix is to track per-labeler health and let the supervisor /
-- consumer pair back off dead rows exponentially:
--
--   * `consecutive_failures` counts the run of consumer exits with no
--     intervening successful frame. Reset to 0 on the first verified
--     + persisted frame.
--   * `last_success_at` is `now()` at the moment a frame is verified
--     + persisted. Operator-visible "last we heard from this labeler".
--     `NULL` for rows that have never produced a verified frame.
--   * `dormant_until` is the wall-clock cutoff before which the
--     supervisor's reconcile pass MUST NOT spawn a consumer for this
--     row. The consumer-side error path writes this with an
--     exponential cadence (1min → 5min → 30min → 6h, cap 24h) keyed
--     off `consecutive_failures`. Cleared (set NULL) on success.
--
-- Existing rows get `consecutive_failures = 0`, `last_success_at` and
-- `dormant_until` `NULL` — i.e. "we have no history, try them once
-- and update the row based on the outcome". This is what the
-- supervisor wants on the first reconcile after deploy.

ALTER TABLE upstream_labelers
    ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN last_success_at TIMESTAMPTZ,
    ADD COLUMN dormant_until TIMESTAMPTZ;

-- Partial index: the supervisor's reconcile path frequently asks
-- "give me enabled rows that are NOT dormant". A partial index over
-- the dormancy predicate keeps that lookup cheap as the table grows
-- past several hundred rows. The matching `WHERE dormant_until IS
-- NULL OR dormant_until <= now()` clause in the load query lines up
-- exactly with this predicate at the plan-time level.
CREATE INDEX upstream_labelers_dormant_until_idx
    ON upstream_labelers (dormant_until)
    WHERE dormant_until IS NOT NULL;

INSERT INTO _polaris_schema_version (version, description)
    VALUES (43, 'upstream-labeler-health');
