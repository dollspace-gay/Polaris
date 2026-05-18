-- LLM-6 (#235) safety-floor thresholds on mod_policies
-- (`.design/llm-moderation-assist.md` REQ-S5, REQ-S6).
--
-- Two per-policy operator levers the safety-floor evaluator reads on
-- every Recommend call:
--
--   * autonomous_rate_limit_per_hour — REQ-S5. Cap on the number of
--     autonomous actions a single policy may emit per rolling hour.
--     Default 60 (one per minute sustained). Setting 0 disables auto-
--     fire for the policy entirely without flipping autonomy_mode (a
--     soft "off switch" the operator can flip with smaller blast
--     radius than full mode change). The CHECK floor admits 0 so this
--     posture is reachable.
--
--   * autonomous_reversal_breaker_threshold — REQ-S6. Reversal-rate
--     fraction in the rolling 7-day window above which the
--     dispatcher writes `autonomous_paused_until = now() + 24h` and
--     emits a structured alert. Default 0.15 (one reversal in seven
--     is the "agent is miscalibrated for this policy" signal). The
--     CHECK pins to [0.0, 1.0] so a 0 setting makes every reversal
--     trip and 1.0 means "never trip".
--
-- Both columns default-fill historical rows under NOT NULL so reads
-- on pre-migration policies surface the documented defaults without
-- a NULL check on the call site. The amend path in
-- repo::mod_policies::amend carries them forward across versions
-- (patch.None → prior value) so a policy edited after this lands
-- keeps whatever operational tuning it had unless the patch
-- explicitly changes it.
--
-- These columns participate in the existing `(identifier, version)`
-- versioning model: amending a policy writes a new row with the
-- (possibly new) threshold values; historical rows keep their
-- thresholds as they were when binding. The LLM dispatcher reads
-- the current-version row on every Recommend call so a threshold
-- change takes effect at the next dispatch.

ALTER TABLE mod_policies
    ADD COLUMN autonomous_rate_limit_per_hour INTEGER NOT NULL DEFAULT 60
        CHECK (autonomous_rate_limit_per_hour >= 0),
    ADD COLUMN autonomous_reversal_breaker_threshold REAL NOT NULL DEFAULT 0.15
        CHECK (autonomous_reversal_breaker_threshold BETWEEN 0.0 AND 1.0);

INSERT INTO _polaris_schema_version (version, description)
    VALUES (53, 'mod-policies-autonomy-thresholds');
