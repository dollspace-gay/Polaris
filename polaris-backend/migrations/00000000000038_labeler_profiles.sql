-- Local cache of labeler display-name + handle (issue #183).
--
-- The case-view's "Third-party labels" panel reads from `indexed_labels`
-- which stores the wire-shape `src` DID. To show a human-readable name
-- ("Alt Text Labeler") instead of the bare DID a moderator can't
-- mentally parse (`did:plc:rh3vjqs4npfpmnkkmx4u4bzj`), we keep a local
-- cache of `(display_name, handle, description)` keyed by DID.
--
-- # Why a cache vs. AppView call per render
--
-- The previous code called `app.bsky.labeler.getServices` per case-view
-- render to enrich label rows. That's a network round-trip on the
-- critical render path AND uses the AppView's labeler-services lookup
-- (which has its own quirks; e.g. the `&dids=` parameter must be
-- repeated, not comma-joined). A local cache:
--
--   * eliminates the round-trip from the render path (case-view stays
--     fast even when AppView is slow);
--   * the labeler-discovery worker can populate this proactively on a
--     7-day TTL, so display names are always fresh by the time a
--     moderator looks at the panel.
--
-- # Schema
--
-- One row per labeler DID. `fetched_at` is when the row was first
-- written; `refreshed_at` is when it was last successfully refreshed.
-- A separate `last_attempt_at` column distinguishes "we tried but
-- the upstream returned nothing" from "we haven't tried yet" so the
-- background refresher can back off rather than hammer a dead labeler.

CREATE TABLE labeler_profiles (
    did              TEXT         PRIMARY KEY,

    -- Display name from the labeler's bsky-side profile
    -- (`creator.displayName` on the `getServices` response).
    -- NULL when the labeler hasn't set one.
    display_name     TEXT,

    -- Handle (e.g. "moderation.bsky.app"). NULL when unset or
    -- equals "handle.invalid".
    handle           TEXT,

    -- Short description of the labeler's policy / scope.
    description      TEXT,

    -- Avatar CDN URL, when set on the labeler's profile.
    avatar_url       TEXT,

    -- First time this row was populated.
    fetched_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- Most-recent successful refresh.
    refreshed_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- Most-recent attempt (success OR failure). The lazy refresher
    -- uses this for backoff; a labeler that returns nothing repeatedly
    -- doesn't get hammered.
    last_attempt_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Stale-while-revalidate the case-view: a row is considered fresh
-- when `now() - refreshed_at < 7 days`; older rows trigger a
-- background refresh on the next time the DID is observed.
CREATE INDEX labeler_profiles_refreshed_at_idx
    ON labeler_profiles (refreshed_at);

INSERT INTO _polaris_schema_version (version, description)
    VALUES (39, 'labeler_profiles — local cache of labeler display-name + handle');
