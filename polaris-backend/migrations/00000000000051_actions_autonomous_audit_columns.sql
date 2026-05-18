-- Autonomous-action audit columns on `actions` (#233, LLM-3 / REQ-F1).
--
-- The LLM moderation assist subsystem
-- (`.design/llm-moderation-assist.md`) lets the LLM dispatcher create
-- actions directly when `autonomy_mode = 'autonomous'`. Per REQ-F1 the
-- audit trail must record everything an investigator needs to
-- reconstruct *why the agent acted*: the originating LLM observation,
-- the model + version + prompt template, the recommendation confidence,
-- and a content hash of the input case bundle so a future replay can
-- prove determinism.
--
-- The columns default to NULL and `actor_kind` defaults to `'human'`
-- so existing rows stay valid and existing call sites continue to
-- compile and behave identically — only the LLM dispatcher (LLM-5,
-- #242) flips `actor_kind = 'autonomous_agent'` and populates the
-- audit envelope. This is the AC-5 backward-compat contract.
--
-- The load-bearing invariant: when `actor_kind = 'autonomous_agent'`,
-- the audit envelope MUST be complete. The named CHECK
-- `actions_autonomous_audit_complete` enforces this at the database
-- boundary so a buggy future writer that sets `actor_kind` without
-- the rest is rejected with a self-explanatory SQLSTATE 23514. The
-- CHECK uses a `CASE … WHEN … THEN … ELSE TRUE END` shape so the
-- expression is NULL-safe (any NULL on a required column collapses
-- the case to FALSE and rejects the insert).
--
-- The `llm_observation_id` FK points at the `LlmRecommendation`
-- observation row that produced this action; that row's `evidence`
-- JSONB carries the full `RecommendResponse` payload (REQ-B2) for
-- replay. The reverse direction (find the action that an LLM
-- observation produced) is queried via this column too.
--
-- The append-only trigger from migration 4 still applies — these are
-- INSERT-time fields only. A future reversal of an autonomous action
-- writes its own row with `actor_kind = 'human'` and leaves the
-- original's audit envelope intact (REQ-F2).

ALTER TABLE actions
    ADD COLUMN actor_kind TEXT NOT NULL DEFAULT 'human'
        CHECK (actor_kind IN ('human', 'autonomous_agent'));

ALTER TABLE actions
    ADD COLUMN llm_observation_id UUID
        REFERENCES observations(id);

ALTER TABLE actions
    ADD COLUMN model TEXT;

ALTER TABLE actions
    ADD COLUMN model_version TEXT;

ALTER TABLE actions
    ADD COLUMN prompt_template_id TEXT;

-- 0.0–1.0; stored as REAL to match the per-variant `confidence`
-- shape on observations + classifier signals. The range is enforced
-- by the LLM adapter (REQ-A3) and re-asserted at the dispatcher
-- level; the DB does not CHECK it here because partial NULLs are
-- legal for human actions and a per-row CHECK would have to be
-- conditional on `actor_kind`.
ALTER TABLE actions
    ADD COLUMN recommendation_confidence REAL;

-- SHA-256 hex of the canonicalised `RecommendRequest` payload.
-- Lets a future audit verify determinism: same case bundle ⇒ same
-- decision. See REQ-D2 in the design.
ALTER TABLE actions
    ADD COLUMN input_hash TEXT;

-- Load-bearing invariant: autonomous actions must carry the full
-- audit envelope. NULL-safe via the explicit IS NOT NULL series so
-- a missing required column collapses the case to FALSE and trips
-- the constraint at insert time.
ALTER TABLE actions
    ADD CONSTRAINT actions_autonomous_audit_complete
    CHECK (
        CASE actor_kind
            WHEN 'autonomous_agent' THEN
                llm_observation_id        IS NOT NULL
                AND model                 IS NOT NULL
                AND model_version         IS NOT NULL
                AND prompt_template_id    IS NOT NULL
                AND recommendation_confidence IS NOT NULL
                AND input_hash            IS NOT NULL
            ELSE TRUE
        END
    );

-- Investigator query: "what has the autonomous agent done lately?"
-- Partial index keyed on the predicate the audit endpoint (LLM-9,
-- #238) will use verbatim. Restricting to autonomous rows keeps
-- the index small in the common (human-dominant) case.
CREATE INDEX actions_autonomous_created_at_idx
    ON actions (created_at DESC)
    WHERE actor_kind = 'autonomous_agent';

-- Pivot index for the case-view "find the action this LLM
-- recommendation produced" query (REQ-J1 surfaces the reverse
-- link in the panel).
CREATE INDEX actions_llm_observation_idx
    ON actions (llm_observation_id)
    WHERE llm_observation_id IS NOT NULL;

INSERT INTO _polaris_schema_version (version, description)
    VALUES (51, 'actions-autonomous-audit-columns');
