-- Moderator-to-subject email log (issue #190 / Ozone-parity
-- `tools.ozone.moderation.defs#modEventEmail`).
--
-- The `EMAIL` moderator verb sends an email to (typically) the
-- subject's contact address. Polaris doesn't know subject email
-- addresses — they aren't on the AT-Proto wire — so the recipient
-- address comes from the moderator at submit time. The intent is
-- recorded here regardless of delivery outcome so the audit trail
-- captures every attempt.
--
-- # Delivery semantics
--
-- * `queued` — the record was persisted but SMTP is not configured;
--   the operator must wire SMTP creds before delivery happens.
-- * `sent` — `lettre` successfully handed the message to the SMTP
--   relay. `delivered_at` records the wall-clock at handoff.
-- * `failed` — `lettre` rejected the message (relay down, auth
--   error, malformed). The error text lands in `delivery_error`.
--
-- # Why no FK on subject_id
--
-- An email might target a subject Polaris has never seen as a
-- moderation case (e.g. a heads-up to a complainant whose DID
-- never produced a subjects row). Keeping `subject_id` nullable
-- lets the verb still record the intent without forcing a synthetic
-- subject; when the moderator emails a known case, the FK is set
-- and the case-view shows the email in the action timeline.

CREATE TABLE moderator_emails (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_id      UUID         REFERENCES subjects(id) ON DELETE SET NULL,
    -- Subject's DID at email time (independent of whether
    -- `subject_id` is set). Operator-supplied; lets the audit log
    -- carry the addressee context even if the matching subjects row
    -- is later purged.
    subject_did     TEXT,
    sent_by         UUID         NOT NULL REFERENCES moderators(id),
    recipient_email TEXT         NOT NULL CHECK (length(recipient_email) BETWEEN 3 AND 320),
    subject_line    TEXT         NOT NULL CHECK (length(subject_line) BETWEEN 1 AND 998),
    body            TEXT         NOT NULL CHECK (length(body) BETWEEN 1 AND 100000),

    -- Delivery state. CHECK enforces the three-variant invariant.
    delivery_status TEXT         NOT NULL DEFAULT 'queued'
        CHECK (delivery_status IN ('queued', 'sent', 'failed')),

    -- When `lettre` accepted the message (i.e. handed it to the SMTP
    -- relay successfully). NULL until then.
    delivered_at    TIMESTAMPTZ,

    -- Operator-readable error message when delivery failed. NULL
    -- when status != 'failed'.
    delivery_error  TEXT,

    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX moderator_emails_subject_id_idx
    ON moderator_emails (subject_id)
    WHERE subject_id IS NOT NULL;

CREATE INDEX moderator_emails_sent_by_idx
    ON moderator_emails (sent_by);

CREATE INDEX moderator_emails_queued_idx
    ON moderator_emails (created_at)
    WHERE delivery_status = 'queued';

INSERT INTO _polaris_schema_version (version, description)
    VALUES (42, 'moderator_emails — EMAIL verb audit log + SMTP outcome');
