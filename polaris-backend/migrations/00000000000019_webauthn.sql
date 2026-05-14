-- Hardware-key (WebAuthn / FIDO2) credentials (design.md §6 / §9.1, issue #40).
-- Adds the post-login hardware-key gate on top of OIDC + ATProto OAuth.
--
-- Threat model: defends against the compromised-moderator-account vector
-- (design.md §9.1). A moderator on the Bluesky deployment profile cannot
-- reach the dashboard without presenting a registered FIDO2 authenticator
-- after SSO completes. The labeler profile leaves the gate off by default
-- but operators can opt in.

CREATE TABLE webauthn_credentials (
    id              BIGSERIAL    PRIMARY KEY,
    moderator_id    UUID         NOT NULL REFERENCES moderators(id) ON DELETE CASCADE,
    -- Authenticator-supplied credential ID (raw bytes; base64url at the API surface).
    credential_id   BYTEA        NOT NULL UNIQUE,
    -- COSE-encoded public key per WebAuthn spec.
    public_key      BYTEA        NOT NULL,
    -- Strictly monotonic per credential. A decrease is a cloning red-flag
    -- detected at `assert_finish` time and surfaced via
    -- `WebauthnError::CloningDetected` + `tracing::error!`.
    sign_count      BIGINT       NOT NULL DEFAULT 0,
    -- Comma-separated transports as reported by the authenticator
    -- (usb, nfc, ble, internal, hybrid). Diagnostic only.
    transports      TEXT,
    -- Operator-meaningful label ("YubiKey 5C", "Travel Key", ...).
    nickname        TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ
);

CREATE INDEX webauthn_credentials_moderator_id_idx
    ON webauthn_credentials(moderator_id);

-- Transient: pending registration challenges. Indexed by state token issued
-- in register/start. 5-minute TTL enforced by the handler (the lookup query
-- filters `created_at > now() - INTERVAL '5 minutes'` and deletes the row
-- on access, mirroring the `auth_oidc_login_states` pattern from #9).
CREATE TABLE webauthn_register_states (
    state           TEXT         PRIMARY KEY,
    moderator_id    UUID         NOT NULL REFERENCES moderators(id) ON DELETE CASCADE,
    -- Server-side bincode-serialised `PasskeyRegistration` from webauthn-rs.
    -- Persisting the framework's opaque state object keeps the WebAuthn
    -- ceremony's CSRF / challenge integrity invariants in one place
    -- (the framework verifies them at `finish_passkey_registration`).
    challenge_state BYTEA        NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX webauthn_register_states_created_at_idx
    ON webauthn_register_states(created_at);

-- Transient: pending assertion challenges. Same shape, separate table so the
-- types don't accidentally interchange.
CREATE TABLE webauthn_assert_states (
    state           TEXT         PRIMARY KEY,
    moderator_id    UUID         NOT NULL REFERENCES moderators(id) ON DELETE CASCADE,
    -- Server-side bincode-serialised `PasskeyAuthentication` from webauthn-rs.
    challenge_state BYTEA        NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX webauthn_assert_states_created_at_idx
    ON webauthn_assert_states(created_at);

INSERT INTO _polaris_schema_version (version, description)
    VALUES (20, 'webauthn');
