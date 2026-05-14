-- ATProto OAuth login-state holding table — parallel to auth_oidc_login_states.
-- Stores per-login PKCE verifier + DPoP keypair (encrypted at rest) +
-- handle + PAR request URI between /auth/atproto/login redirect and
-- /auth/atproto/callback code exchange. 10-minute TTL same as OIDC.
--
-- Issue #31 / REQ-4 / AC-4. Mirrors `auth_oidc_login_states` (see
-- migration 00000000000001_auth.sql) so the shape is familiar to readers
-- already conversant with the OIDC half; the differences vs. OIDC are
-- the DPoP keypair column (sealed bytes, not a CSRF nonce) and the PAR
-- request URI returned by the AS's PAR endpoint.
CREATE TABLE auth_atproto_login_states (
    state TEXT PRIMARY KEY,
    -- PKCE verifier — caller-side secret recovered at code-exchange time.
    pkce_verifier TEXT NOT NULL,
    -- DPoP keypair sealed via auth/crypto.rs (AES-256-GCM, same KEK as
    -- the OIDC refresh-token encryption). The unsealed form is the
    -- per-session keypair proto-blue-oauth uses to bind tokens.
    dpop_keypair_enc BYTEA NOT NULL,
    -- Handle the operator entered at login (e.g. moderator.example.com)
    -- — purely diagnostic; the authoritative subject is the DID returned
    -- by the token endpoint.
    handle TEXT NOT NULL,
    -- PAR (Pushed Authorization Request) URI returned by the AS — included
    -- in the authorize URL the client follows.
    par_request_uri TEXT NOT NULL,
    -- Issuer URL — discovered at start_login and re-used at complete_login
    -- so the code-exchange call can re-discover the same AS metadata
    -- without trusting unsigned callback data. Captured here rather than
    -- re-resolved from the handle at callback time because the operator's
    -- handle may already have been used to mint the row but the
    -- DID/PDS/AS chain takes multiple network hops.
    issuer TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX auth_atproto_login_states_created_at_idx
    ON auth_atproto_login_states(created_at);

-- Schema version row.
INSERT INTO _polaris_schema_version (version, description)
    VALUES (16, 'auth-atproto-login-states');
