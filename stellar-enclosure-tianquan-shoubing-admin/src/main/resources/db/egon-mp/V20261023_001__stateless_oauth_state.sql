-- Stateless OAuth authority: one complete logical change for the approved 2026-10-23 design.
-- The managed runner supplies the transaction-local tianquan_oauth search_path.
-- This migration is immutable. Existing state is rejected rather than deleted or silently converted.

-- No legacy authorization/audit data conversion is part of this clean-environment design.
DO $idp_stateless_clean_target$
BEGIN
    IF EXISTS (SELECT 1 FROM oauth_authorization)
       OR EXISTS (SELECT 1 FROM oauth_token)
       OR EXISTS (SELECT 1 FROM oauth_consent)
       OR EXISTS (SELECT 1 FROM oauth_revocation)
       OR EXISTS (SELECT 1 FROM oauth_audit) THEN
        RAISE EXCEPTION 'STATELESS_OAUTH_CLEAN_STATE_REQUIRED';
    END IF;
END
$idp_stateless_clean_target$;

ALTER TABLE oauth_client
    ADD COLUMN browser_bound BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN post_logout_redirect_uris JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD CONSTRAINT ck_oauth_client_logout_redirects CHECK
        (jsonb_typeof(post_logout_redirect_uris) = 'array'
         AND jsonb_array_length(post_logout_redirect_uris) <= 32),
    ADD CONSTRAINT uk_oauth_client_tenant_pk UNIQUE (tenant_id, id);

-- The authorized scopes may shrink during consent; the requested scope ceiling is immutable.
ALTER TABLE oauth_authorization
    ADD COLUMN requested_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN resource_uri VARCHAR(2048) NOT NULL,
    ADD COLUMN authentication_jti_digest CHAR(64),
    ADD COLUMN client_browser_binding_digest CHAR(64),
    ADD COLUMN interaction_id VARCHAR(64),
    ADD COLUMN refresh_generation BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN retain_until TIMESTAMPTZ(6) NOT NULL,
    ADD CONSTRAINT uk_oauth_authorization_tenant_pk UNIQUE (tenant_id, id),
    ADD CONSTRAINT fk_oauth_authorization_client FOREIGN KEY (tenant_id, client_pk)
        REFERENCES oauth_client (tenant_id, id),
    ADD CONSTRAINT ck_oauth_authorization_scope_ceiling CHECK
        (jsonb_typeof(requested_scopes) = 'array'
         AND jsonb_array_length(requested_scopes) <= 64
         AND authorized_scopes <@ requested_scopes),
    ADD CONSTRAINT ck_oauth_authorization_one_resource CHECK
        (length(resource_uri) BETWEEN 1 AND 2048
         AND jsonb_array_length(audiences) = 1 AND audiences ->> 0 = resource_uri),
    ADD CONSTRAINT ck_oauth_authorization_authentication CHECK
        ((principal_type = 'USER' AND authentication_jti_digest IS NOT NULL
          AND authentication_jti_digest ~ '^[0-9a-f]{64}$'
          AND interaction_id IS NOT NULL)
         OR (principal_type = 'SERVICE' AND authentication_jti_digest IS NULL
             AND interaction_id IS NULL AND client_browser_binding_digest IS NULL)),
    ADD CONSTRAINT ck_oauth_authorization_client_binding CHECK
        (client_browser_binding_digest IS NULL OR client_browser_binding_digest ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT ck_oauth_authorization_generation CHECK (refresh_generation >= 0),
    ADD CONSTRAINT ck_oauth_authorization_retention CHECK
        (retain_until >= absolute_expires_at + INTERVAL '24 hours');
ALTER TABLE oauth_authorization DROP CONSTRAINT ck_oauth_authorization_status;
ALTER TABLE oauth_authorization ADD CONSTRAINT ck_oauth_authorization_status
    CHECK (status IN ('PENDING_CONSENT', 'ACTIVE', 'REVOKED', 'EXPIRED', 'CANCELLED'));
CREATE INDEX ix_authorization_authentication ON oauth_authorization
    (tenant_id, authentication_jti_digest, status, id) WHERE deleted_at IS NULL;
CREATE INDEX ix_authorization_retention_v2 ON oauth_authorization (tenant_id, retain_until, id);

-- Retain spent refresh digests until family expiry plus the full replay/revocation grace.
-- A spent digest is usable only by the authenticated revoke endpoint, never for another exchange.
ALTER TABLE oauth_token
    ADD COLUMN refresh_generation BIGINT,
    ADD COLUMN retain_until TIMESTAMPTZ(6) NOT NULL,
    ADD CONSTRAINT uk_oauth_token_tenant_pk UNIQUE (tenant_id, id),
    ADD CONSTRAINT fk_oauth_token_authorization FOREIGN KEY (tenant_id, authorization_pk)
        REFERENCES oauth_authorization (tenant_id, id),
    ADD CONSTRAINT ck_oauth_token_generation CHECK
        ((token_type = 'REFRESH' AND refresh_generation IS NOT NULL AND refresh_generation >= 0)
         OR (token_type <> 'REFRESH' AND refresh_generation IS NULL)),
    ADD CONSTRAINT ck_oauth_token_retention CHECK (retain_until >= expires_at + INTERVAL '24 hours');
ALTER TABLE oauth_token DROP CONSTRAINT ck_oauth_token_type;
ALTER TABLE oauth_token ADD CONSTRAINT ck_oauth_token_type
    CHECK (token_type IN ('ACCESS', 'REFRESH', 'ID_TOKEN', 'AUTHORIZATION_CODE'));
CREATE UNIQUE INDEX uk_oauth_refresh_generation ON oauth_token
    (tenant_id, authorization_pk, refresh_generation) WHERE token_type = 'REFRESH';
CREATE UNIQUE INDEX uk_oauth_refresh_unspent ON oauth_token
    (tenant_id, authorization_pk) WHERE token_type = 'REFRESH'
      AND consumed_at IS NULL AND revoked_at IS NULL AND deleted_at IS NULL;
CREATE INDEX ix_oauth_token_retention_v2 ON oauth_token (tenant_id, retain_until, id);

ALTER TABLE oauth_consent
    ADD COLUMN resource_uri VARCHAR(2048) NOT NULL,
    ADD CONSTRAINT fk_oauth_consent_client FOREIGN KEY (tenant_id, client_pk)
        REFERENCES oauth_client (tenant_id, id),
    ADD CONSTRAINT ck_oauth_consent_resource CHECK (length(resource_uri) BETWEEN 1 AND 2048);
DROP INDEX uk_consent_1_life;
DROP INDEX uk_consent_1_active;
CREATE UNIQUE INDEX uk_consent_resource_active ON oauth_consent
    (tenant_id, client_pk, subject, resource_uri) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uk_consent_resource_life ON oauth_consent
    (tenant_id, client_pk, subject, resource_uri, deleted_at);

-- Security state is authoritative at commit; no Redis APPLIED phase remains.
ALTER TABLE oauth_security_state
    ADD CONSTRAINT uk_oauth_security_state_identity_permanent UNIQUE (tenant_id, target_type, target_key);
ALTER TABLE oauth_revocation DROP CONSTRAINT ck_oauth_revocation_projection;
ALTER TABLE oauth_revocation DROP COLUMN projection_status;
ALTER TABLE oauth_revocation
    ADD COLUMN retain_until TIMESTAMPTZ(6),
    ADD CONSTRAINT uk_oauth_revocation_target_permanent UNIQUE (tenant_id, target_type, target_key),
    ADD CONSTRAINT ck_oauth_revocation_retention CHECK
        ((expires_at IS NULL AND retain_until IS NULL)
         OR (expires_at IS NOT NULL AND retain_until IS NOT NULL
             AND retain_until >= expires_at + INTERVAL '24 hours'));
CREATE INDEX ix_oauth_revocation_retention_v2 ON oauth_revocation (tenant_id, retain_until, id);

-- Final audit rows and immutable receipts share one stable source fingerprint.
ALTER TABLE oauth_audit
    ADD COLUMN event_fingerprint CHAR(64) NOT NULL,
    ADD COLUMN source_client_pk BIGINT,
    ADD COLUMN source_issuer VARCHAR(2048),
    ADD COLUMN retain_until TIMESTAMPTZ(6) NOT NULL,
    ADD CONSTRAINT uk_oauth_audit_tenant_pk UNIQUE (tenant_id, id),
    ADD CONSTRAINT ck_oauth_audit_fingerprint CHECK (event_fingerprint ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT ck_oauth_audit_retention CHECK (retain_until >= occurred_at + INTERVAL '180 days');
CREATE INDEX ix_oauth_audit_retention_v2 ON oauth_audit (tenant_id, retain_until, id);


CREATE TABLE oauth_authentication (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    jti_digest CHAR(64) NOT NULL,
    subject VARCHAR(128) NOT NULL,
    browser_binding_digest CHAR(64) NOT NULL,
    subject_generation BIGINT NOT NULL,
    realm_generation BIGINT NOT NULL,
    authenticated_at TIMESTAMPTZ(6) NOT NULL,
    acr VARCHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',
    expires_at TIMESTAMPTZ(6) NOT NULL,
    retain_until TIMESTAMPTZ(6) NOT NULL,
    revoked_at TIMESTAMPTZ(6),
    reason_code VARCHAR(128),
    CONSTRAINT pk_oauth_authentication PRIMARY KEY (id),
    CONSTRAINT ck_oauth_authentication_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_authentication_version CHECK (version >= 0),
    CONSTRAINT uk_oauth_authentication_jti UNIQUE (tenant_id, jti_digest),
    CONSTRAINT ck_oauth_authentication_digest CHECK
        (jti_digest ~ '^[0-9a-f]{64}$' AND browser_binding_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_oauth_authentication_generation CHECK (subject_generation >= 0 AND realm_generation >= 0),
    CONSTRAINT ck_oauth_authentication_acr CHECK (acr = 'PASSWORD'),
    CONSTRAINT ck_oauth_authentication_status CHECK (status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_oauth_authentication_expiry CHECK
        (expires_at > authenticated_at AND expires_at <= authenticated_at + INTERVAL '8 hours'
         AND retain_until >= expires_at + INTERVAL '24 hours'),
    CONSTRAINT ck_oauth_authentication_revoked CHECK
        ((status = 'REVOKED' AND revoked_at IS NOT NULL AND reason_code IS NOT NULL)
         OR (status <> 'REVOKED' AND revoked_at IS NULL))
);
CREATE INDEX ix_oauth_authentication_subject ON oauth_authentication
    (tenant_id, subject, status, id) WHERE deleted_at IS NULL;
CREATE INDEX ix_oauth_authentication_browser ON oauth_authentication
    (tenant_id, browser_binding_digest, status, id) WHERE deleted_at IS NULL;
CREATE INDEX ix_oauth_authentication_retention ON oauth_authentication (tenant_id, retain_until, id);
ALTER TABLE oauth_authorization ADD CONSTRAINT fk_oauth_authorization_authentication
    FOREIGN KEY (tenant_id, authentication_jti_digest) REFERENCES oauth_authentication (tenant_id, jti_digest);


CREATE TABLE oauth_interaction (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    interaction_id VARCHAR(64) NOT NULL,
    purpose VARCHAR(24) NOT NULL,
    client_pk BIGINT,
    resource_uri VARCHAR(2048),
    redirect_uri VARCHAR(2048),
    request_digest CHAR(64) NOT NULL,
    request_ciphertext TEXT NOT NULL,
    browser_binding_digest CHAR(64) NOT NULL,
    client_browser_binding_digest CHAR(64),
    csrf_digest CHAR(64) NOT NULL,
    requested_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    approved_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    code_challenge VARCHAR(128),
    code_challenge_method VARCHAR(8),
    authentication_jti_digest CHAR(64),
    restricted_subject VARCHAR(128),
    state VARCHAR(24) NOT NULL DEFAULT 'PENDING',
    expires_at TIMESTAMPTZ(6) NOT NULL,
    retain_until TIMESTAMPTZ(6) NOT NULL,
    consumed_at TIMESTAMPTZ(6),
    failure_code VARCHAR(128),
    CONSTRAINT pk_oauth_interaction PRIMARY KEY (id),
    CONSTRAINT ck_oauth_interaction_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_interaction_version CHECK (version >= 0),
    CONSTRAINT uk_oauth_interaction_identity UNIQUE (tenant_id, interaction_id),
    CONSTRAINT fk_oauth_interaction_client FOREIGN KEY (tenant_id, client_pk) REFERENCES oauth_client (tenant_id, id),
    CONSTRAINT fk_oauth_interaction_authentication FOREIGN KEY (tenant_id, authentication_jti_digest)
        REFERENCES oauth_authentication (tenant_id, jti_digest),
    CONSTRAINT ck_oauth_interaction_purpose CHECK (purpose IN ('AUTHORIZATION', 'PASSWORD_CHANGE', 'LOGOUT')),
    CONSTRAINT ck_oauth_interaction_digest CHECK
        (request_digest ~ '^[0-9a-f]{64}$' AND browser_binding_digest ~ '^[0-9a-f]{64}$'
         AND csrf_digest ~ '^[0-9a-f]{64}$'
         AND (client_browser_binding_digest IS NULL OR client_browser_binding_digest ~ '^[0-9a-f]{64}$')
         AND (authentication_jti_digest IS NULL OR authentication_jti_digest ~ '^[0-9a-f]{64}$')),
    CONSTRAINT ck_oauth_interaction_payload CHECK (octet_length(request_ciphertext) BETWEEN 1 AND 131072),
    CONSTRAINT ck_oauth_interaction_scopes CHECK
        (jsonb_typeof(requested_scopes) = 'array' AND jsonb_array_length(requested_scopes) <= 64
         AND jsonb_typeof(approved_scopes) = 'array' AND approved_scopes <@ requested_scopes),
    CONSTRAINT ck_oauth_interaction_authorization CHECK
        (purpose <> 'AUTHORIZATION' OR (client_pk IS NOT NULL AND resource_uri IS NOT NULL
         AND redirect_uri IS NOT NULL AND code_challenge IS NOT NULL
         AND code_challenge_method IS NOT NULL AND code_challenge_method = 'S256')),
    CONSTRAINT ck_oauth_interaction_state CHECK
        (state IN ('PENDING', 'AUTHENTICATED', 'CONSENT_REQUIRED', 'CONSUMED', 'CANCELLED', 'EXPIRED', 'CLOSED')),
    CONSTRAINT ck_oauth_interaction_expiry CHECK
        (expires_at > create_time AND expires_at <= create_time + INTERVAL '5 minutes'
         AND retain_until >= expires_at + INTERVAL '24 hours'),
    CONSTRAINT ck_oauth_interaction_consumption CHECK
        ((state = 'CONSUMED' AND consumed_at IS NOT NULL) OR (state <> 'CONSUMED' AND consumed_at IS NULL))
);
CREATE INDEX ix_oauth_interaction_browser ON oauth_interaction
    (tenant_id, browser_binding_digest, state, expires_at) WHERE deleted_at IS NULL;
CREATE INDEX ix_oauth_interaction_retention ON oauth_interaction (tenant_id, retain_until, id);
ALTER TABLE oauth_authorization ADD CONSTRAINT fk_oauth_authorization_interaction
    FOREIGN KEY (tenant_id, interaction_id) REFERENCES oauth_interaction (tenant_id, interaction_id);


CREATE TABLE oauth_audit_inbox (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    event_id VARCHAR(64) NOT NULL,
    event_fingerprint CHAR(64) NOT NULL,
    schema_version INTEGER NOT NULL,
    source_client_pk BIGINT NOT NULL,
    source_issuer VARCHAR(2048) NOT NULL,
    source_resource_uri VARCHAR(2048) NOT NULL,
    event_payload JSONB NOT NULL,
    occurred_at TIMESTAMPTZ(6) NOT NULL,
    received_at TIMESTAMPTZ(6) NOT NULL,
    state VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ(6) NOT NULL,
    claim_owner VARCHAR(128),
    claim_token VARCHAR(64),
    claim_generation BIGINT NOT NULL DEFAULT 0,
    lease_until TIMESTAMPTZ(6),
    terminal_at TIMESTAMPTZ(6),
    failure_code VARCHAR(128),
    processing_deadline TIMESTAMPTZ(6) NOT NULL,
    retain_until TIMESTAMPTZ(6) NOT NULL,
    CONSTRAINT pk_oauth_audit_inbox PRIMARY KEY (id),
    CONSTRAINT ck_oauth_audit_inbox_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_audit_inbox_version CHECK (version >= 0),
    CONSTRAINT uk_oauth_audit_inbox_identity UNIQUE (tenant_id, event_id),
    CONSTRAINT uk_oauth_audit_inbox_tenant_pk UNIQUE (tenant_id, id),
    CONSTRAINT ck_oauth_audit_inbox_fingerprint CHECK (event_fingerprint ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_oauth_audit_inbox_schema CHECK (schema_version = 1),
    CONSTRAINT ck_oauth_audit_inbox_payload CHECK
        (jsonb_typeof(event_payload) = 'object' AND octet_length(event_payload::text) <= 16384),
    CONSTRAINT ck_oauth_audit_inbox_state CHECK (state IN ('PENDING', 'PROCESSING', 'STORED', 'DEAD', 'EXPIRED')),
    CONSTRAINT ck_oauth_audit_inbox_attempt CHECK (attempt_count >= 0 AND claim_generation >= 0 AND source_client_pk > 0),
    CONSTRAINT ck_oauth_audit_inbox_claim CHECK
        ((state = 'PROCESSING' AND claim_owner IS NOT NULL AND claim_token IS NOT NULL AND lease_until IS NOT NULL
          AND lease_until > received_at AND lease_until <= processing_deadline)
         OR (state <> 'PROCESSING' AND claim_owner IS NULL AND claim_token IS NULL AND lease_until IS NULL)),
    CONSTRAINT ck_oauth_audit_inbox_terminal CHECK
        ((state IN ('STORED', 'DEAD', 'EXPIRED') AND terminal_at IS NOT NULL)
         OR (state IN ('PENDING', 'PROCESSING') AND terminal_at IS NULL)),
    CONSTRAINT ck_oauth_audit_inbox_retention CHECK
        (processing_deadline > received_at AND retain_until >= occurred_at + INTERVAL '180 days'
         AND retain_until >= processing_deadline)
);
CREATE INDEX ix_oauth_audit_inbox_claim ON oauth_audit_inbox
    (tenant_id, state, next_attempt_at, id) WHERE state IN ('PENDING', 'PROCESSING') AND deleted_at IS NULL;
CREATE INDEX ix_oauth_audit_inbox_lease ON oauth_audit_inbox
    (tenant_id, lease_until, id) WHERE state = 'PROCESSING' AND deleted_at IS NULL;
CREATE INDEX ix_oauth_audit_inbox_retention ON oauth_audit_inbox (tenant_id, retain_until, id);


CREATE TABLE oauth_audit_receipt (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    receipt_id VARCHAR(64) NOT NULL,
    inbox_pk BIGINT NOT NULL,
    event_id VARCHAR(64) NOT NULL,
    event_fingerprint CHAR(64) NOT NULL,
    source_client_pk BIGINT NOT NULL,
    source_issuer VARCHAR(2048) NOT NULL,
    source_resource_uri VARCHAR(2048) NOT NULL,
    outcome VARCHAR(16) NOT NULL,
    audit_pk BIGINT,
    confirmed_at TIMESTAMPTZ(6) NOT NULL,
    retain_until TIMESTAMPTZ(6) NOT NULL,
    CONSTRAINT pk_oauth_audit_receipt PRIMARY KEY (id),
    CONSTRAINT ck_oauth_audit_receipt_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_audit_receipt_version CHECK (version >= 0),
    CONSTRAINT uk_oauth_audit_receipt_id UNIQUE (tenant_id, receipt_id),
    CONSTRAINT uk_oauth_audit_receipt_event UNIQUE (tenant_id, event_id),
    CONSTRAINT uk_oauth_audit_receipt_inbox UNIQUE (tenant_id, inbox_pk),
    CONSTRAINT fk_oauth_audit_receipt_inbox FOREIGN KEY (tenant_id, inbox_pk) REFERENCES oauth_audit_inbox (tenant_id, id),
    CONSTRAINT fk_oauth_audit_receipt_audit FOREIGN KEY (tenant_id, audit_pk) REFERENCES oauth_audit (tenant_id, id),
    CONSTRAINT ck_oauth_audit_receipt_fingerprint CHECK (event_fingerprint ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_oauth_audit_receipt_outcome CHECK
        ((outcome = 'STORED' AND audit_pk IS NOT NULL) OR (outcome IN ('DEAD', 'EXPIRED') AND audit_pk IS NULL)),
    CONSTRAINT ck_oauth_audit_receipt_retention CHECK (retain_until > confirmed_at)
);
CREATE INDEX ix_oauth_audit_receipt_retention ON oauth_audit_receipt (tenant_id, retain_until, id);


CREATE TABLE oauth_audit_dead_letter (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    inbox_pk BIGINT NOT NULL,
    event_id VARCHAR(64) NOT NULL,
    event_fingerprint CHAR(64) NOT NULL,
    failure_code VARCHAR(128) NOT NULL,
    attempt_count INTEGER NOT NULL,
    first_received_at TIMESTAMPTZ(6) NOT NULL,
    terminal_at TIMESTAMPTZ(6) NOT NULL,
    retain_until TIMESTAMPTZ(6) NOT NULL,
    CONSTRAINT pk_oauth_audit_dead_letter PRIMARY KEY (id),
    CONSTRAINT ck_oauth_audit_dead_letter_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_audit_dead_letter_version CHECK (version >= 0),
    CONSTRAINT uk_oauth_audit_dead_letter_inbox UNIQUE (tenant_id, inbox_pk),
    CONSTRAINT fk_oauth_audit_dead_letter_inbox FOREIGN KEY (tenant_id, inbox_pk) REFERENCES oauth_audit_inbox (tenant_id, id),
    CONSTRAINT ck_oauth_audit_dead_letter_fingerprint CHECK (event_fingerprint ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_oauth_audit_dead_letter_attempt CHECK (attempt_count >= 0),
    CONSTRAINT ck_oauth_audit_dead_letter_retention CHECK
        (terminal_at >= first_received_at AND retain_until > terminal_at)
);
CREATE INDEX ix_oauth_audit_dead_letter_retention ON oauth_audit_dead_letter (tenant_id, retain_until, id);


-- Outbox tables are deliberately not duplicated here. Reuse the existing
-- egon_outbox.egon_cola_outbox_message owner/history and the same transactionManager.
-- New destinations carry only redacted payloads and stable event IDs; worker leases,
-- attempt counters and permanent failures remain in that PostgreSQL store.
-- Cleanup runs bounded local transactions with row locks/CAS. No in-memory or Redis
-- lease is authoritative. Do not delete a family while an in-scope token/interaction
-- or authentication fact still references it; no cascading deletes are configured.
