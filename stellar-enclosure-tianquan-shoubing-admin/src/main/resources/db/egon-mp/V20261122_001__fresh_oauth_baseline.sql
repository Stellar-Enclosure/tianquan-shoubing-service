-- Clean-schema baseline through 20261028_005. Historical scripts and their checksums stay immutable.
-- The schema/history owner has already verified an empty or managed target before this transaction.
-- Existing complete schemas only record this new version; their existing objects and rows are preserved.
DO $oauth_fresh_baseline$
BEGIN
    IF to_regclass(format('%I.oauth_realm', current_schema())) IS NULL THEN
        EXECUTE $oauth_schema$
-- Source db/egon-mp/V20261008_001__initialize_oauth_tenant_schema.sql SHA-256 238adf24fc3025f27ac5da91528b6110962977762f3ce751467a970a7c6acc23
-- The schema is created and owned by operations. EgonColaPostgreDdlRunner sets
-- a transaction-local search_path to the empty tianquan_oauth schema.

CREATE TABLE oauth_identity_user (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    identity_sub VARCHAR(64) NOT NULL,
    username VARCHAR(128) NOT NULL,
    username_normalized VARCHAR(128) NOT NULL,
    display_name VARCHAR(200) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ(6),
    last_login_at TIMESTAMPTZ(6),
    CONSTRAINT pk_oauth_identity_user PRIMARY KEY (id),
    CONSTRAINT ck_oauth_identity_user_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_identity_user_version CHECK (version >= 0),
    CONSTRAINT ck_oauth_identity_user_failed_logins CHECK (failed_login_count >= 0),
    CONSTRAINT ck_oauth_identity_user_status CHECK (status IN ('ACTIVE', 'DISABLED', 'LOCKED')),
    CONSTRAINT uk_oauth_identity_user_subject_permanent UNIQUE (tenant_id, identity_sub)
);
CREATE UNIQUE INDEX uk_oauth_identity_user_sub_life ON oauth_identity_user (tenant_id, identity_sub, deleted_at);
CREATE UNIQUE INDEX uk_oauth_identity_user_sub_active ON oauth_identity_user (tenant_id, identity_sub) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uk_oauth_identity_user_name_life ON oauth_identity_user (tenant_id, username_normalized, deleted_at);
CREATE UNIQUE INDEX uk_oauth_identity_user_name_active ON oauth_identity_user (tenant_id, username_normalized) WHERE deleted_at IS NULL;
CREATE INDEX ix_oauth_identity_user_lookup ON oauth_identity_user (tenant_id, username_normalized, identity_sub) WHERE deleted_at IS NULL;

CREATE TABLE oauth_identity_credential (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    legacy_id VARCHAR(64) NOT NULL,
    identity_sub VARCHAR(64) NOT NULL,
    credential_type VARCHAR(32) NOT NULL DEFAULT 'PASSWORD',
    password_hash VARCHAR(512) NOT NULL,
    password_changed_at TIMESTAMPTZ(6) NOT NULL,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    CONSTRAINT pk_oauth_identity_credential PRIMARY KEY (id),
    CONSTRAINT ck_oauth_identity_credential_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_identity_credential_version CHECK (version >= 0),
    CONSTRAINT ck_oauth_identity_credential_type CHECK (credential_type = 'PASSWORD'),
    CONSTRAINT ck_oauth_identity_credential_status CHECK (status IN ('ACTIVE', 'REVOKED')),
    CONSTRAINT uk_oauth_identity_credential_legacy_permanent UNIQUE (tenant_id, legacy_id)
);
CREATE UNIQUE INDEX uk_oauth_identity_credential_legacy_life ON oauth_identity_credential (tenant_id, legacy_id, deleted_at);
CREATE UNIQUE INDEX uk_oauth_identity_credential_legacy_active ON oauth_identity_credential (tenant_id, legacy_id) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uk_oauth_identity_credential_sub_life ON oauth_identity_credential (tenant_id, identity_sub, credential_type, deleted_at);
CREATE UNIQUE INDEX uk_oauth_identity_credential_sub_active ON oauth_identity_credential (tenant_id, identity_sub, credential_type) WHERE deleted_at IS NULL;
CREATE INDEX ix_oauth_identity_credential_lookup ON oauth_identity_credential (tenant_id, identity_sub, credential_type) WHERE deleted_at IS NULL;

CREATE TABLE oauth_identity_tenant (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    identity_tenant_id VARCHAR(64) NOT NULL,
    tenant_code VARCHAR(64) NOT NULL,
    tenant_name VARCHAR(200) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'INITIALIZING',
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT pk_oauth_identity_tenant PRIMARY KEY (id),
    CONSTRAINT ck_oauth_identity_tenant_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_identity_tenant_version CHECK (version >= 0),
    CONSTRAINT ck_oauth_identity_tenant_external_id CHECK (
        identity_tenant_id ~ '^[1-9][0-9]*$'
        AND length(identity_tenant_id) <= 19
        AND (length(identity_tenant_id) < 19 OR identity_tenant_id <= '9223372036854775807')
    ),
    CONSTRAINT ck_oauth_identity_tenant_code CHECK (tenant_code ~ '^[a-z][a-z0-9-]{2,63}$'),
    CONSTRAINT ck_oauth_identity_tenant_status CHECK (status IN ('INITIALIZING', 'ACTIVE', 'SUSPENDED', 'CLOSED')),
    CONSTRAINT ck_oauth_identity_tenant_settings CHECK (jsonb_typeof(settings) = 'object' AND pg_column_size(settings) <= 65536),
    CONSTRAINT uk_oauth_identity_tenant_external_permanent UNIQUE (tenant_id, identity_tenant_id)
);
CREATE UNIQUE INDEX uk_oauth_identity_tenant_id_life ON oauth_identity_tenant (tenant_id, identity_tenant_id, deleted_at);
CREATE UNIQUE INDEX uk_oauth_identity_tenant_id_active ON oauth_identity_tenant (tenant_id, identity_tenant_id) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uk_oauth_identity_tenant_code_life ON oauth_identity_tenant (tenant_id, lower(tenant_code), deleted_at);
CREATE UNIQUE INDEX uk_oauth_identity_tenant_code_active ON oauth_identity_tenant (tenant_id, lower(tenant_code)) WHERE deleted_at IS NULL;
CREATE INDEX ix_oauth_identity_tenant_lookup ON oauth_identity_tenant (tenant_id, status, update_time DESC, identity_tenant_id) WHERE deleted_at IS NULL;

CREATE TABLE oauth_identity_membership (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    membership_id VARCHAR(64) NOT NULL,
    identity_tenant_id VARCHAR(64) NOT NULL,
    identity_sub VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    CONSTRAINT pk_oauth_identity_membership PRIMARY KEY (id),
    CONSTRAINT ck_oauth_identity_membership_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_identity_membership_version CHECK (version >= 0),
    CONSTRAINT ck_oauth_identity_membership_tenant_id CHECK (
        identity_tenant_id ~ '^[1-9][0-9]*$'
        AND length(identity_tenant_id) <= 19
        AND (length(identity_tenant_id) < 19 OR identity_tenant_id <= '9223372036854775807')
    ),
    CONSTRAINT ck_oauth_identity_membership_status CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT uk_oauth_identity_membership_external_permanent UNIQUE (tenant_id, membership_id)
);
CREATE UNIQUE INDEX uk_oauth_identity_membership_id_life ON oauth_identity_membership (tenant_id, membership_id, deleted_at);
CREATE UNIQUE INDEX uk_oauth_identity_membership_id_active ON oauth_identity_membership (tenant_id, membership_id) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uk_oauth_identity_membership_tenant_sub_life ON oauth_identity_membership (tenant_id, identity_tenant_id, identity_sub, deleted_at);
CREATE UNIQUE INDEX uk_oauth_identity_membership_tenant_sub_active ON oauth_identity_membership (tenant_id, identity_tenant_id, identity_sub) WHERE deleted_at IS NULL;
CREATE INDEX ix_oauth_identity_membership_by_subject ON oauth_identity_membership (tenant_id, identity_sub, update_time DESC, identity_tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX ix_oauth_identity_membership_by_tenant ON oauth_identity_membership (tenant_id, identity_tenant_id, update_time DESC, identity_sub) WHERE deleted_at IS NULL;

CREATE TABLE oauth_realm (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    issuer VARCHAR(2048) NOT NULL,
    realm_key VARCHAR(64) NOT NULL,
    realm_type VARCHAR(16) NOT NULL,
    business_tenant_id BIGINT,
    storage_partition_id BIGINT NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'INITIALIZING',
    active_kid VARCHAR(128),
    trust_version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT pk_oauth_realm PRIMARY KEY (id),
    CONSTRAINT ck_oauth_realm_partition CHECK (tenant_id > 0 AND storage_partition_id > 0 AND tenant_id = storage_partition_id),
    CONSTRAINT ck_oauth_realm_version CHECK (version >= 0 AND trust_version >= 0),
    CONSTRAINT ck_oauth_realm_type CHECK (realm_type IN ('TENANT', 'PLATFORM')),
    CONSTRAINT ck_oauth_realm_status CHECK (status IN ('INITIALIZING', 'ACTIVE', 'SUSPENDED', 'CLOSED')),
    CONSTRAINT ck_oauth_realm_business_tenant CHECK ((realm_type = 'TENANT' AND business_tenant_id > 0) OR (realm_type = 'PLATFORM' AND business_tenant_id IS NULL)),
    CONSTRAINT uk_oauth_realm_issuer_permanent UNIQUE (tenant_id, issuer),
    CONSTRAINT uk_oauth_realm_partition_permanent UNIQUE (tenant_id, storage_partition_id)
);
CREATE UNIQUE INDEX uk_realm_1_life ON oauth_realm (tenant_id, issuer, deleted_at);
CREATE UNIQUE INDEX uk_realm_1_active ON oauth_realm (tenant_id, issuer) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uk_realm_2_life ON oauth_realm (tenant_id, realm_key, deleted_at);
CREATE UNIQUE INDEX uk_realm_2_active ON oauth_realm (tenant_id, realm_key) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uk_realm_3_life ON oauth_realm (tenant_id, storage_partition_id, deleted_at);
CREATE UNIQUE INDEX uk_realm_3_active ON oauth_realm (tenant_id, storage_partition_id) WHERE deleted_at IS NULL;
CREATE INDEX ix_realm_access ON oauth_realm (status, realm_key) WHERE deleted_at IS NULL;

CREATE TABLE oauth_client (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    client_id VARCHAR(128) NOT NULL,
    app_id VARCHAR(128),
    client_name VARCHAR(200) NOT NULL,
    client_type VARCHAR(16) NOT NULL,
    purpose VARCHAR(16) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',
    secret_hash VARCHAR(512),
    secret_hint VARCHAR(8),
    credential_version BIGINT NOT NULL DEFAULT 0,
    redirect_uris JSONB NOT NULL DEFAULT '[]'::jsonb,
    resource_uris JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    access_ttl_seconds INTEGER NOT NULL DEFAULT 300,
    refresh_ttl_seconds INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT pk_oauth_client PRIMARY KEY (id),
    CONSTRAINT ck_oauth_client_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_client_version CHECK (version >= 0 AND credential_version >= 0),
    CONSTRAINT ck_oauth_client_type CHECK (client_type IN ('PUBLIC', 'CONFIDENTIAL')),
    CONSTRAINT ck_oauth_client_purpose CHECK (purpose IN ('USER', 'SERVICE')),
    CONSTRAINT ck_oauth_client_status CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT ck_oauth_client_redirects CHECK (jsonb_typeof(redirect_uris) = 'array'),
    CONSTRAINT ck_oauth_client_resources CHECK (jsonb_typeof(resource_uris) = 'array'),
    CONSTRAINT ck_oauth_client_scopes CHECK (jsonb_typeof(allowed_scopes) = 'array'),
    CONSTRAINT ck_oauth_client_access_ttl CHECK (access_ttl_seconds BETWEEN 300 AND 600),
    CONSTRAINT ck_oauth_client_refresh_ttl CHECK (refresh_ttl_seconds = 0 OR (client_type = 'CONFIDENTIAL' AND purpose = 'USER' AND refresh_ttl_seconds BETWEEN 3600 AND 604800)),
    CONSTRAINT uk_oauth_client_identity_permanent UNIQUE (tenant_id, client_id)
);
CREATE UNIQUE INDEX uk_client_1_life ON oauth_client (tenant_id, client_id, deleted_at);
CREATE UNIQUE INDEX uk_client_1_active ON oauth_client (tenant_id, client_id) WHERE deleted_at IS NULL;
CREATE INDEX ix_client_access ON oauth_client (tenant_id, client_id) WHERE deleted_at IS NULL;

CREATE TABLE oauth_grant (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    client_pk BIGINT NOT NULL,
    resource_server_id VARCHAR(128) NOT NULL,
    grant_type VARCHAR(32) NOT NULL,
    allowed_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',
    resource_version BIGINT NOT NULL,
    CONSTRAINT pk_oauth_grant PRIMARY KEY (id),
    CONSTRAINT ck_oauth_grant_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_grant_version CHECK (version >= 0 AND resource_version >= 0),
    CONSTRAINT ck_oauth_grant_type CHECK (grant_type IN ('USER_DELEGATION', 'CLIENT_CREDENTIALS')),
    CONSTRAINT ck_oauth_grant_status CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT ck_oauth_grant_scopes CHECK (jsonb_typeof(allowed_scopes) = 'array')
);
CREATE UNIQUE INDEX uk_grant_1_life ON oauth_grant (tenant_id, client_pk, resource_server_id, grant_type, deleted_at);
CREATE UNIQUE INDEX uk_grant_1_active ON oauth_grant (tenant_id, client_pk, resource_server_id, grant_type) WHERE deleted_at IS NULL;
CREATE INDEX ix_grant_access ON oauth_grant (tenant_id, client_pk, resource_server_id) WHERE deleted_at IS NULL;

CREATE TABLE oauth_authorization (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    client_pk BIGINT NOT NULL,
    principal_name VARCHAR(128) NOT NULL,
    principal_type VARCHAR(16) NOT NULL,
    grant_type VARCHAR(32) NOT NULL,
    authorized_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    audiences JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',
    auth_time TIMESTAMPTZ(6),
    acr VARCHAR(64),
    attributes_ciphertext TEXT NOT NULL,
    absolute_expires_at TIMESTAMPTZ(6) NOT NULL,
    revoked_at TIMESTAMPTZ(6),
    CONSTRAINT pk_oauth_authorization PRIMARY KEY (id),
    CONSTRAINT ck_oauth_authorization_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_authorization_version CHECK (version >= 0),
    CONSTRAINT ck_oauth_authorization_principal CHECK (principal_type IN ('USER', 'SERVICE')),
    CONSTRAINT ck_oauth_authorization_grant CHECK (grant_type IN ('authorization_code', 'client_credentials')),
    CONSTRAINT ck_oauth_authorization_status CHECK (status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
    CONSTRAINT ck_oauth_authorization_scopes CHECK (jsonb_typeof(authorized_scopes) = 'array'),
    CONSTRAINT ck_oauth_authorization_audiences CHECK (jsonb_typeof(audiences) = 'array'),
    CONSTRAINT ck_oauth_authorization_expiry CHECK (absolute_expires_at > create_time)
);
CREATE INDEX ix_authorization_access ON oauth_authorization (tenant_id, principal_name, status, id) WHERE deleted_at IS NULL;
CREATE INDEX ix_authorization_retention ON oauth_authorization (tenant_id, absolute_expires_at, id);

CREATE TABLE oauth_token (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    authorization_pk BIGINT NOT NULL,
    token_type VARCHAR(16) NOT NULL,
    token_digest CHAR(64) NOT NULL,
    token_ciphertext TEXT,
    jti VARCHAR(64),
    issued_at TIMESTAMPTZ(6) NOT NULL,
    expires_at TIMESTAMPTZ(6) NOT NULL,
    consumed_at TIMESTAMPTZ(6),
    revoked_at TIMESTAMPTZ(6),
    metadata_ciphertext TEXT NOT NULL,
    CONSTRAINT pk_oauth_token PRIMARY KEY (id),
    CONSTRAINT ck_oauth_token_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_token_version CHECK (version >= 0),
    CONSTRAINT ck_oauth_token_type CHECK (token_type IN ('ACCESS', 'REFRESH', 'ID_TOKEN', 'AUTHORIZATION_CODE')),
    CONSTRAINT ck_oauth_token_digest CHECK (token_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_oauth_token_jti CHECK (token_type NOT IN ('ACCESS', 'ID_TOKEN') OR jti IS NOT NULL),
    CONSTRAINT ck_oauth_token_expiry CHECK (expires_at > issued_at),
    CONSTRAINT uk_oauth_token_digest_permanent UNIQUE (tenant_id, token_digest)
);
CREATE UNIQUE INDEX uk_token_1_life ON oauth_token (tenant_id, token_digest, deleted_at);
CREATE UNIQUE INDEX uk_token_1_active ON oauth_token (tenant_id, token_digest) WHERE deleted_at IS NULL;
CREATE INDEX ix_token_access ON oauth_token (tenant_id, authorization_pk, token_type) WHERE deleted_at IS NULL;
CREATE INDEX ix_token_retention ON oauth_token (tenant_id, expires_at, id);

CREATE TABLE oauth_consent (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    client_pk BIGINT NOT NULL,
    subject VARCHAR(128) NOT NULL,
    authorities JSONB NOT NULL DEFAULT '[]'::jsonb,
    granted_at TIMESTAMPTZ(6) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',
    CONSTRAINT pk_oauth_consent PRIMARY KEY (id),
    CONSTRAINT ck_oauth_consent_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_consent_version CHECK (version >= 0),
    CONSTRAINT ck_oauth_consent_authorities CHECK (jsonb_typeof(authorities) = 'array'),
    CONSTRAINT ck_oauth_consent_status CHECK (status IN ('ACTIVE', 'REVOKED'))
);
CREATE UNIQUE INDEX uk_consent_1_life ON oauth_consent (tenant_id, client_pk, subject, deleted_at);
CREATE UNIQUE INDEX uk_consent_1_active ON oauth_consent (tenant_id, client_pk, subject) WHERE deleted_at IS NULL;
CREATE INDEX ix_consent_access ON oauth_consent (tenant_id, client_pk, subject) WHERE deleted_at IS NULL;

CREATE TABLE oauth_signing_key (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    kid VARCHAR(128) NOT NULL,
    algorithm VARCHAR(16) NOT NULL DEFAULT 'RS256',
    public_jwk JSONB NOT NULL,
    private_key_ciphertext TEXT NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'PUBLISHED',
    published_at TIMESTAMPTZ(6) NOT NULL,
    activated_at TIMESTAMPTZ(6),
    last_issued_at TIMESTAMPTZ(6),
    verify_until TIMESTAMPTZ(6),
    retired_at TIMESTAMPTZ(6),
    CONSTRAINT pk_oauth_signing_key PRIMARY KEY (id),
    CONSTRAINT ck_oauth_signing_key_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_signing_key_version CHECK (version >= 0),
    CONSTRAINT ck_oauth_signing_key_algorithm CHECK (algorithm = 'RS256'),
    CONSTRAINT ck_oauth_signing_key_jwk CHECK (jsonb_typeof(public_jwk) = 'object'),
    CONSTRAINT ck_oauth_signing_key_status CHECK (status IN ('PUBLISHED', 'ACTIVE', 'VERIFY_ONLY', 'RETIRED', 'COMPROMISED')),
    CONSTRAINT uk_oauth_signing_key_kid_permanent UNIQUE (tenant_id, kid)
);
CREATE UNIQUE INDEX uk_signing_key_1_life ON oauth_signing_key (tenant_id, kid, deleted_at);
CREATE UNIQUE INDEX uk_signing_key_1_active ON oauth_signing_key (tenant_id, kid) WHERE deleted_at IS NULL;
CREATE INDEX ix_signing_key_access ON oauth_signing_key (tenant_id, status, kid) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uk_key_one_active ON oauth_signing_key (tenant_id) WHERE status = 'ACTIVE' AND deleted_at IS NULL;

CREATE TABLE oauth_security_state (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    target_type VARCHAR(16) NOT NULL,
    target_key VARCHAR(128) NOT NULL,
    generation BIGINT NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    revision BIGINT NOT NULL DEFAULT 0,
    reason_code VARCHAR(128) NOT NULL DEFAULT 'INITIALIZED',
    CONSTRAINT pk_oauth_security_state PRIMARY KEY (id),
    CONSTRAINT ck_oauth_security_state_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_security_state_version CHECK (version >= 0 AND generation >= 0 AND revision >= 0),
    CONSTRAINT ck_oauth_security_state_target CHECK (target_type IN ('REALM', 'CLIENT', 'SUBJECT'))
);
CREATE UNIQUE INDEX uk_security_state_1_life ON oauth_security_state (tenant_id, target_type, target_key, deleted_at);
CREATE UNIQUE INDEX uk_security_state_1_active ON oauth_security_state (tenant_id, target_type, target_key) WHERE deleted_at IS NULL;
CREATE INDEX ix_security_state_access ON oauth_security_state (tenant_id, revision) WHERE deleted_at IS NULL;

CREATE TABLE oauth_revocation (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    target_type VARCHAR(16) NOT NULL,
    target_key VARCHAR(128) NOT NULL,
    reason_code VARCHAR(128) NOT NULL,
    revoked_at TIMESTAMPTZ(6) NOT NULL,
    expires_at TIMESTAMPTZ(6),
    revision BIGINT NOT NULL,
    projection_status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    CONSTRAINT pk_oauth_revocation PRIMARY KEY (id),
    CONSTRAINT ck_oauth_revocation_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_revocation_version CHECK (version >= 0 AND revision >= 0),
    CONSTRAINT ck_oauth_revocation_target CHECK (target_type IN ('JTI', 'AUTHORIZATION', 'KID')),
    CONSTRAINT ck_oauth_revocation_projection CHECK (projection_status IN ('PENDING', 'APPLIED')),
    CONSTRAINT ck_oauth_revocation_expiry CHECK (expires_at IS NULL OR expires_at > revoked_at)
);
CREATE UNIQUE INDEX uk_revocation_1_life ON oauth_revocation (tenant_id, target_type, target_key, deleted_at);
CREATE UNIQUE INDEX uk_revocation_1_active ON oauth_revocation (tenant_id, target_type, target_key) WHERE deleted_at IS NULL;
CREATE INDEX ix_revocation_access ON oauth_revocation (tenant_id, revision) WHERE deleted_at IS NULL;
CREATE INDEX ix_revocation_retention ON oauth_revocation (tenant_id, expires_at, id);

CREATE TABLE oauth_audit (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    event_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    subject_ref VARCHAR(128),
    client_ref VARCHAR(128),
    token_ref CHAR(64),
    resource_ref VARCHAR(2048),
    result VARCHAR(16) NOT NULL,
    reason_code VARCHAR(128) NOT NULL,
    trace_id VARCHAR(128),
    occurred_at TIMESTAMPTZ(6) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    audit_kind VARCHAR(16) NOT NULL DEFAULT 'OAUTH',
    public_id VARCHAR(64) NOT NULL,
    actor_sub VARCHAR(64),
    target_sub VARCHAR(64),
    identity_tenant_id VARCHAR(64),
    CONSTRAINT pk_oauth_audit PRIMARY KEY (id),
    CONSTRAINT ck_oauth_audit_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_audit_version CHECK (version >= 0),
    CONSTRAINT ck_oauth_audit_result CHECK (result IN ('SUCCESS', 'DENIED', 'FAILED', 'FAILURE')),
    CONSTRAINT ck_oauth_audit_kind CHECK (audit_kind IN ('OAUTH', 'IDENTITY')),
    CONSTRAINT ck_oauth_audit_payload CHECK (jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 16384),
    CONSTRAINT ck_oauth_audit_token_ref CHECK (token_ref IS NULL OR token_ref ~ '^[0-9a-f]{64}$'),
    CONSTRAINT uk_oauth_audit_event_permanent UNIQUE (tenant_id, event_id)
);
CREATE UNIQUE INDEX uk_audit_1_life ON oauth_audit (tenant_id, event_id, deleted_at);
CREATE UNIQUE INDEX uk_audit_1_active ON oauth_audit (tenant_id, event_id) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uk_audit_public_id_life ON oauth_audit (tenant_id, public_id, deleted_at);
CREATE UNIQUE INDEX uk_audit_public_id_active ON oauth_audit (tenant_id, public_id) WHERE deleted_at IS NULL;
CREATE INDEX ix_audit_access ON oauth_audit (tenant_id, occurred_at DESC, id DESC) WHERE deleted_at IS NULL;
CREATE INDEX ix_audit_retention ON oauth_audit (tenant_id, occurred_at, id);
CREATE INDEX ix_audit_identity_page ON oauth_audit (tenant_id, occurred_at DESC, public_id DESC) WHERE audit_kind = 'IDENTITY' AND deleted_at IS NULL;
CREATE INDEX ix_audit_identity_actor ON oauth_audit (tenant_id, actor_sub, occurred_at DESC, public_id DESC) WHERE audit_kind = 'IDENTITY' AND deleted_at IS NULL;

CREATE TABLE oauth_resource (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    resource_server_id VARCHAR(128) NOT NULL,
    resource_uri VARCHAR(2048) NOT NULL,
    biz_code VARCHAR(128) NOT NULL,
    app_code VARCHAR(128) NOT NULL,
    environment VARCHAR(128) NOT NULL,
    display_name VARCHAR(200) NOT NULL,
    management_client_id VARCHAR(128) NOT NULL,
    management_client_pk BIGINT NOT NULL,
    rbac_application_code VARCHAR(128) NOT NULL,
    entry_permission_code VARCHAR(256) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',
    admission_ticket_ttl_seconds INTEGER NOT NULL DEFAULT 300,
    CONSTRAINT pk_oauth_resource PRIMARY KEY (id),
    CONSTRAINT ck_oauth_resource_partition CHECK (tenant_id > 0),
    CONSTRAINT ck_oauth_resource_version CHECK (version >= 0),
    CONSTRAINT ck_oauth_resource_status CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT ck_oauth_resource_ticket_ttl CHECK (admission_ticket_ttl_seconds BETWEEN 30 AND 900),
    CONSTRAINT uk_oauth_resource_server_permanent UNIQUE (tenant_id, resource_server_id),
    CONSTRAINT uk_oauth_resource_uri_permanent UNIQUE (tenant_id, resource_uri),
    CONSTRAINT uk_oauth_resource_app_permanent UNIQUE (tenant_id, biz_code, app_code, environment),
    CONSTRAINT uk_oauth_resource_manager_permanent UNIQUE (tenant_id, management_client_pk)
);
CREATE UNIQUE INDEX uk_resource_1_life ON oauth_resource (tenant_id, resource_server_id, deleted_at);
CREATE UNIQUE INDEX uk_resource_1_active ON oauth_resource (tenant_id, resource_server_id) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uk_resource_2_life ON oauth_resource (tenant_id, resource_uri, deleted_at);
CREATE UNIQUE INDEX uk_resource_2_active ON oauth_resource (tenant_id, resource_uri) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uk_resource_3_life ON oauth_resource (tenant_id, biz_code, app_code, environment, deleted_at);
CREATE UNIQUE INDEX uk_resource_3_active ON oauth_resource (tenant_id, biz_code, app_code, environment) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uk_resource_4_life ON oauth_resource (tenant_id, management_client_pk, deleted_at);
CREATE UNIQUE INDEX uk_resource_4_active ON oauth_resource (tenant_id, management_client_pk) WHERE deleted_at IS NULL;

-- Source db/egon-mp/V20261009_001__support_oauth_consent_state.sql SHA-256 89210d641e6018b5c1e87a394bbe9d99eb90f64a7f86217ce2ec40a90afad5db
ALTER TABLE oauth_token ALTER COLUMN token_type TYPE VARCHAR(32);
ALTER TABLE oauth_token DROP CONSTRAINT ck_oauth_token_type;
ALTER TABLE oauth_token ADD CONSTRAINT ck_oauth_token_type
    CHECK (token_type IN ('ACCESS', 'REFRESH', 'ID_TOKEN', 'AUTHORIZATION_CODE', 'CONSENT_STATE'));

-- Source db/egon-mp/V20261023_001__stateless_oauth_state.sql SHA-256 21134dca1334ff8af42ac455fd3b2b584f06c29f92846a7bf565a1625115ea13
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

-- Source db/egon-mp/V20261027_001__add_device_sessions.sql SHA-256 560c3293eb5ed128294b82289500d9395d3bfdb5c7a2ed137a3f4f5ddcbfb948
-- Independent client sessions under one SSO authentication; active roles remain account-scoped.
-- The managed runner supplies the transaction-local tianquan_oauth search_path.
CREATE TABLE oauth_device_session (
    id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    client_pk BIGINT NOT NULL,
    subject VARCHAR(128) NOT NULL,
    authentication_jti_digest CHAR(64) NOT NULL,
    authenticated_at TIMESTAMPTZ(6) NOT NULL,
    expires_at TIMESTAMPTZ(6) NOT NULL,
    user_agent VARCHAR(512),
    ip_address VARCHAR(64),
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',
    revoked_at TIMESTAMPTZ(6),
    reason_code VARCHAR(128),
    CONSTRAINT pk_oauth_device_session PRIMARY KEY (id),
    CONSTRAINT uk_oauth_device_session_partition UNIQUE (tenant_id, id),
    CONSTRAINT uk_oauth_device_session_authentication UNIQUE (tenant_id, client_pk, authentication_jti_digest),
    CONSTRAINT fk_oauth_device_session_client FOREIGN KEY (tenant_id, client_pk) REFERENCES oauth_client (tenant_id, id),
    CONSTRAINT fk_oauth_device_session_authentication FOREIGN KEY (tenant_id, authentication_jti_digest)
        REFERENCES oauth_authentication (tenant_id, jti_digest),
    CONSTRAINT ck_oauth_device_session_version CHECK (version >= 0 AND tenant_id > 0),
    CONSTRAINT ck_oauth_device_session_expiry CHECK (expires_at > authenticated_at),
    CONSTRAINT ck_oauth_device_session_status CHECK
        ((status = 'ACTIVE' AND revoked_at IS NULL) OR (status = 'REVOKED' AND revoked_at IS NOT NULL AND reason_code IS NOT NULL))
);
CREATE INDEX ix_oauth_device_session_subject ON oauth_device_session
    (tenant_id, subject, status, authenticated_at, id) WHERE deleted_at IS NULL;

ALTER TABLE oauth_authorization ADD COLUMN device_session_id BIGINT;

-- Preserve existing credentials, authorization families and revocation state.
INSERT INTO oauth_device_session
    (id, tenant_id, create_time, create_user_id, update_time, update_user_id, client_pk, subject,
     authentication_jti_digest, authenticated_at, expires_at, status, revoked_at, reason_code)
SELECT MIN(id), tenant_id, MIN(create_time), 'service:tianquan-shoubing', MAX(update_time), 'service:tianquan-shoubing',
       client_pk, principal_name, authentication_jti_digest, MIN(COALESCE(auth_time, create_time)), MAX(absolute_expires_at),
       CASE WHEN BOOL_OR(status IN ('ACTIVE', 'PENDING_CONSENT')) THEN 'ACTIVE' ELSE 'REVOKED' END,
       CASE WHEN BOOL_OR(status IN ('ACTIVE', 'PENDING_CONSENT')) THEN NULL ELSE MAX(update_time) END,
       CASE WHEN BOOL_OR(status IN ('ACTIVE', 'PENDING_CONSENT')) THEN NULL ELSE 'MIGRATED_CLOSED_SESSION' END
FROM oauth_authorization
WHERE principal_type = 'USER' AND deleted_at IS NULL
GROUP BY tenant_id, client_pk, principal_name, authentication_jti_digest;

UPDATE oauth_authorization a SET device_session_id = s.id
FROM oauth_device_session s
WHERE a.tenant_id = s.tenant_id AND a.client_pk = s.client_pk
  AND a.authentication_jti_digest = s.authentication_jti_digest
  AND a.principal_type = 'USER' AND a.deleted_at IS NULL;

ALTER TABLE oauth_authorization ADD CONSTRAINT fk_oauth_authorization_device_session
    FOREIGN KEY (tenant_id, device_session_id) REFERENCES oauth_device_session (tenant_id, id);
CREATE INDEX ix_oauth_authorization_device_session ON oauth_authorization
    (tenant_id, device_session_id, status, id) WHERE deleted_at IS NULL;

-- Apply the same five-session policy to already established, currently valid sessions.
WITH ranked AS (
    SELECT s.id, ROW_NUMBER() OVER (PARTITION BY s.tenant_id, s.subject ORDER BY s.authenticated_at DESC, s.id DESC) AS position
    FROM oauth_device_session s
    JOIN oauth_authentication a ON a.tenant_id = s.tenant_id AND a.jti_digest = s.authentication_jti_digest
    JOIN oauth_security_state u ON u.tenant_id = s.tenant_id AND u.target_type = 'SUBJECT' AND u.target_key = s.subject
    JOIN oauth_security_state r ON r.tenant_id = s.tenant_id AND r.target_type = 'REALM' AND r.target_key = 'self'
    WHERE s.status = 'ACTIVE' AND s.expires_at > CURRENT_TIMESTAMP AND a.deleted_at IS NULL AND a.status <> 'REVOKED'
      AND u.deleted_at IS NULL AND r.deleted_at IS NULL AND u.enabled AND r.enabled
      AND a.subject_generation = u.generation AND a.realm_generation = r.generation
      AND EXISTS (SELECT 1 FROM oauth_authorization g WHERE g.tenant_id = s.tenant_id AND g.device_session_id = s.id
                  AND g.status = 'ACTIVE' AND g.absolute_expires_at > CURRENT_TIMESTAMP AND g.deleted_at IS NULL)
)
UPDATE oauth_device_session s
SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP, reason_code = 'DEVICE_SESSION_LIMIT_MIGRATION',
    version = s.version + 1, update_time = CURRENT_TIMESTAMP, update_user_id = 'service:tianquan-shoubing'
FROM ranked WHERE s.id = ranked.id AND ranked.position > 5;

UPDATE oauth_authorization g
SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP, version = g.version + 1,
    update_time = CURRENT_TIMESTAMP, update_user_id = 'service:tianquan-shoubing'
FROM oauth_device_session s
WHERE g.tenant_id = s.tenant_id AND g.device_session_id = s.id AND s.reason_code = 'DEVICE_SESSION_LIMIT_MIGRATION'
  AND g.status IN ('ACTIVE', 'PENDING_CONSENT') AND g.deleted_at IS NULL;

-- Source db/egon-mp/V20261028_001__coordinate_oauth_grant_writes.sql SHA-256 4aa6eeed522b092a484849238de3117baf8fee3de752e335edca85c7404fa34f
-- Keep grant writes serialized with issuance without changing the grant's business version.
CREATE FUNCTION oauth_coordinate_grant_client() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND (OLD.tenant_id, OLD.client_pk) <> (NEW.tenant_id, NEW.client_pk) THEN
        IF (OLD.tenant_id, OLD.client_pk) < (NEW.tenant_id, NEW.client_pk) THEN
            UPDATE oauth_client SET version = version WHERE tenant_id = OLD.tenant_id AND id = OLD.client_pk;
            UPDATE oauth_client SET version = version WHERE tenant_id = NEW.tenant_id AND id = NEW.client_pk;
        ELSE
            UPDATE oauth_client SET version = version WHERE tenant_id = NEW.tenant_id AND id = NEW.client_pk;
            UPDATE oauth_client SET version = version WHERE tenant_id = OLD.tenant_id AND id = OLD.client_pk;
        END IF;
    ELSE
        UPDATE oauth_client SET version = version
         WHERE tenant_id = CASE WHEN TG_OP = 'DELETE' THEN OLD.tenant_id ELSE NEW.tenant_id END
           AND id = CASE WHEN TG_OP = 'DELETE' THEN OLD.client_pk ELSE NEW.client_pk END;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER tr_oauth_grant_client_fence
    BEFORE INSERT OR UPDATE OR DELETE ON oauth_grant
    FOR EACH ROW EXECUTE FUNCTION oauth_coordinate_grant_client();

-- Source db/egon-mp/V20261028_002__subject_revocation_fanout.sql SHA-256 b71c431fa3f51a5bd135927ca45e61ee000936d34ee5c0a607b0289ada604167
-- Preserve every subject-to-tenant association so a removed membership cannot hide old tokens.
CREATE TABLE oauth_subject_tenant_history (
    tenant_id BIGINT NOT NULL,
    identity_sub VARCHAR(64) NOT NULL,
    identity_tenant_id BIGINT NOT NULL CHECK (identity_tenant_id > 0),
    deleted_at TIMESTAMP(6),
    CONSTRAINT pk_oauth_subject_tenant_history PRIMARY KEY (tenant_id, identity_sub, identity_tenant_id),
    CONSTRAINT ck_oauth_subject_tenant_history_active CHECK (deleted_at IS NULL)
);

-- Keep the backfill and trigger installation atomic with respect to membership writes.
LOCK TABLE oauth_identity_membership IN SHARE ROW EXCLUSIVE MODE;

INSERT INTO oauth_subject_tenant_history (tenant_id, identity_sub, identity_tenant_id, deleted_at)
SELECT DISTINCT tenant_id, identity_sub, CAST(identity_tenant_id AS BIGINT), CAST(NULL AS TIMESTAMP) FROM oauth_identity_membership;

CREATE FUNCTION oauth_coordinate_subject_membership() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.tenant_id <> NEW.tenant_id THEN
        UPDATE oauth_realm SET version = version WHERE tenant_id = LEAST(OLD.tenant_id, NEW.tenant_id)
            AND realm_key = 'platform' AND deleted_at IS NULL;
        UPDATE oauth_realm SET version = version WHERE tenant_id = GREATEST(OLD.tenant_id, NEW.tenant_id)
            AND realm_key = 'platform' AND deleted_at IS NULL;
    ELSE
        UPDATE oauth_realm SET version = version
         WHERE tenant_id = CASE WHEN TG_OP = 'DELETE' THEN OLD.tenant_id ELSE NEW.tenant_id END
           AND realm_key = 'platform' AND deleted_at IS NULL;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        INSERT INTO oauth_subject_tenant_history (tenant_id, identity_sub, identity_tenant_id, deleted_at)
        VALUES (NEW.tenant_id, NEW.identity_sub, CAST(NEW.identity_tenant_id AS BIGINT), NULL)
        ON CONFLICT (tenant_id, identity_sub, identity_tenant_id) DO NOTHING;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER tr_oauth_subject_membership_fence
    BEFORE INSERT OR UPDATE OR DELETE ON oauth_identity_membership
    FOR EACH ROW EXECUTE FUNCTION oauth_coordinate_subject_membership();

ALTER TABLE oauth_security_state ADD COLUMN directory_subject_revision BIGINT NOT NULL DEFAULT 0
    CHECK (directory_subject_revision >= 0),
    ADD COLUMN directory_subject_fingerprint CHAR(64),
    ADD CONSTRAINT ck_oauth_subject_source_fingerprint CHECK (
        (directory_subject_revision = 0 AND directory_subject_fingerprint IS NULL)
        OR (target_type = 'SUBJECT' AND directory_subject_revision > 0 AND directory_subject_fingerprint IS NOT NULL
            AND directory_subject_fingerprint ~ '^[0-9a-f]{64}$')
    );

CREATE TABLE oauth_subject_revocation_task (
    id BIGINT NOT NULL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    identity_sub VARCHAR(64) NOT NULL,
    target_tenant_id VARCHAR(64) NOT NULL,
    source_revision BIGINT NOT NULL,
    subject_enabled BOOLEAN NOT NULL,
    reason_code VARCHAR(128) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    next_attempt_at TIMESTAMPTZ(6) NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    lease_owner VARCHAR(64),
    lease_until TIMESTAMPTZ(6),
    CONSTRAINT ck_oauth_subject_task_partition CHECK (tenant_id > 0 AND version >= 0 AND source_revision > 0),
    CONSTRAINT ck_oauth_subject_task_status CHECK (status IN ('PENDING', 'LEASED', 'DONE')),
    CONSTRAINT ck_oauth_subject_task_lease CHECK ((status = 'LEASED' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL)
        OR (status IN ('PENDING', 'DONE') AND lease_owner IS NULL AND lease_until IS NULL)),
    CONSTRAINT uk_oauth_subject_task UNIQUE (tenant_id, identity_sub, target_tenant_id, source_revision)
);
CREATE INDEX ix_oauth_subject_task_due ON oauth_subject_revocation_task
    (tenant_id, status, next_attempt_at, lease_until, id) WHERE deleted_at IS NULL;

-- Source db/egon-mp/V20261028_003__password_change_receipt.sql SHA-256 288e7175b9f6228588442daac7ef1d1e342e1eaada4ec30e836feafac26799af
-- A receipt and the password change commit together in the identity directory partition.
CREATE TABLE oauth_password_change_receipt (
    id BIGINT NOT NULL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    operation_key CHAR(64) NOT NULL,
    identity_sub VARCHAR(64) NOT NULL,
    origin_tenant_id BIGINT NOT NULL,
    CONSTRAINT ck_oauth_password_receipt_scope CHECK (tenant_id > 0 AND origin_tenant_id > 0 AND version = 0 AND deleted_at IS NULL),
    CONSTRAINT ck_oauth_password_receipt_key CHECK (operation_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT uk_oauth_password_receipt_operation UNIQUE (tenant_id, operation_key)
);

-- Source db/egon-mp/V20261028_004__ordered_subject_delivery.sql SHA-256 2c7b1f2e57ce58f8c9098059593065bc0b2b0b317be7e82614959a41cbf31b6d
-- Existing subject projections start a new delivery chain after this migration.
ALTER TABLE oauth_security_state ADD COLUMN directory_subject_ordered_revision BIGINT NOT NULL DEFAULT 0,
    ADD CONSTRAINT ck_oauth_subject_ordered_revision CHECK
        (directory_subject_ordered_revision >= 0 AND directory_subject_ordered_revision <= directory_subject_revision);

CREATE TABLE oauth_subject_delivery_receipt (
    id BIGINT NOT NULL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    event_id VARCHAR(64) NOT NULL,
    identity_sub VARCHAR(64) NOT NULL,
    source_revision BIGINT NOT NULL,
    previous_revision BIGINT NOT NULL,
    payload_fingerprint CHAR(64) NOT NULL,
    CONSTRAINT ck_oauth_subject_delivery_scope CHECK (tenant_id > 0 AND version = 0 AND source_revision > 0
        AND previous_revision >= 0 AND previous_revision < source_revision AND deleted_at IS NULL),
    CONSTRAINT ck_oauth_subject_delivery_fingerprint CHECK (payload_fingerprint ~ '^[0-9a-f]{64}$'),
    CONSTRAINT uk_oauth_subject_delivery_event UNIQUE (tenant_id, event_id),
    CONSTRAINT uk_oauth_subject_delivery_revision UNIQUE (tenant_id, identity_sub, source_revision)
);

-- Source db/egon-mp/V20261028_005__coordinate_resource_grants.sql SHA-256 d24d3731048e02eb31f55caf16abbc8a901a9e3889052bcbddba541c055ec24a
-- Resource mutations and cross-shard grant operations serialize through this technical row.
CREATE TABLE oauth_resource_fence (
    id BIGINT NOT NULL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    create_time TIMESTAMPTZ(6) NOT NULL,
    create_user_id VARCHAR(128) NOT NULL,
    update_time TIMESTAMPTZ(6) NOT NULL,
    update_user_id VARCHAR(128) NOT NULL,
    deleted_at TIMESTAMP(6),
    CONSTRAINT ck_oauth_resource_fence_scope CHECK (tenant_id > 0 AND version >= 0 AND deleted_at IS NULL),
    CONSTRAINT uk_oauth_resource_fence_partition UNIQUE (tenant_id, id)
);

LOCK TABLE oauth_resource IN SHARE ROW EXCLUSIVE MODE;
INSERT INTO oauth_resource_fence (id, tenant_id, version, create_time, create_user_id, update_time, update_user_id, deleted_at)
SELECT id, tenant_id, 0, create_time, create_user_id, update_time, update_user_id, NULL FROM oauth_resource;

CREATE FUNCTION oauth_coordinate_resource_fence() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO oauth_resource_fence (id, tenant_id, version, create_time, create_user_id, update_time, update_user_id, deleted_at)
        VALUES (NEW.id, NEW.tenant_id, 0, NEW.create_time, NEW.create_user_id, NEW.update_time, NEW.update_user_id, NULL);
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND (OLD.id <> NEW.id OR OLD.tenant_id <> NEW.tenant_id) THEN
        RAISE EXCEPTION 'OAUTH_RESOURCE_IDENTITY_IMMUTABLE';
    END IF;
    UPDATE oauth_resource_fence SET version = version + 1, update_time = clock_timestamp(),
        update_user_id = CASE WHEN TG_OP = 'DELETE' THEN OLD.update_user_id ELSE NEW.update_user_id END
        WHERE id = OLD.id AND tenant_id = OLD.tenant_id AND deleted_at IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'OAUTH_RESOURCE_FENCE_MISSING'; END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER tr_oauth_resource_fence
    BEFORE INSERT OR UPDATE OR DELETE ON oauth_resource
    FOR EACH ROW EXECUTE FUNCTION oauth_coordinate_resource_fence();

$oauth_schema$;
    END IF;
END
$oauth_fresh_baseline$;
