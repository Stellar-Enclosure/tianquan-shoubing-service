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
