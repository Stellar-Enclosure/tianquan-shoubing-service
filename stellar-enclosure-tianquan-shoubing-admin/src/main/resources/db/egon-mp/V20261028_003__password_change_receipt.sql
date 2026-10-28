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
