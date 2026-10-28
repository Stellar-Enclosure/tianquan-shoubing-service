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
SELECT DISTINCT tenant_id, identity_sub, CAST(identity_tenant_id AS BIGINT), NULL FROM oauth_identity_membership;

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
