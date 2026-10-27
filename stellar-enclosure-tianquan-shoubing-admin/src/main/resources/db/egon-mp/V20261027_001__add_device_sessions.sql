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
