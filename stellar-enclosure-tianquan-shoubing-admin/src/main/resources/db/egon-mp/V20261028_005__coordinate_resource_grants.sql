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
