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
