package top.egon.cola.platform.tianquan.shoubing.admin.resource.service;

import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.OAuthClientPurposeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthManagementRealmResolver;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.bo.OAuthGrantBO;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.bo.OAuthResourceBO;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthGrantRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthResourceRepository;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ResourceGrantType;

/** Confirms committed resource/grant facts without a Redis runtime publication requirement. */
@RequiredArgsConstructor
public class ResourceServerProjectionService {

    private final OAuthResourceRepository resources;
    private final OAuthGrantRepository grants;
    private final OAuthManagementRealmResolver realms;

    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public void projectResource(OAuthResourceBO resource, OAuthClientBO client) {
        Objects.requireNonNull(resource, "resource"); Objects.requireNonNull(client, "client");
        var current = resources.findByResourceServerId(realms.platformRealm(), resource.getResourceServerId())
                .orElseThrow(() -> new IllegalStateException("RESOURCE_AUTHORITY_FACT_MISSING"));
        if (current.getVersion() < resource.getVersion() || !Objects.equals(current.getManagementClientPk(), client.getId())
                || !Objects.equals(current.getResourceUri(), resource.getResourceUri())) {
            throw new IllegalArgumentException("RESOURCE_AUTHORITY_BINDING_MISMATCH");
        }
    }

    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public void projectServiceGrant(TrustedRealmBO realm, OAuthClientBO client, OAuthResourceBO resource, OAuthGrantBO grant) {
        requireCommittedGrant(realm, client, resource, grant);
    }

    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public void deleteServiceGrant(TrustedRealmBO realm, OAuthClientBO client, OAuthResourceBO resource, OAuthGrantBO grant) {
        var current = requireCommittedGrant(realm, client, resource, grant);
        if ("ACTIVE".equals(current.getStatus().name())) {
            throw new IllegalArgumentException("RESOURCE_GRANT_DISABLE_NOT_COMMITTED");
        }
    }

    private OAuthGrantBO requireCommittedGrant(TrustedRealmBO realm, OAuthClientBO client, OAuthResourceBO resource, OAuthGrantBO grant) {
        Objects.requireNonNull(realm, "realm").validateTrustedPartition();
        if (client == null || resource == null || grant == null || client.getPurpose() != OAuthClientPurposeEnum.SERVICE
                || grant.getGrantType() != ResourceGrantType.CLIENT_CREDENTIALS
                || !Objects.equals(client.getId(), grant.getClientPk())
                || !Objects.equals(resource.getResourceServerId(), grant.getResourceServerId())) {
            throw new IllegalArgumentException("RESOURCE_GRANT_AUTHORITY_BINDING_INVALID");
        }
        var current = grants.findGrant(realm, client.getId(), resource.getResourceServerId(), ResourceGrantType.CLIENT_CREDENTIALS)
                .orElseThrow(() -> new IllegalStateException("RESOURCE_GRANT_AUTHORITY_FACT_MISSING"));
        if (current.getVersion() < grant.getVersion()) { throw new IllegalStateException("RESOURCE_GRANT_COMMIT_NOT_VISIBLE"); }
        return current;
    }
}
