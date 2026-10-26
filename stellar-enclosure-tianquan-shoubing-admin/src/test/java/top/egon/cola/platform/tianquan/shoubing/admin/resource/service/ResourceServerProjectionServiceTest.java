package top.egon.cola.platform.tianquan.shoubing.admin.resource.service;

import java.net.URI;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.OAuthClientPurposeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthManagementRealmResolver;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.bo.OAuthGrantBO;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.bo.OAuthResourceBO;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthGrantRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthResourceRepository;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ClientResourceGrant;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ResourceGrantType;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ResourceServerProjectionServiceTest {
    private final OAuthResourceRepository resources = mock(OAuthResourceRepository.class);
    private final OAuthGrantRepository grants = mock(OAuthGrantRepository.class);
    private final OAuthManagementRealmResolver realms = mock(OAuthManagementRealmResolver.class);
    private final ResourceServerProjectionService service = new ResourceServerProjectionService(resources, grants, realms);
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/platform"))
            .realmKey("platform").realmType(RealmTypeEnum.PLATFORM).storagePartitionId(1L).trustVersion(0L).build();

    @Test void resourceDeliveryRequiresMatchingCommittedOwnerAndVersion() {
        when(realms.platformRealm()).thenReturn(realm);
        var resource = OAuthResourceBO.builder().resourceServerId("api").resourceUri(URI.create("https://api.example"))
                .managementClientPk(3L).version(4).build();
        when(resources.findByResourceServerId(realm, "api")).thenReturn(Optional.of(resource));
        assertDoesNotThrow(() -> service.projectResource(resource, OAuthClientBO.builder().id(3L).build()));
        assertThrows(IllegalArgumentException.class, () -> service.projectResource(resource, OAuthClientBO.builder().id(5L).build()));
    }

    @Test void disablingGrantCannotBeAcknowledgedWhileDatabaseStillAllowsIt() {
        var resource = OAuthResourceBO.builder().resourceServerId("api").build();
        var client = OAuthClientBO.builder().id(3L).purpose(OAuthClientPurposeEnum.SERVICE).build();
        var grant = OAuthGrantBO.builder().clientPk(3L).resourceServerId("api").grantType(ResourceGrantType.CLIENT_CREDENTIALS)
                .status(ClientResourceGrant.Status.ACTIVE).version(2).build();
        when(grants.findGrant(realm, 3L, "api", ResourceGrantType.CLIENT_CREDENTIALS)).thenReturn(Optional.of(grant));
        assertThrows(IllegalArgumentException.class, () -> service.deleteServiceGrant(realm, client, resource, grant));
        grant.setStatus(ClientResourceGrant.Status.DISABLED);
        assertDoesNotThrow(() -> service.deleteServiceGrant(realm, client, resource, grant));
    }

    @Test void missingGrantDoesNotBecomeACommittedProjection() {
        var client = OAuthClientBO.builder().id(3L).purpose(OAuthClientPurposeEnum.SERVICE).build();
        var grant = OAuthGrantBO.builder().clientPk(3L).resourceServerId("api").grantType(ResourceGrantType.CLIENT_CREDENTIALS).build();
        assertThrows(IllegalStateException.class, () -> service.projectServiceGrant(realm, client, OAuthResourceBO.builder().resourceServerId("api").build(), grant));
    }
}
