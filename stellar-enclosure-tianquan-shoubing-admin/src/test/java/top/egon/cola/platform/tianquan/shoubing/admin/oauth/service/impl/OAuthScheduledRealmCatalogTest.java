package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.tenant.domain.bo.IdentityTenantBO;
import top.egon.cola.platform.tianquan.shoubing.admin.tenant.repo.IdentityTenantRepository;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class OAuthScheduledRealmCatalogTest {
    private final OAuthManagementRealmResolver management = mock(OAuthManagementRealmResolver.class);
    private final OAuthRealmRepository realms = mock(OAuthRealmRepository.class);
    private final IdentityTenantRepository tenants = mock(IdentityTenantRepository.class);
    private final TrustedRealmBO platform = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/platform"))
            .realmKey("platform").realmType(RealmTypeEnum.PLATFORM).storagePartitionId(1L).trustVersion(0L).build();
    private final OAuthScheduledRealmCatalog catalog = new OAuthScheduledRealmCatalog(management, realms, tenants);

    @Test void enumeratesEachTenantPartitionOnceIncludingClosedRealms() {
        when(management.platformRealm()).thenReturn(platform);
        when(tenants.findAllByOrderByUpdatedAtDescIdAsc()).thenReturn(List.of(tenant("2"), tenant("3"), tenant("2"), tenant("1")));
        when(realms.findAllByStoragePartition(any())).thenAnswer(call -> {
            TrustedRealmBO scope = call.getArgument(0);
            long id = scope.getStoragePartitionId();
            if (id == 1) return List.of(OAuthRealmBO.builder().realmKey("platform").realmType(RealmTypeEnum.PLATFORM)
                    .storagePartitionId(1L).issuer(platform.getIssuer()).status("ACTIVE").trustVersion(0L).build());
            return List.of(OAuthRealmBO.builder().realmKey("tenant:" + id).realmType(RealmTypeEnum.TENANT)
                    .storagePartitionId(id).businessTenantId(id).issuer(URI.create("https://idp.example/tenants/" + id))
                    .status(id == 2 ? "ACTIVE" : "CLOSED").trustVersion(4L).build());
        });

        assertThat(catalog.findAll()).extracting(OAuthRealmBO::getRealmKey).containsExactly("platform", "tenant:2", "tenant:3");
        verify(realms, times(3)).findAllByStoragePartition(any());
        verify(realms).findAllByStoragePartition(argThat(scope -> scope.getStoragePartitionId() == 2L
                && scope.getRealmKey().equals("tenant:2") && scope.getBusinessTenantId() == 2L));
    }

    @Test void unavailableOrMismatchedPartitionDoesNotSuppressOtherTenants() {
        when(management.platformRealm()).thenReturn(platform);
        when(tenants.findAllByOrderByUpdatedAtDescIdAsc()).thenReturn(List.of(tenant("2"), tenant("3"), tenant("4")));
        when(realms.findAllByStoragePartition(any())).thenAnswer(call -> {
            TrustedRealmBO scope = call.getArgument(0);
            long id = scope.getStoragePartitionId();
            if (id == 2) throw new IllegalStateException("replica unavailable");
            if (id == 3) return List.of(OAuthRealmBO.builder().storagePartitionId(9L).build());
            if (id == 4) return List.of(OAuthRealmBO.builder().realmKey("tenant:4").realmType(RealmTypeEnum.TENANT)
                    .storagePartitionId(4L).businessTenantId(4L).issuer(URI.create("https://idp.example/tenants/4"))
                    .status("ACTIVE").trustVersion(0L).build());
            return List.of();
        });

        assertThat(catalog.findAll()).extracting(OAuthRealmBO::getRealmKey).containsExactly("tenant:4");
    }

    @Test void refusesAnAmbientTransactionBeforeReadingSeveralPartitions() {
        TransactionSynchronizationManager.setActualTransactionActive(true);
        try {
            assertThatThrownBy(catalog::findAll).hasMessage("OAUTH_REALM_CATALOG_AMBIENT_TRANSACTION_UNSUPPORTED");
            verifyNoInteractions(management, realms, tenants);
        } finally { TransactionSynchronizationManager.setActualTransactionActive(false); }
    }

    private static IdentityTenantBO tenant(String id) { return IdentityTenantBO.builder().identityTenantId(id).build(); }
}
