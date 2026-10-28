package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.tenant.repo.IdentityTenantRepository;

/** Enumerates each registered tenant partition through its replica for independent maintenance work. */
@Component("oauthScheduledRealmCatalog")
@RequiredArgsConstructor
@Slf4j
public class OAuthScheduledRealmCatalog {
    @Qualifier("oauthManagementRealmResolver") private final OAuthManagementRealmResolver managementRealms;
    @Qualifier("oAuthRealmRepository") private final OAuthRealmRepository realms;
    @Qualifier("identityTenantRepository") private final IdentityTenantRepository tenants;

    public List<OAuthRealmBO> findAll() {
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("OAUTH_REALM_CATALOG_AMBIENT_TRANSACTION_UNSUPPORTED");
        }
        TrustedRealmBO platform = managementRealms.platformRealm();
        platform.validateTrustedPartition();
        List<OAuthRealmBO> result = new ArrayList<>();
        addPartition(result, platform, platform);
        Set<Long> visited = new HashSet<>();
        visited.add(platform.getStoragePartitionId());
        for (var tenant : tenants.findAllByOrderByUpdatedAtDescIdAsc()) {
            String value = tenant.getIdentityTenantId();
            try {
                if (value == null || !value.matches("[1-9][0-9]{0,18}")) throw new IllegalArgumentException("invalid tenant id");
                long id = Long.parseLong(value);
                if (id <= 0 || !visited.add(id)) continue;
                TrustedRealmBO scope = TrustedRealmBO.builder().issuer(platform.getIssuer().resolve("/tenants/" + id))
                        .realmKey("tenant:" + id).realmType(RealmTypeEnum.TENANT).storagePartitionId(id)
                        .businessTenantId(id).trustVersion(0L).build();
                addPartition(result, platform, scope);
            } catch (RuntimeException failure) {
                log.warn("OAuth realm maintenance partition deferred; failureType={}", failure.getClass().getSimpleName());
            }
        }
        return List.copyOf(result);
    }

    private void addPartition(List<OAuthRealmBO> result, TrustedRealmBO platform, TrustedRealmBO scope) {
        List<OAuthRealmBO> rows = realms.findAllByStoragePartition(scope);
        for (OAuthRealmBO row : rows) {
            if (row == null || !Objects.equals(row.getStoragePartitionId(), scope.getStoragePartitionId())) {
                throw new IllegalStateException("OAUTH_REALM_CATALOG_PARTITION_MISMATCH");
            }
            if (row.getRealmType() == RealmTypeEnum.PLATFORM) {
                if (!Objects.equals(row.getRealmKey(), "platform") || row.getBusinessTenantId() != null
                        || !Objects.equals(row.getIssuer(), platform.getIssuer())
                        || !Objects.equals(scope.getStoragePartitionId(), platform.getStoragePartitionId())) {
                    throw new IllegalStateException("OAUTH_REALM_CATALOG_IDENTITY_MISMATCH");
                }
            } else if (row.getRealmType() != RealmTypeEnum.TENANT
                    || !Objects.equals(row.getBusinessTenantId(), scope.getStoragePartitionId())
                    || !Objects.equals(row.getRealmKey(), "tenant:" + scope.getStoragePartitionId())
                    || !Objects.equals(row.getIssuer(), platform.getIssuer().resolve("/tenants/" + scope.getStoragePartitionId()))) {
                throw new IllegalStateException("OAUTH_REALM_CATALOG_IDENTITY_MISMATCH");
            }
        }
        result.addAll(rows);
    }
}
