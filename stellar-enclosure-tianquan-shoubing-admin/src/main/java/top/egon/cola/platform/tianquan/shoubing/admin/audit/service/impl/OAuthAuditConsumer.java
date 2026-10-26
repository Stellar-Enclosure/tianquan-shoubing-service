package top.egon.cola.platform.tianquan.shoubing.admin.audit.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthManagementRealmResolver;

/** Recovers committed PostgreSQL inbox rows; leases are persisted and fenced by generation. */
@Service("oauthAuditConsumer")
@RequiredArgsConstructor
@Slf4j
public class OAuthAuditConsumer {

    @Qualifier("oauthAuditDeliveryService") private final OAuthAuditDeliveryService delivery;
    @Qualifier("oAuthRealmRepository") private final OAuthRealmRepository realms;
    @Qualifier("oauthManagementRealmResolver") private final OAuthManagementRealmResolver managementRealms;
    @Qualifier("tenantIssuerService") private final TenantIssuerService issuers;

    @Scheduled(fixedDelayString = "${egon.cola.platform.tianquan.shoubing.audit.consumer-delay:1000}")
    public void consume() {
        for (var registered : realms.findAllByStoragePartition(managementRealms.platformRealm())) {
            if (!"ACTIVE".equals(registered.getStatus())) { continue; }
            try { delivery.drain(issuers.resolveExactIssuer(registered.getIssuer())); }
            catch (RuntimeException failure) {
                log.warn("OAuth audit database recovery deferred; realmKey={} failureType={}",
                        registered.getRealmKey(), failure.getClass().getSimpleName());
            }
        }
    }
}
