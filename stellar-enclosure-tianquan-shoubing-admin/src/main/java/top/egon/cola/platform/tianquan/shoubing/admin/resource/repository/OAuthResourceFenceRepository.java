package top.egon.cola.platform.tianquan.shoubing.admin.resource.repository;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties;
import top.egon.cola.component.common.mybatis.business.EgonColaTenantIdProvider;
import top.egon.cola.component.common.mybatis.business.EgonColaUserIdProvider;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.dao.OAuthResourceFenceMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.bo.OAuthResourceBO;

@Repository
@RequiredArgsConstructor
public class OAuthResourceFenceRepository {
    private final OAuthResourceFenceMapper mapper;
    @Qualifier("egon.cola.component.mybatis-plus-top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties")
    private final EgonColaMybatisPlusProperties properties;
    @Qualifier("egonColaMdcUserIdProvider") private final EgonColaUserIdProvider actor;
    @Qualifier("egonColaMybatisPlusClock") private final Clock clock;

    @Transactional(propagation = Propagation.MANDATORY)
    public boolean fenceCurrent(TrustedRealmBO realm, OAuthResourceBO resource) {
        Objects.requireNonNull(realm, "realm").validateTrustedPartition();
        Objects.requireNonNull(resource, "resource");
        if (realm.getRealmType() != RealmTypeEnum.PLATFORM || resource.getId() == null || resource.getId() <= 0
                || resource.getVersion() < 0 || resource.getResourceServerId() == null || resource.getResourceServerId().isBlank()) {
            throw new IllegalArgumentException("OAUTH_RESOURCE_FENCE_INVALID");
        }
        String tenantKey = properties.getTenantId().getMdcKey(); String actorKey = properties.getAudit().getUserIdMdcKey();
        if (tenantKey.equals(actorKey)) throw new IllegalStateException("OAUTH_STATE_MDC_KEYS_INVALID");
        String previousTenant = MDC.get(tenantKey); String previousActor = MDC.get(actorKey);
        try {
            MDC.put(tenantKey, Long.toString(realm.getStoragePartitionId()));
            if (previousActor == null || previousActor.isBlank()) MDC.put(actorKey, "service:tianquan-shoubing");
            long tenant = EgonColaTenantIdProvider.currentTenantId();
            Long version = mapper.selectVersion(tenant, resource.getId());
            return version != null && mapper.fenceObserved(tenant, resource.getId(), version, resource.getVersion(),
                    resource.getResourceServerId(), clock.instant().truncatedTo(ChronoUnit.MICROS), actor.currentUserId()) == 1;
        } finally {
            if (previousTenant == null) MDC.remove(tenantKey); else MDC.put(tenantKey, previousTenant);
            if (previousActor == null) MDC.remove(actorKey); else MDC.put(actorKey, previousActor);
        }
    }
}
