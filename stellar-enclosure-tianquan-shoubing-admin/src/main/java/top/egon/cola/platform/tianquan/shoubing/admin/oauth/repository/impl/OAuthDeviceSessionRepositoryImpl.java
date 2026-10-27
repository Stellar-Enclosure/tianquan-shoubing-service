package top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.impl;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties;
import top.egon.cola.component.common.mybatis.business.EgonColaTenantIdProvider;
import top.egon.cola.component.common.mybatis.business.EgonColaUserIdProvider;
import top.egon.cola.component.common.mybatis.extension.EgonColaRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.OAuthDeviceSessionMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthDeviceSessionBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.po.OAuthDeviceSessionPO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter.OAuthDeviceSessionConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthDeviceSessionRepository;

@Repository("oAuthDeviceSessionRepository")
@RequiredArgsConstructor
public class OAuthDeviceSessionRepositoryImpl extends EgonColaRepository<OAuthDeviceSessionMapper, OAuthDeviceSessionPO>
        implements OAuthDeviceSessionRepository {
    @Getter @Qualifier("OAuthDeviceSessionMapper")
    private final OAuthDeviceSessionMapper baseMapper;
    @Getter(AccessLevel.PROTECTED)
    @Qualifier("egon.cola.component.mybatis-plus-top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties")
    private final EgonColaMybatisPlusProperties properties;
    @Qualifier("OAuthDeviceSessionConverterImpl") private final OAuthDeviceSessionConverter converter;
    @Qualifier("egonColaMdcUserIdProvider") private final EgonColaUserIdProvider userIdProvider;
    @Qualifier("egonColaMybatisPlusClock") private final Clock clock;

    @Override
    @Transactional(readOnly = true)
    public Optional<OAuthDeviceSessionBO> findById(TrustedRealmBO realm, long id) {
        return withRealm(realm, tenant -> Optional.ofNullable(baseMapper.selectSession(tenant, id)).map(converter::toTarget));
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<OAuthDeviceSessionBO> findByAuthentication(TrustedRealmBO realm, String digest, Long clientPk) {
        return withRealm(realm, tenant -> Optional.ofNullable(baseMapper.selectByAuthentication(tenant, digest, clientPk)).map(converter::toTarget));
    }

    @Override
    @Transactional(readOnly = true)
    public List<OAuthDeviceSessionBO> findLiveBySubject(TrustedRealmBO realm, String subject, Instant now) {
        return withRealm(realm, tenant -> baseMapper.selectLiveBySubject(tenant, subject, now).stream().map(converter::toTarget).toList());
    }

    @Override
    @Transactional
    public OAuthDeviceSessionBO save(TrustedRealmBO realm, OAuthDeviceSessionBO value, long expectedVersion) {
        Objects.requireNonNull(value, "session");
        if (value.getClientPk() == null || value.getClientPk() <= 0 || value.getSubject() == null || value.getSubject().isBlank()
                || value.getAuthenticationJtiDigest() == null || !value.getAuthenticationJtiDigest().matches("[0-9a-f]{64}")
                || value.getAuthenticatedAt() == null || value.getExpiresAt() == null
                || !value.getExpiresAt().isAfter(value.getAuthenticatedAt())
                || !List.of("ACTIVE", "REVOKED").contains(value.getStatus())
                || ("REVOKED".equals(value.getStatus()) ? value.getRevokedAt() == null || value.getReasonCode() == null : value.getRevokedAt() != null)
                || value.getUserAgent() != null && value.getUserAgent().length() > 512
                || value.getIpAddress() != null && value.getIpAddress().length() > 64) {
            throw new IllegalArgumentException("OAUTH_DEVICE_SESSION_INVALID");
        }
        return withRealm(realm, tenant -> {
            var current = value.getId() == null ? null : baseMapper.selectSession(tenant, value.getId());
            var row = converter.toSource(value);
            row.setTenantId(tenant);
            if (current == null) {
                if (value.getId() != null || expectedVersion != 0L || value.getVersion() != 0L) { throw stale(); }
                if (!super.save(row)) { throw new IllegalStateException("OAUTH_DEVICE_SESSION_INSERT_NOT_APPLIED"); }
            } else {
                if (current.getVersion() != expectedVersion || value.getVersion() != Math.addExact(expectedVersion, 1L)) { throw stale(); }
                if (!Objects.equals(current.getSubject(), value.getSubject()) || !Objects.equals(current.getClientPk(), value.getClientPk())
                        || !Objects.equals(current.getAuthenticationJtiDigest(), value.getAuthenticationJtiDigest())
                        || !Objects.equals(current.getAuthenticatedAt(), value.getAuthenticatedAt())
                        || !Objects.equals(current.getUserAgent(), value.getUserAgent()) || !Objects.equals(current.getIpAddress(), value.getIpAddress())
                        || value.getExpiresAt().isBefore(current.getExpiresAt())
                        || "REVOKED".equals(current.getStatus()) && !"REVOKED".equals(value.getStatus())) {
                    throw new IllegalArgumentException("OAUTH_DEVICE_SESSION_IDENTITY_IMMUTABLE");
                }
                row.setUpdateUserId(userIdProvider.currentUserId());
                row.setUpdateTime(clock.instant().truncatedTo(ChronoUnit.MICROS));
                if (baseMapper.updateExpectedVersion(tenant, row, expectedVersion) != 1) { throw stale(); }
            }
            return converter.toTarget(row);
        });
    }

    @Override
    @Transactional
    public int deleteRetained(TrustedRealmBO realm, Instant now, int limit) {
        Objects.requireNonNull(now, "now");
        if (limit < 1 || limit > 500) { throw new IllegalArgumentException("OAUTH_SESSION_RETENTION_LIMIT_INVALID"); }
        return withRealm(realm, tenant -> baseMapper.deleteRetained(tenant, now, limit, userIdProvider.currentUserId()));
    }

    private <T> T withRealm(TrustedRealmBO realm, Function<Long, T> action) {
        Objects.requireNonNull(realm, "realm").validateTrustedPartition();
        String tenantKey = properties.getTenantId().getMdcKey();
        String actorKey = properties.getAudit().getUserIdMdcKey();
        if (tenantKey.equals(actorKey)) { throw new IllegalStateException("OAUTH_STATE_MDC_KEYS_INVALID"); }
        String previousTenant = MDC.get(tenantKey); String previousActor = MDC.get(actorKey);
        try {
            MDC.put(tenantKey, Long.toString(realm.getStoragePartitionId()));
            if (previousActor == null || previousActor.isBlank()) { MDC.put(actorKey, "service:tianquan-shoubing"); }
            Long tenant = EgonColaTenantIdProvider.currentTenantId();
            if (!tenant.equals(realm.getStoragePartitionId())) { throw new IllegalStateException("OAUTH_STATE_TENANT_MISMATCH"); }
            return action.apply(tenant);
        } finally {
            restore(tenantKey, previousTenant); restore(actorKey, previousActor);
        }
    }

    private static void restore(String key, String value) {
        if (value == null) { MDC.remove(key); } else { MDC.put(key, value); }
    }

    private static OptimisticLockingFailureException stale() {
        return new OptimisticLockingFailureException("OAuth device session version no longer matches");
    }
}
