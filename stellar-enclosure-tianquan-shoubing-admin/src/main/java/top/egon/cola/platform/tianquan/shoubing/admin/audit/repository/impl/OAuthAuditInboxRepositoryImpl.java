package top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.impl;

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
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties;
import top.egon.cola.component.common.mybatis.business.EgonColaTenantIdProvider;
import top.egon.cola.component.common.mybatis.business.EgonColaUserIdProvider;
import top.egon.cola.component.common.mybatis.extension.EgonColaRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.dao.OAuthAuditInboxMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditInboxBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.po.OAuthAuditInboxPO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.converter.OAuthAuditInboxConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditInboxRepository;

@Repository("oAuthAuditInboxRepository")
@RequiredArgsConstructor
public class OAuthAuditInboxRepositoryImpl extends EgonColaRepository<OAuthAuditInboxMapper, OAuthAuditInboxPO>
        implements OAuthAuditInboxRepository {

    @Getter @Qualifier("OAuthAuditInboxMapper")
    private final OAuthAuditInboxMapper baseMapper;
    @Getter(AccessLevel.PROTECTED)
    @Qualifier("egon.cola.component.mybatis-plus-top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties")
    private final EgonColaMybatisPlusProperties properties;
    @Qualifier("OAuthAuditInboxConverterImpl")
    private final OAuthAuditInboxConverter converter;
    @Qualifier("egonColaMdcUserIdProvider")
    private final EgonColaUserIdProvider userIdProvider;
    @Qualifier("egonColaMybatisPlusClock")
    private final Clock clock;

    @Override
    @Transactional(readOnly = true)
    public Optional<OAuthAuditInboxBO> findByEventId(TrustedRealmBO realm, String key) {
        requireKey(key);
        return withRealm(realm, tenant -> Optional.ofNullable(baseMapper.selectByKey(tenant, key)).map(converter::toTarget));
    }

    @Override
    @Transactional
    public Optional<OAuthAuditInboxBO> findByEventIdForUpdate(TrustedRealmBO realm, String key) {
        requireKey(key);
        return withRealm(realm, tenant -> Optional.ofNullable(baseMapper.selectByKeyForUpdate(tenant, key)).map(converter::toTarget));
    }

    @Override
    @Transactional(readOnly = true)
    public List<OAuthAuditInboxBO> findRetainedBefore(TrustedRealmBO realm, Instant now, long afterId, int limit) {
        Objects.requireNonNull(now, "now"); requirePage(afterId, limit);
        return withRealm(realm, tenant -> baseMapper.selectRetainedBefore(tenant, now, afterId, limit)
                .stream().map(converter::toTarget).toList());
    }

    @Override
    @Transactional
    public OAuthAuditInboxBO save(TrustedRealmBO realm, OAuthAuditInboxBO requested, long expectedVersion) {
        Objects.requireNonNull(requested, "requested"); requireKey(requested.getEventId());
        if (expectedVersion < 0) { throw new IllegalArgumentException("OAUTH_STATE_VERSION_INVALID"); }
        return withRealm(realm, tenant -> {
            try {
                OAuthAuditInboxPO current = baseMapper.selectByKeyForUpdate(tenant, requested.getEventId());
                requireTransition(current, requested);
                if (current == null) {
                    if (requested.getId() != null || requested.getVersion() != 0L || expectedVersion != 0L) {
                        throw stale();
                    }
                    OAuthAuditInboxPO row = converter.toSource(requested);
                    row.setTenantId(tenant); row.setVersion(0L);
                    if (!super.save(row)) { throw new IllegalStateException("OAUTH_STATE_INSERT_NOT_APPLIED"); }
                    return converter.toTarget(row);
                }
                long next = Math.addExact(expectedVersion, 1L);
                if (current.getVersion() != expectedVersion || requested.getVersion() != next
                        || !Objects.equals(requested.getId(), current.getId())) { throw stale(); }
                OAuthAuditInboxPO row = converter.toSource(requested);
                row.setTenantId(tenant); row.setId(current.getId()); row.setVersion(next);
                row.setUpdateUserId(userIdProvider.currentUserId());
                row.setUpdateTime(clock.instant().truncatedTo(ChronoUnit.MICROS));
                if (baseMapper.updateExpectedVersion(tenant, row, expectedVersion) != 1) { throw stale(); }
                return converter.toTarget(row);
            } catch (DataIntegrityViolationException conflict) {
                throw new IllegalStateException("OAUTH_STATE_IDENTITY_CONFLICT", conflict);
            }
        });
    }

    static void requireTransition(OAuthAuditInboxPO current, OAuthAuditInboxBO requested) {
        if (requested.getRetainUntil() == null) { throw new IllegalArgumentException("OAUTH_STATE_RETENTION_REQUIRED"); }
        if (requested.getEventPayload() == null || !requested.getEventPayload().isObject()
                || requested.getProcessingDeadline() == null || requested.getReceivedAt() == null
                || !requested.getProcessingDeadline().isAfter(requested.getReceivedAt())
                || !List.of("PENDING", "PROCESSING", "STORED", "DEAD", "EXPIRED").contains(requested.getState())) {
            throw new IllegalArgumentException("OAUTH_AUDIT_INBOX_STATE_INVALID");
        }
        boolean claimed = requested.getClaimOwner() != null && requested.getClaimToken() != null && requested.getLeaseUntil() != null;
        boolean unclaimed = requested.getClaimOwner() == null && requested.getClaimToken() == null && requested.getLeaseUntil() == null;
        if ("PROCESSING".equals(requested.getState()) ? !claimed
                || !requested.getLeaseUntil().isAfter(requested.getReceivedAt())
                || requested.getLeaseUntil().isAfter(requested.getProcessingDeadline()) : !unclaimed) {
            throw new IllegalArgumentException("OAUTH_AUDIT_CLAIM_INVALID");
        }
        if (List.of("STORED", "DEAD", "EXPIRED").contains(requested.getState()) != (requested.getTerminalAt() != null)) {
            throw new IllegalArgumentException("OAUTH_AUDIT_TERMINAL_INVALID");
        }
        if (current != null && (List.of("STORED", "DEAD", "EXPIRED").contains(current.getState())
                || requested.getAttemptCount() < current.getAttemptCount()
                || requested.getClaimGeneration() < current.getClaimGeneration())) {
            throw new IllegalArgumentException("OAUTH_AUDIT_INBOX_TERMINAL_OR_STALE");
        }
        if (current == null) { return; }
        if (!Objects.equals(current.getEventId(), requested.getEventId())
                || !Objects.equals(current.getEventFingerprint(), requested.getEventFingerprint())
                || !Objects.equals(current.getSchemaVersion(), requested.getSchemaVersion())
                || !Objects.equals(current.getSourceClientPk(), requested.getSourceClientPk())
                || !Objects.equals(current.getSourceIssuer(), requested.getSourceIssuer())
                || !Objects.equals(current.getSourceResourceUri(), requested.getSourceResourceUri())
                || !Objects.equals(current.getEventPayload(), requested.getEventPayload())
                || !Objects.equals(current.getOccurredAt(), requested.getOccurredAt())
                || !Objects.equals(current.getReceivedAt(), requested.getReceivedAt())
                || !Objects.equals(current.getProcessingDeadline(), requested.getProcessingDeadline())
                || !Objects.equals(current.getRetainUntil(), requested.getRetainUntil())) {
            throw new IllegalArgumentException("OAUTH_STATE_IDENTITY_IMMUTABLE");
        }
    }

    @Override
    @Transactional(readOnly = true)
    public List<OAuthAuditInboxBO> findDue(TrustedRealmBO realm, Instant now, int limit) {
        Objects.requireNonNull(now, "now"); requirePage(0L, limit);
        return withRealm(realm, tenant -> baseMapper.selectDue(tenant, now, limit).stream().map(converter::toTarget).toList());
    }

    @Override
    @Transactional
    public boolean deleteRetained(TrustedRealmBO realm, long id, long expectedVersion, Instant now) {
        if (id <= 0 || expectedVersion < 0 || now == null) { throw new IllegalArgumentException("OAUTH_RETENTION_INPUT_INVALID"); }
        return withRealm(realm, tenant -> baseMapper.deleteRetained(tenant, id, expectedVersion,
                now.truncatedTo(ChronoUnit.MICROS), userIdProvider.currentUserId()) == 1);
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

    private static void requirePage(long afterId, int limit) {
        if (afterId < 0 || limit < 1 || limit > 500) { throw new IllegalArgumentException("OAUTH_STATE_PAGE_INVALID"); }
    }

    private static void requireKey(String key) {
        if (key == null || (key.isBlank() || key.length() > 64 || !key.equals(key.trim()))) { throw new IllegalArgumentException("OAUTH_STATE_KEY_INVALID"); }
    }

    private static OptimisticLockingFailureException stale() {
        return new OptimisticLockingFailureException("OAuth state version no longer matches");
    }
}
