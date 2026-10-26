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
import top.egon.cola.platform.tianquan.shoubing.admin.audit.dao.OAuthAuditReceiptMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditReceiptBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.po.OAuthAuditReceiptPO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.converter.OAuthAuditReceiptConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditReceiptRepository;

@Repository("oAuthAuditReceiptRepository")
@RequiredArgsConstructor
public class OAuthAuditReceiptRepositoryImpl extends EgonColaRepository<OAuthAuditReceiptMapper, OAuthAuditReceiptPO>
        implements OAuthAuditReceiptRepository {

    @Getter @Qualifier("OAuthAuditReceiptMapper")
    private final OAuthAuditReceiptMapper baseMapper;
    @Getter(AccessLevel.PROTECTED)
    @Qualifier("egon.cola.component.mybatis-plus-top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties")
    private final EgonColaMybatisPlusProperties properties;
    @Qualifier("OAuthAuditReceiptConverterImpl")
    private final OAuthAuditReceiptConverter converter;
    @Qualifier("egonColaMdcUserIdProvider")
    private final EgonColaUserIdProvider userIdProvider;
    @Qualifier("egonColaMybatisPlusClock")
    private final Clock clock;

    @Override
    @Transactional(readOnly = true)
    public Optional<OAuthAuditReceiptBO> findByEventId(TrustedRealmBO realm, String key) {
        requireKey(key);
        return withRealm(realm, tenant -> Optional.ofNullable(baseMapper.selectByKey(tenant, key)).map(converter::toTarget));
    }

    @Override
    @Transactional
    public Optional<OAuthAuditReceiptBO> findByEventIdForUpdate(TrustedRealmBO realm, String key) {
        requireKey(key);
        return withRealm(realm, tenant -> Optional.ofNullable(baseMapper.selectByKeyForUpdate(tenant, key)).map(converter::toTarget));
    }

    @Override
    @Transactional(readOnly = true)
    public List<OAuthAuditReceiptBO> findRetainedBefore(TrustedRealmBO realm, Instant now, long afterId, int limit) {
        Objects.requireNonNull(now, "now"); requirePage(afterId, limit);
        return withRealm(realm, tenant -> baseMapper.selectRetainedBefore(tenant, now, afterId, limit)
                .stream().map(converter::toTarget).toList());
    }

    @Override
    @Transactional
    public OAuthAuditReceiptBO save(TrustedRealmBO realm, OAuthAuditReceiptBO requested, long expectedVersion) {
        Objects.requireNonNull(requested, "requested"); requireKey(requested.getEventId());
        if (expectedVersion < 0) { throw new IllegalArgumentException("OAUTH_STATE_VERSION_INVALID"); }
        return withRealm(realm, tenant -> {
            try {
                OAuthAuditReceiptPO current = baseMapper.selectByKeyForUpdate(tenant, requested.getEventId());
                requireTransition(current, requested);
                if (current == null) {
                    if (requested.getId() != null || requested.getVersion() != 0L || expectedVersion != 0L) {
                        throw stale();
                    }
                    OAuthAuditReceiptPO row = converter.toSource(requested);
                    row.setTenantId(tenant); row.setVersion(0L);
                    if (!super.save(row)) { throw new IllegalStateException("OAUTH_STATE_INSERT_NOT_APPLIED"); }
                    return converter.toTarget(row);
                }
                long next = Math.addExact(expectedVersion, 1L);
                if (current.getVersion() != expectedVersion || requested.getVersion() != next
                        || !Objects.equals(requested.getId(), current.getId())) { throw stale(); }
                OAuthAuditReceiptPO row = converter.toSource(requested);
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

    static void requireTransition(OAuthAuditReceiptPO current, OAuthAuditReceiptBO requested) {
        if (requested.getRetainUntil() == null) { throw new IllegalArgumentException("OAUTH_STATE_RETENTION_REQUIRED"); }
        if (!List.of("STORED", "DEAD", "EXPIRED").contains(requested.getOutcome())
                || "STORED".equals(requested.getOutcome()) != (requested.getAuditPk() != null)) {
            throw new IllegalArgumentException("OAUTH_AUDIT_RECEIPT_INVALID");
        }
        if (current != null) { throw new IllegalArgumentException("OAUTH_AUDIT_RECEIPT_IMMUTABLE"); }
        if (current == null) { return; }
        if (!Objects.equals(current.getReceiptId(), requested.getReceiptId())
                || !Objects.equals(current.getInboxPk(), requested.getInboxPk())
                || !Objects.equals(current.getEventId(), requested.getEventId())
                || !Objects.equals(current.getEventFingerprint(), requested.getEventFingerprint())
                || !Objects.equals(current.getSourceClientPk(), requested.getSourceClientPk())
                || !Objects.equals(current.getSourceIssuer(), requested.getSourceIssuer())
                || !Objects.equals(current.getSourceResourceUri(), requested.getSourceResourceUri())
                || !Objects.equals(current.getOutcome(), requested.getOutcome())
                || !Objects.equals(current.getAuditPk(), requested.getAuditPk())
                || !Objects.equals(current.getConfirmedAt(), requested.getConfirmedAt())
                || !Objects.equals(current.getRetainUntil(), requested.getRetainUntil())) {
            throw new IllegalArgumentException("OAUTH_STATE_IDENTITY_IMMUTABLE");
        }
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
