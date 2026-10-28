package top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties;
import top.egon.cola.component.common.mybatis.business.EgonColaTenantIdProvider;
import top.egon.cola.component.common.mybatis.business.EgonColaUserIdProvider;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.dao.SubjectDeliveryReceiptMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository;

/** Persists ordered subject-delivery receipts in the target realm's local transaction. */
@Service("oauthSubjectDeliveryOrderService")
@RequiredArgsConstructor
public class OAuthSubjectDeliveryOrderService {
    public static final String SOURCE_REVISION_HEADER = "oauth-subject-source-revision";
    public static final String PREVIOUS_REVISION_HEADER = "oauth-subject-previous-revision";
    private final SubjectDeliveryReceiptMapper receipts;
    @Qualifier("oAuthSecurityStateRepository") private final OAuthSecurityStateRepository states;
    @Qualifier("egon.cola.component.mybatis-plus-top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties")
    private final EgonColaMybatisPlusProperties properties;
    @Qualifier("egonColaMdcUserIdProvider") private final EgonColaUserIdProvider actor;
    @Qualifier("egonColaMybatisPlusClock") private final Clock clock;

    @Transactional
    public void confirm(TrustedRealmBO realm, String subject, long sourceRevision, long previousRevision,
            String eventId, String payloadFingerprint) {
        Objects.requireNonNull(realm, "realm").validateTrustedPartition();
        if (subject == null || !subject.matches("[A-Za-z0-9._~-]{1,64}") || eventId == null
                || !eventId.matches("[A-Za-z0-9._~-]{1,64}") || sourceRevision <= 0
                || previousRevision < 0 || previousRevision >= sourceRevision || payloadFingerprint == null
                || !payloadFingerprint.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("OAUTH_SUBJECT_DELIVERY_INVALID");
        }
        String tenantKey = properties.getTenantId().getMdcKey();
        String actorKey = properties.getAudit().getUserIdMdcKey();
        if (tenantKey.equals(actorKey)) throw new IllegalStateException("OAUTH_STATE_MDC_KEYS_INVALID");
        String previousTenant = MDC.get(tenantKey); String previousActor = MDC.get(actorKey);
        try {
            MDC.put(tenantKey, Long.toString(realm.getStoragePartitionId()));
            if (previousActor == null || previousActor.isBlank()) MDC.put(actorKey, "service:tianquan-shoubing");
            long tenant = EgonColaTenantIdProvider.currentTenantId();
            if (tenant != realm.getStoragePartitionId()) throw new IllegalStateException("OAUTH_STATE_TENANT_MISMATCH");
            var now = clock.instant().truncatedTo(ChronoUnit.MICROS);
            int inserted = receipts.insertIfAbsent(SnowflakeIdGenerator.nextLongId(), tenant, eventId, subject,
                    sourceRevision, previousRevision, payloadFingerprint, now, actor.currentUserId());
            if (inserted != 0 && inserted != 1) throw new IllegalStateException("OAUTH_SUBJECT_DELIVERY_RECEIPT_INVALID");
            var state = states.findByTarget(realm, OAuthSecurityTargetEnum.SUBJECT, subject)
                    .orElseThrow(() -> new TransientDataAccessResourceException("OAuth subject projection is not yet visible"));
            boolean confirmed = inserted == 0
                    ? states.fenceSubjectDeliveryDuplicate(realm, state.getId(), state.getVersion(), subject,
                            sourceRevision, previousRevision, eventId, payloadFingerprint, now)
                    : states.fenceSubjectDelivery(realm, state.getId(), state.getVersion(), subject, sourceRevision, previousRevision, now);
            if (!confirmed) {
                throw new TransientDataAccessResourceException("OAuth subject predecessor is not yet delivered");
            }
        } finally {
            if (previousTenant == null) MDC.remove(tenantKey); else MDC.put(tenantKey, previousTenant);
            if (previousActor == null) MDC.remove(actorKey); else MDC.put(actorKey, previousActor);
        }
    }
}
