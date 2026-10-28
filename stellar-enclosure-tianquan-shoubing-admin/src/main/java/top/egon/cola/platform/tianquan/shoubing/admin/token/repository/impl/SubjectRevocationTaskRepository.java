package top.egon.cola.platform.tianquan.shoubing.admin.token.repository.impl;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.component.common.mybatis.business.EgonColaUserIdProvider;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.repo.IdentityDirectoryContext;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.support.OAuthTransactionFences;
import top.egon.cola.platform.tianquan.shoubing.admin.token.dao.SubjectRevocationTaskMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSecurityStateBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.SubjectRevocationTaskBO;

@Repository
@RequiredArgsConstructor
public class SubjectRevocationTaskRepository {
    private static final int PAGE_SIZE = 200;
    private final SubjectRevocationTaskMapper mapper;
    private final IdentityDirectoryContext directory;
    @Qualifier("egonColaMdcUserIdProvider") private final EgonColaUserIdProvider actor;
    @Qualifier("egonColaMybatisPlusClock") private final Clock clock;

    /** Caller already fenced the platform realm in the transaction that changed the subject. */
    @Transactional(propagation = Propagation.MANDATORY)
    public void enqueueForSubject(TrustedRealmBO platform, OAuthSecurityStateBO realmState,
            String subject, long revision, boolean enabled, String reason) {
        Objects.requireNonNull(platform, "platform").validateTrustedPartition();
        if (platform.getRealmType() != top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum.PLATFORM
                || platform.getStoragePartitionId() != directory.directoryPartitionId() || revision <= 0) {
            throw new IllegalArgumentException("OAUTH_SUBJECT_FANOUT_SCOPE_INVALID");
        }
        directory.withPlatformDirectoryPartition(() -> {
            long tenantId = directory.directoryPartitionId();
            long after = 0L;
            while (true) {
                List<Long> page = mapper.selectHistoryPage(tenantId, subject, after, PAGE_SIZE);
                long last = after;
                for (Long target : page) {
                    if (target == null || target <= last || target == tenantId) {
                        throw new IllegalStateException("OAUTH_SUBJECT_FANOUT_HISTORY_INVALID");
                    }
                    last = target;
                }
                Instant now = now();
                if (mapper.fenceHistoryPage(tenantId, realmState.getId(), realmState.getVersion(), subject,
                        after, last, page, page.size(), now, actor.currentUserId()) != 1) {
                    throw new OptimisticLockingFailureException("subject tenant history is not yet visible together");
                }
                realmState.setVersion(Math.addExact(realmState.getVersion(), 1L));
                OAuthTransactionFences.securityStateWritten(platform, realmState);
                for (Long target : page) {
                    var task = new SubjectRevocationTaskBO();
                    task.setId(SnowflakeIdGenerator.nextLongId()); task.setTenantId(tenantId); task.setVersion(0L);
                    task.setIdentitySub(subject); task.setTargetTenantId(Long.toString(target)); task.setSourceRevision(revision);
                    task.setSubjectEnabled(enabled); task.setReasonCode(reason);
                    if (mapper.insertTask(task, now, actor.currentUserId()) != 1) {
                        throw new IllegalStateException("OAUTH_SUBJECT_FANOUT_INSERT_FAILED");
                    }
                }
                if (page.isEmpty()) break;
                after = last;
            }
            return null;
        });
    }

    @Transactional(readOnly = true, timeout = 30)
    public List<SubjectRevocationTaskBO> due(int limit) {
        if (limit < 1 || limit > 200) throw new IllegalArgumentException("invalid subject revocation batch");
        return directory.withPlatformDirectoryPartition(() -> mapper.selectDue(directory.directoryPartitionId(), now(), limit));
    }

    @Transactional(timeout = 30)
    public boolean claim(SubjectRevocationTaskBO task, String owner, Duration lease) {
        requireOwner(owner);
        if (lease == null || lease.isZero() || lease.isNegative()) throw new IllegalArgumentException("invalid subject revocation lease");
        return directory.withPlatformDirectoryPartition(() -> {
            Instant now = now();
            int changed = mapper.claim(directory.directoryPartitionId(), task, owner, now.plus(lease), now, actor.currentUserId());
            if (changed == 1) {
                task.setVersion(Math.addExact(task.getVersion(), 1L)); task.setLeaseOwner(owner);
                int attempts = task.getAttemptCount() == null ? 0 : task.getAttemptCount();
                task.setAttemptCount(attempts == Integer.MAX_VALUE ? attempts : attempts + 1);
            }
            return changed == 1;
        });
    }

    @Transactional(timeout = 30)
    public boolean complete(SubjectRevocationTaskBO task, String owner) {
        requireOwner(owner);
        return directory.withPlatformDirectoryPartition(() -> mapper.complete(directory.directoryPartitionId(), task,
                owner, now(), actor.currentUserId()) == 1);
    }

    @Transactional(timeout = 30)
    public boolean retry(SubjectRevocationTaskBO task, String owner, Duration delay) {
        requireOwner(owner);
        if (delay == null || delay.isNegative() || delay.isZero()) throw new IllegalArgumentException("invalid subject revocation retry delay");
        return directory.withPlatformDirectoryPartition(() -> {
            Instant now = now();
            return mapper.retry(directory.directoryPartitionId(), task, owner, now.plus(delay), now, actor.currentUserId()) == 1;
        });
    }

    private Instant now() { return clock.instant().truncatedTo(ChronoUnit.MICROS); }
    private static void requireOwner(String owner) {
        if (owner == null || owner.isBlank() || owner.length() > 64) throw new IllegalArgumentException("invalid subject revocation owner");
    }
}
