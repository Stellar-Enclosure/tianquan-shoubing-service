package top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl;

import java.time.Duration;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthManagementRealmResolver;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.impl.SubjectRevocationTaskRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.TokenRevocationService;

/** Retries durable directory-shard intents until each target-shard transaction commits. */
@Component
@RequiredArgsConstructor
@Slf4j
public class SubjectRevocationTaskWorker {
    private static final Duration LEASE = Duration.ofMinutes(2);
    private final SubjectRevocationTaskRepository tasks;
    private final OAuthManagementRealmResolver realms;
    private final TokenRevocationService revocations;

    @Scheduled(fixedDelayString = "${egon.tianquan-shoubing.oauth.subject-revocation-delay:5000}")
    public void dispatch() {
        for (var task : tasks.due(100)) {
            String owner = UUID.randomUUID().toString();
            if (!tasks.claim(task, owner, LEASE)) continue;
            try {
                var realm = realms.resolveTenantForRevocation(task.getTargetTenantId());
                revocations.applySubjectTask(realm, task);
                if (!tasks.complete(task, owner)) {
                    log.warn("Subject revocation task lease changed before completion; taskId={}", task.getId());
                }
            } catch (RuntimeException failure) {
                try {
                    tasks.retry(task, owner, retryDelay(task.getAttemptCount()));
                } catch (RuntimeException retryFailure) {
                    failure.addSuppressed(retryFailure);
                }
                int attempts = task.getAttemptCount() == null ? 1 : Math.max(1, task.getAttemptCount());
                if ((attempts & (attempts - 1)) == 0) {
                    log.warn("Subject revocation task will be retried; taskId={}, attempts={}, failureType={}",
                            task.getId(), attempts, failure.getClass().getSimpleName());
                }
            }
        }
    }

    private static Duration retryDelay(Integer attemptCount) {
        int exponent = Math.min(6, Math.max(0, (attemptCount == null ? 1 : attemptCount) - 1));
        return Duration.ofSeconds(Math.min(300, 5L << exponent));
    }
}
