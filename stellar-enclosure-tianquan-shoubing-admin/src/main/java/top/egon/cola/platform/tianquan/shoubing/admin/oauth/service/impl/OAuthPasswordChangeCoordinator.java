package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import top.egon.cola.component.common.crypto.digest.Digests;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.component.common.mybatis.business.EgonColaUserIdProvider;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.repo.IdentityDirectoryContext;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.PasswordChangeReceiptMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthInteractionBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthInteractionRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.support.OAuthTransactionFences;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityFacade;
import top.egon.cola.platform.tianquan.shoubing.core.identity.PasswordCredential;
import top.egon.cola.platform.tianquan.shoubing.core.port.PasswordHashPort;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.repository.IdentityCredentialRepository;

/** Coordinates three local transactions; the directory receipt makes retries idempotent. */
@Component("oauthPasswordChangeCoordinator")
@RequiredArgsConstructor
public class OAuthPasswordChangeCoordinator {
    @Qualifier("transactionManager") private final PlatformTransactionManager transactionManager;
    @Qualifier("oAuthInteractionRepository") private final OAuthInteractionRepository interactions;
    @Qualifier("oAuthRealmRepository") private final OAuthRealmRepository realms;
    @Qualifier("identityFacade") private final IdentityFacade identities;
    @Qualifier("identityCredentialRepository") private final IdentityCredentialRepository credentials;
    @Qualifier("springPasswordHashAdapter") private final PasswordHashPort passwordHashes;
    private final IdentityDirectoryContext directory;
    private final PasswordChangeReceiptMapper receipts;
    @Qualifier("egonColaMdcUserIdProvider") private final EgonColaUserIdProvider actor;
    @Qualifier("idpClock") private final Clock clock;

    public void change(TrustedRealmBO realm, OAuthInteractionBO observed, char[] oldPassword, char[] newPassword) {
        Objects.requireNonNull(oldPassword, "oldPassword"); Objects.requireNonNull(newPassword, "newPassword");
        try {
            var claimed = transaction().execute(status -> {
                if (!OAuthTransactionFences.activeRealm(realms, realm)
                        || !interactions.claimPasswordChange(realm, observed, now())) {
                    throw new OptimisticLockingFailureException("OAuth password interaction changed before claim");
                }
                return observed.toBuilder().state("AUTHENTICATED").version(Math.addExact(observed.getVersion(), 1L)).build();
            });
            Objects.requireNonNull(claimed, "claimed interaction");
            String operationKey = Digests.sha256Hex("password-change-v1:" + realm.getStoragePartitionId() + ':'
                    + claimed.getInteractionId() + ':' + claimed.getRestrictedSubject() + ':' + claimed.getBrowserBindingDigest());
            transaction().executeWithoutResult(status -> directory.withPlatformDirectoryPartition(() -> {
                int inserted = receipts.insertIfAbsent(SnowflakeIdGenerator.nextLongId(), directory.directoryPartitionId(),
                        operationKey, claimed.getRestrictedSubject(), realm.getStoragePartitionId(), now(), actor.currentUserId());
                if (inserted == 1) {
                    identities.changePassword(claimed.getRestrictedSubject(), oldPassword, newPassword, now());
                } else if (inserted == 0) {
                    var credential = credentials.findByIdentitySub(claimed.getRestrictedSubject())
                            .filter(value -> value.status() == PasswordCredential.Status.ACTIVE)
                            .orElseThrow(() -> new org.springframework.dao.TransientDataAccessResourceException("Changed credential is not yet visible"));
                    if (!passwordHashes.matches(newPassword, credential.passwordHash())) {
                        throw new org.springframework.dao.TransientDataAccessResourceException("Changed credential is not yet visible or differs from the retry");
                    }
                } else {
                    throw new IllegalStateException("OAUTH_PASSWORD_RECEIPT_INSERT_INVALID");
                }
                return null;
            }));
            transaction().executeWithoutResult(status -> {
                if (!interactions.consumePasswordChange(realm, claimed, now())) {
                    throw new OptimisticLockingFailureException("OAuth password interaction changed before completion");
                }
            });
        } finally {
            Arrays.fill(oldPassword, '\0'); Arrays.fill(newPassword, '\0');
        }
    }

    private TransactionTemplate transaction() {
        var template = new TransactionTemplate(transactionManager);
        template.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        template.setTimeout(60);
        return template;
    }

    private java.time.Instant now() { return clock.instant().truncatedTo(ChronoUnit.MICROS); }
}
