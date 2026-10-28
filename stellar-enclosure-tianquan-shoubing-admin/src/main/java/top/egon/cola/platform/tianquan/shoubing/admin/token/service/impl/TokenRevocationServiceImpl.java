package top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import jakarta.annotation.PostConstruct;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.validation.annotation.Validated;
import top.egon.cola.component.common.crypto.digest.Digests;
import top.egon.cola.component.outbox.api.OutboxMessage;
import top.egon.cola.component.outbox.api.TransactionalOutbox;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.support.OAuthTransactionFences;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthorizationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthManagementRealmResolver;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthRevocationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSecurityStateBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthTokenBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.command.OAuthClientRevokeCommand;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.command.OAuthSubjectRevokeCommand;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.command.RevokeOAuthTokenCommand;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthTokenTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthRevocationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthTokenRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.TokenRevocationService;
import top.egon.cola.platform.tianquan.shoubing.core.audit.OAuthSecurityChangedEvent;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;

@Service("tokenRevocationService")
@Slf4j
@RequiredArgsConstructor
@Validated
public class TokenRevocationServiceImpl implements TokenRevocationService {

    private top.egon.cola.platform.tianquan.shoubing.admin.support.outbox.OAuthOutboxIdentity outboxIdentity =
            top.egon.cola.platform.tianquan.shoubing.admin.support.outbox.OAuthOutboxIdentity.singleGroup();
    private top.egon.cola.platform.tianquan.shoubing.admin.token.repository.impl.SubjectRevocationTaskRepository subjectTasks;
    private volatile top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthExecutionPrimaryGuard executionPrimary;

    @org.springframework.beans.factory.annotation.Autowired
    void setOutboxIdentity(top.egon.cola.platform.tianquan.shoubing.admin.support.outbox.OAuthOutboxIdentity identity) {
        this.outboxIdentity = Objects.requireNonNull(identity, "identity");
    }

    @org.springframework.beans.factory.annotation.Autowired
    void setSubjectTasks(top.egon.cola.platform.tianquan.shoubing.admin.token.repository.impl.SubjectRevocationTaskRepository tasks) {
        this.subjectTasks = Objects.requireNonNull(tasks, "tasks");
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setExecutionPrimary(@Qualifier("oauthExecutionPrimaryGuard")
            top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthExecutionPrimaryGuard guard) {
        this.executionPrimary = Objects.requireNonNull(guard, "guard");
    }

    private static final int TOKEN_PAGE_SIZE = 500;

    @Qualifier("oAuthRealmRepository")
    private final OAuthRealmRepository realmRepository;
    @Qualifier("oAuthClientRepository")
    private final OAuthClientRepository clientRepository;
    @Qualifier("oAuthAuthorizationRepository")
    private final OAuthAuthorizationRepository authorizationRepository;
    @Qualifier("oAuthTokenRepository")
    private final OAuthTokenRepository tokenRepository;
    @Qualifier("oAuthSecurityStateRepository")
    private final OAuthSecurityStateRepository stateRepository;
    @Qualifier("oAuthRevocationRepository")
    private final OAuthRevocationRepository revocationRepository;
    @Qualifier("oAuthAuditRepository")
    private final OAuthAuditRepository auditRepository;
    @Qualifier("transactionalOutbox")
    private final TransactionalOutbox outbox;
    @Qualifier("oauthSecurityProjectionComponent")
    private final OAuthSecurityProjectionComponent projectionComponent;
    @Qualifier("oauthManagementRealmResolver")
    private final OAuthManagementRealmResolver managementRealmResolver;
    @Qualifier("egonColaMybatisPlusClock")
    private final Clock clock;
    @Value("${egon.tianquan-shoubing.clock-skew:30s}")
    private final Duration clockSkew;
    @Qualifier("transactionManager")
    private final PlatformTransactionManager transactionManager;

    @PostConstruct
    void validateClockSkew() {
        if (clockSkew.isNegative() || clockSkew.compareTo(Duration.ofSeconds(60)) > 0) {
            throw new IllegalStateException("OAUTH_CLOCK_SKEW_INVALID");
        }
    }

    @Override
    @Transactional(transactionManager = "transactionManager", isolation = Isolation.REPEATABLE_READ)
    public void revokeExecutionGrant(TrustedRealmBO trustedRealm, String grantId, Instant intentDeadline) {
        var primary = executionPrimary;
        if (primary == null) throw unavailable("EXECUTION_AUTHORITY_PRIMARY_REQUIRED");
        primary.requirePrimaryTransaction();
        TrustedRealmBO realm = requireRealm(trustedRealm);
        if (realm.getBusinessTenantId() == null || grantId == null || !grantId.matches("[89][0-9]{62}") || intentDeadline == null
                || intentDeadline.isAfter(Instant.parse("9999-12-30T23:59:59Z"))) {
            throw new IllegalArgumentException("EXECUTION_GRANT_REVOCATION_INVALID");
        }
        if (!OAuthTransactionFences.realm(realmRepository, realm)) {
            throw unavailable("OAUTH_REVOCATION_REALM_NOT_READY");
        }
        OAuthSecurityStateBO realmState = requiredState(realm, OAuthSecurityTargetEnum.REALM, "self");
        Instant now = clock.instant().truncatedTo(ChronoUnit.MICROS);
        Instant minimum = now.plus(Duration.ofHours(8));
        Instant requestedExpiry = (intentDeadline.isAfter(minimum) ? intentDeadline : minimum).plus(clockSkew);
        Instant expiresAt = requestedExpiry.truncatedTo(ChronoUnit.MICROS);
        if (expiresAt.isBefore(requestedExpiry)) expiresAt = expiresAt.plus(1, ChronoUnit.MICROS);
        Instant retainUntil = expiresAt.plusSeconds(86_400);
        OAuthRevocationBO current = revocationRepository.findByTarget(realm, OAuthSecurityTargetEnum.JTI, grantId).orElse(null);
        boolean publish = false;
        if (current == null) {
            long revision = nextRevision(realmState, null, null);
            if (!stateRepository.advanceRealmIfRevocationAbsent(realm, realmState.getId(), realmState.getVersion(),
                    OAuthSecurityTargetEnum.JTI, grantId, revision, now)) {
                throw new org.springframework.dao.OptimisticLockingFailureException("OAuth execution grant revocation changed");
            }
            realmState.setVersion(Math.addExact(realmState.getVersion(), 1L)).setRevision(revision);
            OAuthTransactionFences.securityStateWritten(realm, realmState);
            current = revocationRepository.save(realm, OAuthRevocationBO.builder().version(0L)
                    .targetType(OAuthSecurityTargetEnum.JTI).targetKey(grantId).reasonCode("EXECUTION_GRANT_REVOKED")
                    .revokedAt(now).expiresAt(expiresAt).revision(revision).retainUntil(retainUntil).build(), 0L);
            publish = true;
        } else {
            if (!"EXECUTION_GRANT_REVOKED".equals(current.getReasonCode())) {
                throw unavailable("EXECUTION_GRANT_REVOCATION_COLLISION");
            }
            if (!revocationRepository.fenceObservedVersion(realm, current)) {
                throw new org.springframework.dao.OptimisticLockingFailureException("OAuth execution grant revocation changed");
            }
            current.setVersion(Math.addExact(current.getVersion(), 1L));
            if (current.getExpiresAt() != null && expiresAt.isAfter(current.getExpiresAt())) {
                long revision = Math.addExact(Math.max(realmState.getRevision(), current.getRevision()), 1L);
                saveRealmRevision(realm, realmState, revision);
                if (current.getRetainUntil() != null && current.getRetainUntil().isAfter(retainUntil)) {
                    retainUntil = current.getRetainUntil();
                }
                current = revocationRepository.save(realm, OAuthRevocationBO.builder().id(current.getId())
                        .version(Math.addExact(current.getVersion(), 1L)).targetType(OAuthSecurityTargetEnum.JTI)
                        .targetKey(grantId).reasonCode(current.getReasonCode()).revokedAt(current.getRevokedAt())
                        .expiresAt(expiresAt).revision(revision).retainUntil(retainUntil).build(), current.getVersion());
                publish = true;
            }
        }
        if (publish) {
            var event = event(realm, current.getRevision(), OAuthSecurityTargetEnum.JTI, grantId, null,
                    current.getExpiresAt(), current.getReasonCode(), now);
            saveAuditIfAbsent(realm, event, "EXECUTION_GRANT_REVOKED");
            enqueue(realm, event);
            registerProjectionAfterCommit(List.of(new ProjectionChange(realm, event, OAuthSecurityTargetEnum.JTI)));
        }
    }

    @Override
    @Transactional(transactionManager = "transactionManager")
    public void revoke(
            @NotNull @Valid TrustedRealmBO trustedRealm,
            @NotNull @Valid RevokeOAuthTokenCommand command) {
        revokeInternal(trustedRealm, command, false);
    }

    @Override
    @Transactional(transactionManager = "transactionManager")
    public void revokeKnown(
            @NotNull @Valid TrustedRealmBO trustedRealm,
            @NotNull @Valid RevokeOAuthTokenCommand command) {
        revokeInternal(trustedRealm, command, true);
    }

    private void revokeInternal(TrustedRealmBO trustedRealm, RevokeOAuthTokenCommand command, boolean tokenWasObserved) {
        TrustedRealmBO realm = requireRealm(trustedRealm);
        RevokeOAuthTokenCommand input = Objects.requireNonNull(command, "command");
        if (!OAuthTransactionFences.realm(realmRepository, realm)) {
            throw unavailable("OAUTH_REVOCATION_REALM_NOT_READY");
        }
        OAuthSecurityStateBO realmState = requiredState(realm, OAuthSecurityTargetEnum.REALM, "self");
        OAuthTokenBO tokenCandidate = tokenRepository.findByTokenDigest(realm, input.getTokenDigest())
                .orElse(null);
        if (tokenCandidate == null) {
            if (tokenWasObserved) { throw new org.springframework.dao.TransientDataAccessResourceException("observed token is not yet visible"); }
            // A replica miss is only idempotent once the primary condition confirms absence.
            if (!stateRepository.fenceRealmWhenTokenAbsent(realm, realmState.getId(), realmState.getVersion(),
                    input.getTokenDigest(), clock.instant())) {
                throw new org.springframework.dao.TransientDataAccessResourceException("token absence cannot yet be confirmed");
            }
            return;
        }
        OAuthAuthorizationBO authorizationCandidate = authorizationRepository.findById(
                        realm, tokenCandidate.getAuthorizationPk())
                .orElseThrow(() -> unavailable("OAUTH_REVOCATION_AUTHORIZATION_MISSING"));
        if (!Objects.equals(authorizationCandidate.getClientPk(), input.getClientPk())) {
            throw invalidClient();
        }
        OAuthClientBO clientCandidate = clientRepository.findById(realm, authorizationCandidate.getClientPk())
                .orElseThrow(() -> unavailable("OAUTH_REVOCATION_CLIENT_MISSING"));
        if (!Objects.equals(clientCandidate.getId(), input.getClientPk())) { throw invalidClient(); }
        if (!OAuthTransactionFences.client(clientRepository, realm, clientCandidate)) {
            throw new org.springframework.dao.OptimisticLockingFailureException("OAuth client changed before token revocation");
        }
        OAuthClientBO client = clientCandidate;
        OAuthSecurityStateBO clientState = requiredState(
                realm, OAuthSecurityTargetEnum.CLIENT, Long.toString(client.getId()));
        OAuthSecurityStateBO subjectState = "USER".equals(authorizationCandidate.getPrincipalType())
                ? requiredState(realm, OAuthSecurityTargetEnum.SUBJECT, authorizationCandidate.getPrincipalName())
                : null;
        OAuthAuthorizationBO authorization = authorizationCandidate;
        OAuthTokenBO token = tokenRepository.findByTokenDigest(realm, input.getTokenDigest())
                .orElse(null);
        if (token == null) {
            throw new org.springframework.dao.TransientDataAccessResourceException("observed token is not yet visible");
        }
        if (!Objects.equals(authorization.getClientPk(), input.getClientPk())
                || !Objects.equals(token.getAuthorizationPk(), authorization.getId())) {
            throw invalidClient();
        }

        Instant now = clock.instant().truncatedTo(ChronoUnit.MICROS);
        boolean family = token.getTokenType() == OAuthTokenTypeEnum.REFRESH
                || token.getTokenType() == OAuthTokenTypeEnum.CODE;
        OAuthSecurityTargetEnum targetType = family || token.getJti() == null
                ? OAuthSecurityTargetEnum.AUTHORIZATION : OAuthSecurityTargetEnum.JTI;
        String targetKey = targetType == OAuthSecurityTargetEnum.JTI
                ? token.getJti() : Long.toString(authorization.getId());
        Instant expiry = targetType == OAuthSecurityTargetEnum.JTI
                ? token.getExpiresAt() : authorization.getAbsoluteExpiresAt();
        Instant expiresAt = safeExpiry(expiry, now);

        if (family) {
            revokeAuthorizationFamily(realm, authorization, now);
        } else if (token.getRevokedAt() == null) {
            tokenRepository.save(realm, revoked(token, now), token.getVersion());
        }

        OAuthRevocationBO current = revocationRepository.findByTarget(realm, targetType, targetKey)
                .orElse(null);
        OAuthSecurityChangedEvent event;
        boolean enqueue = current == null;
        if (current == null) {
            long revision = nextRevision(realmState, clientState, subjectState);
            if (!stateRepository.advanceRealmIfRevocationAbsent(realm, realmState.getId(), realmState.getVersion(),
                    targetType, targetKey, revision, now)) {
                throw new org.springframework.dao.OptimisticLockingFailureException("OAuth revocation or realm state changed");
            }
            realmState.setVersion(Math.addExact(realmState.getVersion(), 1L)).setRevision(revision);
            OAuthTransactionFences.securityStateWritten(realm, realmState);
            OAuthRevocationBO created = OAuthRevocationBO.builder()
                    .version(0L)
                    .targetType(targetType)
                    .targetKey(targetKey)
                    .reasonCode(input.getReasonCode())
                    .revokedAt(now)
                    .expiresAt(expiresAt)
                    .revision(revision)
                    .retainUntil(expiresAt.plusSeconds(86_400))
                    .build();
            current = revocationRepository.save(realm, created, 0L);
            event = event(realm, current.getRevision(), targetType, targetKey, null,
                    current.getExpiresAt(), current.getReasonCode(), current.getRevokedAt());
            saveAuditIfAbsent(realm, event, "TOKEN_REVOKED");
        } else {
            if (!revocationRepository.fenceObservedVersion(realm, current)) {
                throw new org.springframework.dao.OptimisticLockingFailureException("OAuth revocation changed after the candidate read");
            }
            if (current.getExpiresAt() != null && expiresAt.isAfter(current.getExpiresAt())) {
                throw unavailable("OAUTH_REVOCATION_EXPIRY_CONFLICT");
            }
            event = event(realm, current.getRevision(), targetType, targetKey, null,
                    current.getExpiresAt(), current.getReasonCode(), current.getRevokedAt());
        }
        if (enqueue) {
            enqueue(realm, event);
        }
        registerProjectionAfterCommit(List.of(new ProjectionChange(realm, event, targetType)));
    }

    @Override
    @Transactional(transactionManager = "transactionManager")
    public void revokeSubject(@NotNull @Valid OAuthSubjectRevokeCommand command) {
        OAuthSubjectRevokeCommand input = Objects.requireNonNull(command, "command");
        TrustedRealmBO platformRealm = managementRealmResolver.platformRealm();
        List<OAuthRealmBO> registered = realmRepository.findAllByStoragePartition(platformRealm);
        if (registered.isEmpty()) {
            throw unavailable("OAUTH_REVOCATION_REALM_DIRECTORY_EMPTY");
        }
        List<ProjectionChange> projections = new ArrayList<>(registered.size());
        for (OAuthRealmBO realmRow : registered) {
            TrustedRealmBO realm = trustedRealm(realmRow);
            if (!OAuthTransactionFences.realm(realmRepository, realm)) {
                throw new org.springframework.dao.OptimisticLockingFailureException("OAuth realm changed before subject revocation");
            }
            OAuthSecurityStateBO realmState = requiredState(realm, OAuthSecurityTargetEnum.REALM, "self");
            OAuthSecurityStateBO subjectState = stateRepository.findByTarget(
                    realm, OAuthSecurityTargetEnum.SUBJECT, input.getSubject()).orElse(null);
            if (subjectState == null && hasAuthorizationHistory(realm, input.getSubject())) {
                throw unavailable("OAUTH_SECURITY_SUBJECT_STATE_MISSING_WITH_AUTHORIZATION");
            }
            Instant now = clock.instant().truncatedTo(ChronoUnit.MICROS);
            long revision = nextRevision(realmState, null, subjectState);
            long generation = subjectState == null ? 0L : Math.addExact(subjectState.getGeneration(), 1L);
            boolean enabled = switch (input.getReasonCode()) {
                case "USER_DISABLED" -> false;
                case "USER_ENABLED", "USER_CREATED" -> true;
                default -> subjectState == null || subjectState.isEnabled();
            };
            if (subjectState == null) {
                if (!stateRepository.advanceRealmIfSubjectAbsent(realm, realmState.getId(), realmState.getVersion(),
                        input.getSubject(), revision, now)) {
                    throw new org.springframework.dao.OptimisticLockingFailureException("OAuth subject state or authorization history changed");
                }
                realmState.setVersion(Math.addExact(realmState.getVersion(), 1L)).setRevision(revision);
                OAuthTransactionFences.securityStateWritten(realm, realmState);
            } else {
                realmState = saveRealmRevision(realm, realmState, revision);
            }
            OAuthSecurityStateBO changed = securityState(
                    subjectState, OAuthSecurityTargetEnum.SUBJECT, input.getSubject(),
                    generation, enabled, revision, input.getReasonCode());
            OAuthSecurityStateBO saved = stateRepository.save(
                    realm, changed, subjectState == null ? 0L : subjectState.getVersion());
            OAuthSecurityChangedEvent event = event(realm, revision, OAuthSecurityTargetEnum.SUBJECT,
                    input.getSubject(), saved.getGeneration(), null, input.getReasonCode(), now);
            saveAuditIfAbsent(realm, event, "SUBJECT_REVOKED");
            enqueue(realm, event);
            Objects.requireNonNull(subjectTasks, "subjectTasks").enqueueForSubject(realm, realmState,
                    input.getSubject(), revision, saved.isEnabled(), input.getReasonCode());
            projections.add(new ProjectionChange(realm, event, null));
        }
        registerProjectionAfterCommit(projections);
    }

    @Override
    @Transactional(transactionManager = "transactionManager")
    public void revokeClient(
            @NotNull @Valid TrustedRealmBO trustedRealm,
            @NotNull @Valid OAuthClientRevokeCommand command) {
        TrustedRealmBO realm = requireRealm(trustedRealm);
        OAuthClientRevokeCommand input = Objects.requireNonNull(command, "command");
        if (!OAuthTransactionFences.realm(realmRepository, realm)) {
            throw new org.springframework.dao.OptimisticLockingFailureException("OAuth realm changed before client revocation");
        }
        OAuthSecurityStateBO realmState = requiredState(realm, OAuthSecurityTargetEnum.REALM, "self");
        OAuthClientBO client = input.getWrittenClient();
        if (client != null) {
            if (!Objects.equals(client.getId(), input.getClientPk()) || !OAuthTransactionFences.isClientWritten(realm, client)) {
                throw new IllegalStateException("OAUTH_CLIENT_WRITE_PROOF_REQUIRED");
            }
        } else {
            client = clientRepository.findById(realm, input.getClientPk())
                    .orElseThrow(() -> unavailable("OAUTH_REVOCATION_CLIENT_MISSING"));
            if (!OAuthTransactionFences.client(clientRepository, realm, client)) {
                throw new org.springframework.dao.OptimisticLockingFailureException("OAuth client changed before client revocation");
            }
        }
        OAuthSecurityStateBO clientState = stateRepository.findByTarget(
                realm, OAuthSecurityTargetEnum.CLIENT, Long.toString(client.getId())).orElse(null);
        boolean created = clientState == null;
        if (created && !"CLIENT_CREATED".equals(input.getReasonCode())) {
            throw unavailable("OAUTH_SECURITY_CLIENT_STATE_MISSING");
        }
        Instant now = clock.instant().truncatedTo(ChronoUnit.MICROS);
        long revision = nextRevision(realmState, clientState, null);
        long generation = created ? 0L : Math.addExact(clientState.getGeneration(), 1L);
        boolean enabled = client.getStatus() == OAuthClient.Status.ACTIVE;
        saveRealmRevision(realm, realmState, revision);
        OAuthSecurityStateBO changed = securityState(
                clientState, OAuthSecurityTargetEnum.CLIENT, Long.toString(client.getId()),
                generation, enabled, revision, input.getReasonCode());
        OAuthSecurityStateBO saved = stateRepository.save(
                realm, changed, clientState == null ? 0L : clientState.getVersion());
        OAuthSecurityChangedEvent event = event(realm, revision, OAuthSecurityTargetEnum.CLIENT,
                Long.toString(client.getId()), saved.getGeneration(), null, input.getReasonCode(), now);
        saveAuditIfAbsent(realm, event, "CLIENT_SECURITY_CHANGED");
        enqueue(realm, event);
        registerProjectionAfterCommit(List.of(new ProjectionChange(realm, event, null)));
    }

    @Override
    @Transactional(transactionManager = "transactionManager", timeout = 60)
    public void applySubjectTask(TrustedRealmBO trustedRealm,
            top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.SubjectRevocationTaskBO task) {
        TrustedRealmBO realm = requireRealm(trustedRealm);
        Objects.requireNonNull(task, "task");
        if (realm.getBusinessTenantId() == null || task.getTargetTenantId() == null
                || !Long.toString(realm.getBusinessTenantId()).equals(task.getTargetTenantId())
                || task.getIdentitySub() == null || !task.getIdentitySub().matches("[A-Za-z0-9._~-]{1,64}")
                || task.getSourceRevision() == null || task.getSourceRevision() <= 0
                || task.getSubjectEnabled() == null || task.getReasonCode() == null
                || !task.getReasonCode().matches("[A-Z0-9_]{1,128}")) {
            throw new IllegalArgumentException("OAUTH_SUBJECT_TASK_INVALID");
        }
        if (!OAuthTransactionFences.realm(realmRepository, realm)) {
            throw new org.springframework.dao.OptimisticLockingFailureException("OAuth realm changed before subject propagation");
        }
        Instant now = clock.instant().truncatedTo(ChronoUnit.MICROS);
        OAuthSecurityStateBO current = stateRepository.findByTarget(realm, OAuthSecurityTargetEnum.SUBJECT,
                task.getIdentitySub()).orElse(null);
        String fingerprint = Digests.sha256Hex("subject-task-v1:" + task.getIdentitySub() + ":" + task.getTargetTenantId()
                + ":" + task.getSourceRevision() + ":" + task.getSubjectEnabled() + ":" + task.getReasonCode());
        if (current != null && current.getDirectorySubjectRevision() >= task.getSourceRevision()) {
            if (!stateRepository.fenceSubjectAtLeast(realm, current, task.getSourceRevision(), fingerprint, now)) {
                throw new org.springframework.dao.OptimisticLockingFailureException("OAuth subject propagation changed");
            }
            return;
        }
        OAuthSecurityStateBO realmState = requiredState(realm, OAuthSecurityTargetEnum.REALM, "self");
        long revision = nextRevision(realmState, null, current);
        if (current == null) {
            if (!stateRepository.advanceRealmIfSubjectAbsent(realm, realmState.getId(), realmState.getVersion(),
                    task.getIdentitySub(), revision, now)) {
                throw new org.springframework.dao.OptimisticLockingFailureException("OAuth subject is not yet safe to initialize");
            }
            realmState.setVersion(Math.addExact(realmState.getVersion(), 1L)).setRevision(revision);
            OAuthTransactionFences.securityStateWritten(realm, realmState);
        } else {
            saveRealmRevision(realm, realmState, revision);
        }
        long generation = current == null ? 0L : Math.addExact(current.getGeneration(), 1L);
        long previousDelivery = current == null ? 0L : current.getDirectorySubjectOrderedRevision();
        OAuthSecurityStateBO changed = securityState(current, OAuthSecurityTargetEnum.SUBJECT, task.getIdentitySub(),
                generation, task.getSubjectEnabled(), revision, task.getReasonCode())
                .setDirectorySubjectRevision(task.getSourceRevision()).setDirectorySubjectOrderedRevision(task.getSourceRevision())
                .setDirectorySubjectFingerprint(fingerprint);
        OAuthSecurityStateBO saved = stateRepository.save(realm, changed, current == null ? 0L : current.getVersion());
        OAuthSecurityChangedEvent event = event(realm, revision, OAuthSecurityTargetEnum.SUBJECT, task.getIdentitySub(),
                saved.getGeneration(), null, task.getReasonCode(), now);
        saveAuditIfAbsent(realm, event, "SUBJECT_REVOKED");
        enqueue(realm, event, task.getSourceRevision(), previousDelivery);
        registerProjectionAfterCommit(List.of(new ProjectionChange(realm, event, null)));
    }

    private void revokeAuthorizationFamily(TrustedRealmBO realm, OAuthAuthorizationBO authorization, Instant now) {
        if (!"REVOKED".equals(authorization.getStatus())) {
            OAuthAuthorizationBO changed = OAuthAuthorizationBO.builder()
                    .id(authorization.getId())
                    .version(Math.addExact(authorization.getVersion(), 1L))
                    .clientPk(authorization.getClientPk())
                    .principalName(authorization.getPrincipalName())
                    .principalType(authorization.getPrincipalType())
                    .grantType(authorization.getGrantType())
                    .authorizedScopes(authorization.getAuthorizedScopes())
                    .audiences(authorization.getAudiences())
                    .status("REVOKED")
                    .authTime(authorization.getAuthTime())
                    .acr(authorization.getAcr())
                    .attributes(authorization.getAttributes())
                    .absoluteExpiresAt(authorization.getAbsoluteExpiresAt())
                    .requestedScopes(authorization.getRequestedScopes())
                    .resourceUri(authorization.getResourceUri())
                    .authenticationJtiDigest(authorization.getAuthenticationJtiDigest())
                    .clientBrowserBindingDigest(authorization.getClientBrowserBindingDigest())
                    .interactionId(authorization.getInteractionId())
                    .deviceSessionId(authorization.getDeviceSessionId())
                    .refreshGeneration(authorization.getRefreshGeneration())
                    .retainUntil(authorization.getRetainUntil())
                    .revokedAt(now)
                    .build();
            authorizationRepository.save(realm, changed, authorization.getVersion());
        }
        for (OAuthTokenTypeEnum tokenType : OAuthTokenTypeEnum.values()) {
            long afterId = 0L;
            while (true) {
                List<OAuthTokenBO> page = tokenRepository.findByAuthorization(
                        realm, authorization.getId(), tokenType, afterId, TOKEN_PAGE_SIZE);
                if (page.isEmpty()) {
                    break;
                }
                for (OAuthTokenBO candidate : page) {
                    afterId = Objects.requireNonNull(candidate.getId(), "tokenId");
                    OAuthTokenBO current = tokenRepository.findByTokenDigest(
                                    realm, candidate.getTokenDigest())
                            .orElse(null);
                    if (current != null && current.getRevokedAt() == null) {
                        tokenRepository.save(realm, revoked(current, now), current.getVersion());
                    }
                }
                if (page.size() < TOKEN_PAGE_SIZE) {
                    break;
                }
            }
        }
    }

    private void registerProjectionAfterCommit(List<ProjectionChange> changes) {
        // The authoritative changes and outbox are already in the surrounding transaction.
        // No external acknowledgement can change a committed revocation's meaning.
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("OAUTH_REVOCATION_TRANSACTION_REQUIRED");
        }
    }

    private void saveAuditIfAbsent(TrustedRealmBO realm, OAuthSecurityChangedEvent event, String eventType) {
        if (auditRepository.findByEventId(realm, event.eventId()).isPresent()) {
            return;
        }
        OAuthAuditBO audit = OAuthAuditBO.builder()
                .version(0L)
                .eventId(event.eventId())
                .eventType(eventType)
                .result("SUCCESS")
                .reasonCode(event.reasonCode())
                .occurredAt(event.occurredAt())
                .auditKind("OAUTH")
                .publicId(event.eventId())
                .payload(JsonNodeFactory.instance.objectNode())
                .build();
        auditRepository.save(realm, audit, 0L);
    }

    private void enqueue(TrustedRealmBO realm, OAuthSecurityChangedEvent event) {
        enqueue(realm, event, null, 0L);
    }

    private void enqueue(TrustedRealmBO realm, OAuthSecurityChangedEvent event, Long sourceRevision, long previousRevision) {
        String idempotencyKey = "oauth-security:" + event.realmKey() + ":" + event.targetType()
                + ":" + event.targetKey() + ":" + event.revision();
        var scope = outboxIdentity.forTenant("oauth_security_state", realm.getStoragePartitionId());
        var message = OutboxMessage.builder()
                .messageId(event.eventId())
                .idempotencyKey(scope.idempotencyKey(idempotencyKey))
                .channel(OAuthSecurityChangedEvent.OUTBOX_CHANNEL)
                .destination(OAuthSecurityChangedEvent.OUTBOX_DESTINATION)
                .payload(event)
                .schemaVersion("1");
        if (sourceRevision != null) {
            message.header(OAuthSubjectDeliveryOrderService.SOURCE_REVISION_HEADER, Long.toString(sourceRevision))
                    .header(OAuthSubjectDeliveryOrderService.PREVIOUS_REVISION_HEADER, Long.toString(previousRevision));
        }
        outbox.enqueue(message.build());
    }

    private OAuthSecurityChangedEvent event(
            TrustedRealmBO realm,
            long revision,
            OAuthSecurityTargetEnum targetType,
            String targetKey,
            Long generation,
            Instant expiresAt,
            String reasonCode,
            Instant occurredAt) {
        String idempotencyKey = "oauth-security:" + realm.getRealmKey() + ":" + targetType.getCode()
                + ":" + targetKey + ":" + revision;
        return new OAuthSecurityChangedEvent(
                outboxIdentity.forTenant("oauth_security_state", realm.getStoragePartitionId()).messageId(Digests.sha256Hex(idempotencyKey)),
                1,
                realm.getIssuer(),
                realm.getRealmKey(),
                revision,
                targetType.getCode(),
                targetKey,
                generation,
                expiresAt,
                reasonCode,
                occurredAt,
                null);
    }

    private OAuthSecurityStateBO requiredState(
            TrustedRealmBO realm,
            OAuthSecurityTargetEnum targetType,
            String targetKey) {
        return stateRepository.findByTarget(realm, targetType, targetKey)
                .orElseThrow(() -> unavailable("OAUTH_SECURITY_STATE_MISSING"));
    }

    private OAuthSecurityStateBO saveRealmRevision(TrustedRealmBO realm, OAuthSecurityStateBO current, long revision) {
        return stateRepository.save(realm, securityState(
                current, OAuthSecurityTargetEnum.REALM, "self", current.getGeneration(),
                current.isEnabled(), revision, current.getReasonCode()), current.getVersion());
    }

    private OAuthSecurityStateBO securityState(
            OAuthSecurityStateBO current,
            OAuthSecurityTargetEnum targetType,
            String targetKey,
            long generation,
            boolean enabled,
            long revision,
            String reasonCode) {
        return OAuthSecurityStateBO.builder()
                .id(current == null ? null : current.getId())
                .version(current == null ? 0L : Math.addExact(current.getVersion(), 1L))
                .targetType(targetType)
                .targetKey(targetKey)
                .generation(generation)
                .enabled(enabled)
                .revision(revision)
                .directorySubjectRevision(current == null ? 0L : current.getDirectorySubjectRevision())
                .directorySubjectOrderedRevision(current == null ? 0L : current.getDirectorySubjectOrderedRevision())
                .directorySubjectFingerprint(current == null ? null : current.getDirectorySubjectFingerprint())
                .reasonCode(reasonCode)
                .build();
    }


    private OAuthTokenBO revoked(OAuthTokenBO current, Instant now) {
        return OAuthTokenBO.builder()
                .id(current.getId())
                .version(Math.addExact(current.getVersion(), 1L))
                .authorizationPk(current.getAuthorizationPk())
                .tokenType(current.getTokenType())
                .tokenDigest(current.getTokenDigest())
                .tokenValue(current.getTokenValue())
                .jti(current.getJti())
                .issuedAt(current.getIssuedAt())
                .expiresAt(current.getExpiresAt())
                .consumedAt(current.getConsumedAt())
                .revokedAt(now)
                .metadata(current.getMetadata())
                .refreshGeneration(current.getRefreshGeneration())
                .retainUntil(current.getRetainUntil())
                .build();
    }

    private long nextRevision(
            OAuthSecurityStateBO realmState,
            OAuthSecurityStateBO clientState,
            OAuthSecurityStateBO subjectState) {
        long current = realmState.getRevision();
        if (clientState != null) {
            current = Math.max(current, clientState.getRevision());
        }
        if (subjectState != null) {
            current = Math.max(current, subjectState.getRevision());
        }
        return Math.addExact(current, 1L);
    }

    private boolean hasAuthorizationHistory(TrustedRealmBO realm, String subject) {
        return !authorizationRepository.findByPrincipalName(realm, subject, "ACTIVE", 0L, 1).isEmpty()
                || !authorizationRepository.findByPrincipalName(realm, subject, "REVOKED", 0L, 1).isEmpty()
                || !authorizationRepository.findByPrincipalName(realm, subject, "EXPIRED", 0L, 1).isEmpty();
    }

    private Instant safeExpiry(Instant expiry, Instant now) {
        Instant value = Objects.requireNonNull(expiry, "tokenExpiry").plus(clockSkew);
        return value.isAfter(now) ? value : now.plusSeconds(1);
    }

    private static TrustedRealmBO requireRealm(TrustedRealmBO trustedRealm) {
        TrustedRealmBO realm = Objects.requireNonNull(trustedRealm, "trustedRealm");
        realm.validateTrustedPartition();
        return realm;
    }

    private static TrustedRealmBO trustedRealm(OAuthRealmBO realm) {
        OAuthRealmBO registered = Objects.requireNonNull(realm, "registeredRealm");
        TrustedRealmBO trusted = TrustedRealmBO.builder()
                .issuer(registered.getIssuer())
                .realmKey(registered.getRealmKey())
                .realmType(registered.getRealmType())
                .storagePartitionId(registered.getStoragePartitionId())
                .businessTenantId(registered.getBusinessTenantId())
                .trustVersion(registered.getTrustVersion())
                .build();
        trusted.validateTrustedPartition();
        return trusted;
    }

    private static OAuth2AuthenticationException invalidClient() {
        return new OAuth2AuthenticationException(
                new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, "Request rejected", null));
    }

    private static OAuth2AuthenticationException unavailable(String code) {
        return new OAuth2AuthenticationException(new OAuth2Error("temporarily_unavailable", code, null));
    }

    private static OAuth2AuthenticationException unavailable(String code, Throwable cause) {
        return new OAuth2AuthenticationException(new OAuth2Error("temporarily_unavailable", code, null), cause);
    }

    private record ProjectionChange(
            TrustedRealmBO realm,
            OAuthSecurityChangedEvent event,
            OAuthSecurityTargetEnum revocationTargetType) {
    }
}
