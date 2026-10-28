package top.egon.cola.platform.tianquan.shoubing.admin.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import top.egon.cola.component.outbox.api.OutboxMessage;
import top.egon.cola.component.outbox.api.OutboxReceipt;
import top.egon.cola.component.outbox.api.TransactionalOutbox;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationAttributesBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthSecuritySnapshotBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthorizationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthManagementRealmResolver;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthRevocationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSecurityStateBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthTokenBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthTokenMetadataBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.command.OAuthClientRevokeCommand;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.command.OAuthSubjectRevokeCommand;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.command.RevokeOAuthTokenCommand;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthTokenTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthRevocationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthTokenRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthSecurityProjectionComponent;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.TokenRevocationServiceImpl;
import top.egon.cola.platform.tianquan.shoubing.core.audit.OAuthSecurityChangedEvent;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;

class TokenRevocationServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-08T12:00:00Z");
    private static final String TOKEN_DIGEST = "a".repeat(64);
    private static final TrustedRealmBO REALM = TrustedRealmBO.builder()
            .issuer(URI.create("https://idp.example/tenants/1001"))
            .realmKey("tenant:1001")
            .realmType(RealmTypeEnum.TENANT)
            .storagePartitionId(1001L)
            .businessTenantId(1001L)
            .trustVersion(0L)
            .build();

    private final OAuthRealmRepository realms = mock(OAuthRealmRepository.class);
    private final OAuthClientRepository clients = mock(OAuthClientRepository.class);
    private final OAuthAuthorizationRepository authorizations = mock(OAuthAuthorizationRepository.class);
    private final OAuthTokenRepository tokens = mock(OAuthTokenRepository.class);
    private final OAuthSecurityStateRepository states = mock(OAuthSecurityStateRepository.class);
    private final OAuthRevocationRepository revocations = mock(OAuthRevocationRepository.class);
    private final OAuthAuditRepository audits = mock(OAuthAuditRepository.class);
    private final TransactionalOutbox outbox = mock(TransactionalOutbox.class);
    private final OAuthSecurityProjectionComponent projection = mock(OAuthSecurityProjectionComponent.class);
    private final OAuthManagementRealmResolver managementRealms = mock(OAuthManagementRealmResolver.class);
    private final top.egon.cola.platform.tianquan.shoubing.admin.token.repository.impl.SubjectRevocationTaskRepository subjectTasks =
            mock(top.egon.cola.platform.tianquan.shoubing.admin.token.repository.impl.SubjectRevocationTaskRepository.class);
    private final PlatformTransactionManager transactionManager = mock(PlatformTransactionManager.class);
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private TokenRevocationServiceImpl service;

    @BeforeEach
    void setUp() {
        TransactionStatus status = mock(TransactionStatus.class);
        when(status.isNewTransaction()).thenReturn(true);
        when(transactionManager.getTransaction(any())).thenReturn(status);
        when(outbox.enqueue(any(OutboxMessage.class))).thenAnswer(invocation -> {
            OutboxMessage message = invocation.getArgument(0);
            return new OutboxReceipt(message.messageId(), message.idempotencyKey(), true);
        });
        when(audits.findByEventId(eq(REALM), any())).thenReturn(Optional.empty());
        when(realms.fenceObservedVersion(REALM)).thenReturn(true);
        when(clients.fenceObservedVersion(eq(REALM), any())).thenReturn(true);
        when(states.advanceRealmIfRevocationAbsent(eq(REALM), anyLong(), anyLong(), any(), anyString(), anyLong(), any())).thenReturn(true);
        when(revocations.fenceObservedVersion(eq(REALM), any())).thenReturn(true);
        service = new TokenRevocationServiceImpl(
                realms, clients, authorizations, tokens, states, revocations, audits,
                outbox, projection, managementRealms, clock, Duration.ofSeconds(30), transactionManager);
        org.springframework.test.util.ReflectionTestUtils.setField(service, "subjectTasks", subjectTasks);
    }

    @AfterEach
    void clearTransactionSynchronization() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.getSynchronizations().forEach(sync ->
                    sync.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));
            TransactionSynchronizationManager.clearSynchronization();
        }
        TransactionSynchronizationManager.setActualTransactionActive(false);
    }

    @Test
    void revokesAccessTokenAndRetainsItsTombstoneInThePrimaryTransaction() {
        OAuthSecurityStateBO realmState = securityState(OAuthSecurityTargetEnum.REALM, "self", 1L, 7L);
        OAuthSecurityStateBO clientState = securityState(OAuthSecurityTargetEnum.CLIENT, "501", 2L, 8L);
        OAuthSecurityStateBO subjectState = securityState(OAuthSecurityTargetEnum.SUBJECT, "alice", 3L, 9L);
        OAuthClientBO client = client();
        OAuthAuthorizationBO authorization = authorization();
        OAuthTokenBO token = token();
        when(realms.findByRealmKeyForUpdate(REALM)).thenReturn(Optional.of(realmRow()));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self"))
                .thenReturn(Optional.of(realmState));
        when(tokens.findByTokenDigest(REALM, TOKEN_DIGEST)).thenReturn(Optional.of(token));
        when(authorizations.findById(REALM, 700L)).thenReturn(Optional.of(authorization));
        when(clients.findById(REALM, 501L)).thenReturn(Optional.of(client));
        when(clients.findByClientIdForUpdate(REALM, "web-client")).thenReturn(Optional.of(client));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.CLIENT, "501"))
                .thenReturn(Optional.of(clientState));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.SUBJECT, "alice"))
                .thenReturn(Optional.of(subjectState));
        when(revocations.findByTarget(REALM, OAuthSecurityTargetEnum.JTI, "123456"))
                .thenReturn(Optional.empty(), Optional.of(pendingJti()));
        when(states.save(eq(REALM), any(OAuthSecurityStateBO.class), eq(0L)))
                .thenAnswer(invocation -> invocation.getArgument(1));
        when(revocations.save(eq(REALM), any(OAuthRevocationBO.class), eq(0L)))
                .thenAnswer(invocation -> {
                    OAuthRevocationBO value = invocation.getArgument(1);
                    value.setId(800L);
                    return value;
                });

        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        service.revoke(REALM, RevokeOAuthTokenCommand.builder()
                .tokenDigest(TOKEN_DIGEST).clientPk(501L).reasonCode("ADMIN_REVOKE").build());
        List<TransactionSynchronization> callbacks = TransactionSynchronizationManager.getSynchronizations();
        callbacks.forEach(TransactionSynchronization::afterCommit);

        ArgumentCaptor<OAuthTokenBO> tokenChange = ArgumentCaptor.forClass(OAuthTokenBO.class);
        verify(realms).fenceObservedVersion(REALM);
        verify(realms, never()).findByRealmKeyForUpdate(REALM);
        verify(clients).fenceObservedVersion(REALM, client);
        verify(clients, never()).findByClientIdForUpdate(any(), anyString());
        verify(states, never()).findByTargetForUpdate(any(), any(), anyString());
        verify(revocations, never()).findByTargetForUpdate(any(), any(), anyString());
        verify(tokens).save(eq(REALM), tokenChange.capture(), eq(0L));
        verify(authorizations, never()).findByIdForUpdate(any(), anyLong());
        verify(tokens, never()).findByTokenDigestForUpdate(any(), anyString());
        assertThat(tokenChange.getValue().getRevokedAt()).isEqualTo(NOW);
        ArgumentCaptor<OutboxMessage> outboxMessage = ArgumentCaptor.forClass(OutboxMessage.class);
        verify(outbox).enqueue(outboxMessage.capture());
        OAuthSecurityChangedEvent event = (OAuthSecurityChangedEvent) outboxMessage.getValue().payload();
        assertThat(event.targetType()).isEqualTo("JTI");
        assertThat(event.targetKey()).isEqualTo("123456");
        assertThat(event.revision()).isEqualTo(10L);
        assertThat(event.toString()).doesNotContain(TOKEN_DIGEST);
        verify(audits).save(eq(REALM), any(OAuthAuditBO.class), eq(0L));
        verify(projection, never()).applyProjection(any(), any());
        ArgumentCaptor<OAuthRevocationBO> statuses = ArgumentCaptor.forClass(OAuthRevocationBO.class);
        verify(revocations).save(eq(REALM), statuses.capture(), eq(0L));
        assertThat(statuses.getValue().getRetainUntil()).isAfter(statuses.getValue().getExpiresAt());
    }

    @Test
    void staleRealmCandidateRollsBackBeforeTokenRevocation() {
        when(realms.fenceObservedVersion(REALM)).thenReturn(false);
        var transaction = new org.springframework.transaction.support.TransactionTemplate(transactionManager);
        var command = RevokeOAuthTokenCommand.builder().tokenDigest(TOKEN_DIGEST).clientPk(501L).reasonCode("ADMIN_REVOKE").build();

        assertThatThrownBy(() -> transaction.executeWithoutResult(status -> service.revoke(REALM, command)))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(error -> assertThat(((OAuth2AuthenticationException) error).getError().getErrorCode())
                        .isEqualTo("temporarily_unavailable"));
        verify(transactionManager).rollback(any());
        verifyNoInteractions(tokens, states, authorizations, revocations);
    }

    @Test
    void staleClientCandidateRollsBackBeforeTokenOrOutboxWrites() {
        OAuthTokenBO token = token();
        OAuthClientBO client = client();
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.REALM, "self", 1L, 7L)));
        when(tokens.findByTokenDigest(REALM, TOKEN_DIGEST)).thenReturn(Optional.of(token));
        when(authorizations.findById(REALM, 700L)).thenReturn(Optional.of(authorization()));
        when(clients.findById(REALM, 501L)).thenReturn(Optional.of(client));
        when(clients.fenceObservedVersion(REALM, client)).thenReturn(false);
        var transaction = new org.springframework.transaction.support.TransactionTemplate(transactionManager);
        var command = RevokeOAuthTokenCommand.builder().tokenDigest(TOKEN_DIGEST).clientPk(501L).reasonCode("ADMIN_REVOKE").build();

        assertThatThrownBy(() -> transaction.executeWithoutResult(status -> service.revoke(REALM, command)))
                .isInstanceOf(org.springframework.dao.OptimisticLockingFailureException.class);
        verify(transactionManager).rollback(any());
        verify(tokens, never()).save(any(), any(), anyLong());
        verifyNoInteractions(revocations);
        verify(outbox, never()).enqueue(any(OutboxMessage.class));
    }

    @Test
    void revocationMissingOnReplicaButPresentOnPrimaryRollsBackBeforeOutbox() {
        OAuthTokenBO token = token(); OAuthClientBO client = client();
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.REALM, "self", 1L, 7L)));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.CLIENT, "501"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.CLIENT, "501", 2L, 8L)));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.SUBJECT, "alice"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.SUBJECT, "alice", 3L, 9L)));
        when(tokens.findByTokenDigest(REALM, TOKEN_DIGEST)).thenReturn(Optional.of(token));
        when(authorizations.findById(REALM, 700L)).thenReturn(Optional.of(authorization()));
        when(clients.findById(REALM, 501L)).thenReturn(Optional.of(client));
        when(revocations.findByTarget(REALM, OAuthSecurityTargetEnum.JTI, "123456")).thenReturn(Optional.empty());
        when(states.advanceRealmIfRevocationAbsent(eq(REALM), anyLong(), anyLong(), any(), anyString(), anyLong(), any())).thenReturn(false);
        var transaction = new org.springframework.transaction.support.TransactionTemplate(transactionManager);

        assertThatThrownBy(() -> transaction.executeWithoutResult(status -> service.revoke(REALM,
                RevokeOAuthTokenCommand.builder().tokenDigest(TOKEN_DIGEST).clientPk(501L).reasonCode("ADMIN_REVOKE").build())))
                .isInstanceOf(org.springframework.dao.OptimisticLockingFailureException.class);
        verify(transactionManager).rollback(any());
        verify(revocations, never()).save(any(), any(), anyLong());
        verify(outbox, never()).enqueue(any(OutboxMessage.class));
    }

    @Test
    void invalidClientBindingDoesNotWriteOrEnqueue() {
        OAuthTokenBO token = token();
        when(realms.findByRealmKeyForUpdate(REALM)).thenReturn(Optional.of(realmRow()));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.REALM, "self", 1L, 7L)));
        when(tokens.findByTokenDigest(REALM, TOKEN_DIGEST)).thenReturn(Optional.of(token));
        when(authorizations.findById(REALM, 700L)).thenReturn(Optional.of(authorization()));

        assertThatThrownBy(() -> service.revoke(REALM, RevokeOAuthTokenCommand.builder()
                .tokenDigest(TOKEN_DIGEST).clientPk(999L).reasonCode("ADMIN_REVOKE").build()))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(failure -> assertThat(((OAuth2AuthenticationException) failure)
                        .getError().getErrorCode()).isEqualTo("invalid_client"));

        verify(tokens, never()).save(eq(REALM), any(OAuthTokenBO.class), anyLong());
        verify(revocations, never()).save(eq(REALM), any(OAuthRevocationBO.class), anyLong());
        verify(outbox, never()).enqueue(any(OutboxMessage.class));
    }

    @Test
    void refreshRevocationCancelsTheAuthorizationFamilyBeforeReturning() {
        OAuthSecurityStateBO realmState = securityState(OAuthSecurityTargetEnum.REALM, "self", 1L, 7L);
        OAuthSecurityStateBO clientState = securityState(OAuthSecurityTargetEnum.CLIENT, "501", 2L, 8L);
        OAuthSecurityStateBO subjectState = securityState(OAuthSecurityTargetEnum.SUBJECT, "alice", 3L, 9L);
        OAuthClientBO client = client();
        OAuthAuthorizationBO authorization = authorization()
                .setRequestedScopes(List.of("openid", "orders.read"))
                .setResourceUri("https://api.example/resource")
                .setAuthenticationJtiDigest("d".repeat(64))
                .setClientBrowserBindingDigest("e".repeat(64))
                .setInteractionId("interaction-1")
                .setDeviceSessionId(73L)
                .setRefreshGeneration(7L)
                .setRetainUntil(NOW.plusSeconds(90_000));
        OAuthTokenBO access = token().setId(701L).setTokenType(OAuthTokenTypeEnum.ACCESS)
                .setTokenDigest("b".repeat(64)).setJti("123457");
        OAuthTokenBO refresh = token().setId(702L).setTokenType(OAuthTokenTypeEnum.REFRESH)
                .setTokenDigest("c".repeat(64)).setJti("123458").setRefreshGeneration(7L)
                .setRetainUntil(NOW.plusSeconds(90_000));
        when(realms.findByRealmKeyForUpdate(REALM)).thenReturn(Optional.of(realmRow()));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self"))
                .thenReturn(Optional.of(realmState));
        when(tokens.findByTokenDigest(REALM, refresh.getTokenDigest())).thenReturn(Optional.of(refresh));
        when(authorizations.findById(REALM, 700L)).thenReturn(Optional.of(authorization));
        when(clients.findById(REALM, 501L)).thenReturn(Optional.of(client));
        when(clients.findByClientIdForUpdate(REALM, "web-client")).thenReturn(Optional.of(client));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.CLIENT, "501"))
                .thenReturn(Optional.of(clientState));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.SUBJECT, "alice"))
                .thenReturn(Optional.of(subjectState));
        when(tokens.findByTokenDigest(eq(REALM), anyString())).thenAnswer(invocation -> {
            String digest = invocation.getArgument(1);
            if (refresh.getTokenDigest().equals(digest)) {
                return Optional.of(refresh);
            }
            if (access.getTokenDigest().equals(digest)) {
                return Optional.of(access);
            }
            return Optional.empty();
        });
        when(tokens.findByAuthorization(eq(REALM), eq(700L), any(), anyLong(), eq(500)))
                .thenAnswer(invocation -> {
                    OAuthTokenTypeEnum tokenType = invocation.getArgument(2);
                    if (tokenType == OAuthTokenTypeEnum.ACCESS) {
                        return List.of(access);
                    }
                    if (tokenType == OAuthTokenTypeEnum.REFRESH) {
                        return List.of(refresh);
                    }
                    return List.of();
                });
        when(revocations.findByTarget(REALM, OAuthSecurityTargetEnum.AUTHORIZATION, "700"))
                .thenReturn(Optional.empty(), Optional.of(OAuthRevocationBO.builder()
                        .id(801L).version(0L).targetType(OAuthSecurityTargetEnum.AUTHORIZATION)
                        .targetKey("700").reasonCode("ADMIN_REVOKE").revokedAt(NOW)
                        .expiresAt(NOW.plusSeconds(3630)).revision(10L).build()));
        when(states.save(eq(REALM), any(OAuthSecurityStateBO.class), eq(0L)))
                .thenAnswer(invocation -> invocation.getArgument(1));
        when(authorizations.save(eq(REALM), any(OAuthAuthorizationBO.class), eq(0L)))
                .thenAnswer(invocation -> invocation.getArgument(1));
        when(tokens.save(eq(REALM), any(OAuthTokenBO.class), eq(0L)))
                .thenAnswer(invocation -> invocation.getArgument(1));
        when(revocations.save(eq(REALM), any(OAuthRevocationBO.class), eq(0L)))
                .thenAnswer(invocation -> {
                    OAuthRevocationBO value = invocation.getArgument(1);
                    if (value.getId() == null) {
                        value.setId(801L);
                    }
                    return value;
                });

        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        service.revoke(REALM, RevokeOAuthTokenCommand.builder()
                .tokenDigest(refresh.getTokenDigest()).clientPk(501L).reasonCode("ADMIN_REVOKE").build());
        TransactionSynchronizationManager.getSynchronizations().forEach(TransactionSynchronization::afterCommit);

        ArgumentCaptor<OAuthAuthorizationBO> authorizationChange = ArgumentCaptor.forClass(OAuthAuthorizationBO.class);
        verify(authorizations).save(eq(REALM), authorizationChange.capture(), eq(0L));
        assertThat(authorizationChange.getValue().getStatus()).isEqualTo("REVOKED");
        assertThat(authorizationChange.getValue().getRequestedScopes()).isEqualTo(authorization.getRequestedScopes());
        assertThat(authorizationChange.getValue().getResourceUri()).isEqualTo(authorization.getResourceUri());
        assertThat(authorizationChange.getValue().getAuthenticationJtiDigest()).isEqualTo(authorization.getAuthenticationJtiDigest());
        assertThat(authorizationChange.getValue().getClientBrowserBindingDigest()).isEqualTo(authorization.getClientBrowserBindingDigest());
        assertThat(authorizationChange.getValue().getInteractionId()).isEqualTo(authorization.getInteractionId());
        assertThat(authorizationChange.getValue().getDeviceSessionId()).isEqualTo(authorization.getDeviceSessionId());
        assertThat(authorizationChange.getValue().getRefreshGeneration()).isEqualTo(authorization.getRefreshGeneration());
        assertThat(authorizationChange.getValue().getRetainUntil()).isEqualTo(authorization.getRetainUntil());
        assertAuthorizationRevocationPassesPersistenceGuards(authorization, authorizationChange.getValue());
        ArgumentCaptor<OAuthTokenBO> tokenChanges = ArgumentCaptor.forClass(OAuthTokenBO.class);
        verify(tokens, org.mockito.Mockito.times(2)).save(eq(REALM), tokenChanges.capture(), eq(0L));
        assertThat(tokenChanges.getAllValues()).allSatisfy(value -> assertThat(value.getRevokedAt()).isEqualTo(NOW));
        assertThat(tokenChanges.getAllValues()).filteredOn(value -> value.getTokenType() == OAuthTokenTypeEnum.REFRESH)
                .singleElement().satisfies(value -> {
                    assertThat(value.getRefreshGeneration()).isEqualTo(7L);
                    assertThat(value.getRetainUntil()).isEqualTo(NOW.plusSeconds(90_000));
                });
        ArgumentCaptor<OutboxMessage> outboxMessage = ArgumentCaptor.forClass(OutboxMessage.class);
        verify(outbox).enqueue(outboxMessage.capture());
        OAuthSecurityChangedEvent event = (OAuthSecurityChangedEvent) outboxMessage.getValue().payload();
        assertThat(event.targetType()).isEqualTo("AUTHORIZATION");
        assertThat(event.targetKey()).isEqualTo("700");
        verify(projection, never()).applyProjection(any(), any());
    }

    @Test
    void staleAuthorizationRollsBackFamilyRevocationBeforeOutboxEnqueue() {
        OAuthTokenBO refresh = token().setTokenType(OAuthTokenTypeEnum.REFRESH);
        OAuthAuthorizationBO authorization = authorization();
        OAuthClientBO client = client();
        when(realms.findByRealmKeyForUpdate(REALM)).thenReturn(Optional.of(realmRow()));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.REALM, "self", 1L, 7L)));
        when(tokens.findByTokenDigest(REALM, TOKEN_DIGEST)).thenReturn(Optional.of(refresh));
        when(authorizations.findById(REALM, 700L)).thenReturn(Optional.of(authorization));
        when(clients.findById(REALM, 501L)).thenReturn(Optional.of(client));
        when(clients.findByClientIdForUpdate(REALM, "web-client")).thenReturn(Optional.of(client));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.CLIENT, "501"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.CLIENT, "501", 2L, 8L)));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.SUBJECT, "alice"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.SUBJECT, "alice", 3L, 9L)));
        org.mockito.Mockito.doThrow(new org.springframework.dao.OptimisticLockingFailureException("stale authorization"))
                .when(authorizations).save(eq(REALM), any(), eq(0L));
        var transaction = new org.springframework.transaction.support.TransactionTemplate(transactionManager);

        assertThatThrownBy(() -> transaction.executeWithoutResult(status -> service.revoke(REALM,
                RevokeOAuthTokenCommand.builder().tokenDigest(TOKEN_DIGEST).clientPk(501L).reasonCode("ADMIN_REVOKE").build())))
                .isInstanceOf(org.springframework.dao.OptimisticLockingFailureException.class);
        verify(transactionManager).rollback(any());
        verify(authorizations, never()).findByIdForUpdate(any(), anyLong());
        verify(outbox, never()).enqueue(any(OutboxMessage.class));
    }

    @Test
    void observedTokenMissingOnReplicaIsRetryableWhileUnknownRevocationRemainsIdempotent() {
        when(realms.findByRealmKeyForUpdate(REALM)).thenReturn(Optional.of(realmRow()));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.REALM, "self", 1L, 7L)));
        when(tokens.findByTokenDigest(REALM, TOKEN_DIGEST)).thenReturn(Optional.empty());
        when(states.fenceRealmWhenTokenAbsent(REALM, 1L, 0L, TOKEN_DIGEST, NOW)).thenReturn(true);
        var command = RevokeOAuthTokenCommand.builder().tokenDigest(TOKEN_DIGEST).clientPk(501L).reasonCode("REFRESH_TOKEN_REPLAY").build();

        service.revoke(REALM, command);
        assertThatThrownBy(() -> service.revokeKnown(REALM, command))
                .isInstanceOf(org.springframework.dao.TransientDataAccessResourceException.class);
        verify(states).fenceRealmWhenTokenAbsent(REALM, 1L, 0L, TOKEN_DIGEST, NOW);
        verify(outbox, never()).enqueue(any(OutboxMessage.class));
    }

    @Test
    void replicaMissCannotReportAnUnknownTokenWhenThePrimaryConditionDoesNotConfirmAbsence() {
        when(realms.findByRealmKeyForUpdate(REALM)).thenReturn(Optional.of(realmRow()));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.REALM, "self", 1L, 7L)));
        when(tokens.findByTokenDigest(REALM, TOKEN_DIGEST)).thenReturn(Optional.empty());
        when(states.fenceRealmWhenTokenAbsent(REALM, 1L, 0L, TOKEN_DIGEST, NOW)).thenReturn(false);
        var transaction = new org.springframework.transaction.support.TransactionTemplate(transactionManager);
        var command = RevokeOAuthTokenCommand.builder().tokenDigest(TOKEN_DIGEST).clientPk(501L).reasonCode("ADMIN_REVOKE").build();

        assertThatThrownBy(() -> transaction.executeWithoutResult(status -> service.revoke(REALM, command)))
                .isInstanceOf(org.springframework.dao.TransientDataAccessResourceException.class);
        verify(transactionManager).rollback(any());
        verify(outbox, never()).enqueue(any(OutboxMessage.class));
        verifyNoInteractions(authorizations);
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    void observedTokenMissingDuringSecondLookupRollsBackRevocation(boolean alreadyObservedByCaller) {
        OAuthTokenBO refresh = token().setTokenType(OAuthTokenTypeEnum.REFRESH);
        OAuthAuthorizationBO authorization = authorization(); OAuthClientBO client = client();
        when(realms.findByRealmKeyForUpdate(REALM)).thenReturn(Optional.of(realmRow()));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.REALM, "self", 1L, 7L)));
        when(tokens.findByTokenDigest(REALM, TOKEN_DIGEST)).thenReturn(Optional.of(refresh), Optional.empty());
        when(authorizations.findById(REALM, 700L)).thenReturn(Optional.of(authorization));
        when(clients.findById(REALM, 501L)).thenReturn(Optional.of(client));
        when(clients.findByClientIdForUpdate(REALM, "web-client")).thenReturn(Optional.of(client));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.CLIENT, "501"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.CLIENT, "501", 2L, 8L)));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.SUBJECT, "alice"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.SUBJECT, "alice", 3L, 9L)));
        var transaction = new org.springframework.transaction.support.TransactionTemplate(transactionManager);
        var command = RevokeOAuthTokenCommand.builder().tokenDigest(TOKEN_DIGEST).clientPk(501L).reasonCode("REFRESH_TOKEN_REPLAY").build();

        assertThatThrownBy(() -> transaction.executeWithoutResult(status -> {
            if (alreadyObservedByCaller) {
                service.revokeKnown(REALM, command);
            } else {
                service.revoke(REALM, command);
            }
        }))
                .isInstanceOf(org.springframework.dao.TransientDataAccessResourceException.class);
        verify(transactionManager).rollback(any());
        verify(authorizations, never()).save(any(), any(), anyLong());
        verify(outbox, never()).enqueue(any(OutboxMessage.class));
    }

    @Test
    void clientCreationSeedsGenerationZeroAndUsesRealmScopedOutboxEvent() {
        OAuthSecurityStateBO realmState = securityState(OAuthSecurityTargetEnum.REALM, "self", 1L, 7L);
        OAuthClientBO client = client();
        when(realms.findByRealmKeyForUpdate(REALM)).thenReturn(Optional.of(realmRow()));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self"))
                .thenReturn(Optional.of(realmState));
        when(clients.findById(REALM, 501L)).thenReturn(Optional.of(client));
        when(clients.findByClientIdForUpdate(REALM, "web-client")).thenReturn(Optional.of(client));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.CLIENT, "501"))
                .thenReturn(Optional.empty());
        when(states.save(eq(REALM), any(OAuthSecurityStateBO.class), eq(0L)))
                .thenAnswer(invocation -> invocation.getArgument(1));

        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        service.revokeClient(REALM, new OAuthClientRevokeCommand(501L, "CLIENT_CREATED"));
        TransactionSynchronizationManager.getSynchronizations().forEach(TransactionSynchronization::afterCommit);

        ArgumentCaptor<OAuthSecurityStateBO> stateChange = ArgumentCaptor.forClass(OAuthSecurityStateBO.class);
        verify(states, org.mockito.Mockito.times(2)).save(eq(REALM), stateChange.capture(), anyLong());
        OAuthSecurityStateBO clientState = stateChange.getAllValues().get(1);
        assertThat(clientState.getTargetType()).isEqualTo(OAuthSecurityTargetEnum.CLIENT);
        assertThat(clientState.getGeneration()).isZero();
        assertThat(clientState.isEnabled()).isTrue();
        ArgumentCaptor<OutboxMessage> outboxMessage = ArgumentCaptor.forClass(OutboxMessage.class);
        verify(outbox).enqueue(outboxMessage.capture());
        assertThat(((OAuthSecurityChangedEvent) outboxMessage.getValue().payload()).targetType())
                .isEqualTo("CLIENT");
        verify(states, never()).findByTargetForUpdate(any(), any(), anyString());
    }

    @Test
    void clientRevocationUsesTheClientWrittenInTheSameTransaction() {
        OAuthSecurityStateBO realmState = securityState(OAuthSecurityTargetEnum.REALM, "self", 1L, 7L);
        OAuthClientBO saved = client();
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self")).thenReturn(Optional.of(realmState));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.CLIENT, "501")).thenReturn(Optional.empty());
        when(states.save(eq(REALM), any(OAuthSecurityStateBO.class), eq(0L))).thenAnswer(call -> call.getArgument(1));
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        top.egon.cola.platform.tianquan.shoubing.admin.oauth.support.OAuthTransactionFences.clientWritten(REALM, saved);

        service.revokeClient(REALM, OAuthClientRevokeCommand.builder().clientPk(501L)
                .reasonCode("CLIENT_CREATED").writtenClient(saved).build());

        verify(clients, never()).findById(any(), anyLong());
        verify(clients, never()).findByClientIdForUpdate(any(), anyString());
        verify(outbox).enqueue(any());
    }

    @Test
    void unprovenWrittenClientCannotBypassThePrimaryFence() {
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.REALM, "self", 1L, 7L)));
        assertThatThrownBy(() -> service.revokeClient(REALM, OAuthClientRevokeCommand.builder()
                .clientPk(501L).reasonCode("CLIENT_CREATED").writtenClient(client()).build()))
                .hasMessage("OAUTH_CLIENT_WRITE_PROOF_REQUIRED");
        verify(outbox, never()).enqueue(any());
    }

    @Test
    void firstSubjectSecurityStateIsSeededWithoutResettingAnExistingAuthorization() {
        TrustedRealmBO platform = TrustedRealmBO.builder()
                .issuer(URI.create("https://idp.example/platform"))
                .realmKey("platform").realmType(RealmTypeEnum.PLATFORM)
                .storagePartitionId(9000L).trustVersion(0L).build();
        OAuthRealmBO registered = realmRow();
        OAuthSecurityStateBO realmState = securityState(OAuthSecurityTargetEnum.REALM, "self", 1L, 7L);
        when(managementRealms.platformRealm()).thenReturn(platform);
        when(realms.findAllByStoragePartition(platform)).thenReturn(List.of(registered));
        when(realms.findByRealmKeyForUpdate(REALM)).thenReturn(Optional.of(registered));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self"))
                .thenReturn(Optional.of(realmState));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.SUBJECT, "alice"))
                .thenReturn(Optional.empty());
        when(states.advanceRealmIfSubjectAbsent(eq(REALM), anyLong(), anyLong(), eq("alice"), anyLong(), any())).thenReturn(true);
        when(authorizations.findByPrincipalName(REALM, "alice", "ACTIVE", 0L, 1)).thenReturn(List.of());
        when(authorizations.findByPrincipalName(REALM, "alice", "REVOKED", 0L, 1)).thenReturn(List.of());
        when(authorizations.findByPrincipalName(REALM, "alice", "EXPIRED", 0L, 1)).thenReturn(List.of());
        when(states.save(eq(REALM), any(OAuthSecurityStateBO.class), eq(0L)))
                .thenAnswer(invocation -> invocation.getArgument(1));

        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        service.revokeSubject(new OAuthSubjectRevokeCommand("alice", "USER_CREATED"));
        TransactionSynchronizationManager.getSynchronizations().forEach(TransactionSynchronization::afterCommit);

        ArgumentCaptor<OAuthSecurityStateBO> stateChange = ArgumentCaptor.forClass(OAuthSecurityStateBO.class);
        verify(states).save(eq(REALM), stateChange.capture(), anyLong());
        OAuthSecurityStateBO subjectState = stateChange.getValue();
        assertThat(subjectState.getTargetType()).isEqualTo(OAuthSecurityTargetEnum.SUBJECT);
        assertThat(subjectState.getGeneration()).isZero();
        assertThat(subjectState.getTargetKey()).isEqualTo("alice");
        verify(states, never()).findByTargetForUpdate(any(), any(), anyString());
        verify(subjectTasks).enqueueForSubject(eq(REALM), any(), eq("alice"), anyLong(), eq(true), eq("USER_CREATED"));
    }

    @Test
    void replicaMissCannotSeedSubjectIfPrimaryHasStateOrAuthorizationHistory() {
        TrustedRealmBO platform = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/platform"))
                .realmKey("platform").realmType(RealmTypeEnum.PLATFORM).storagePartitionId(9000L).trustVersion(0L).build();
        OAuthRealmBO registered = realmRow();
        when(managementRealms.platformRealm()).thenReturn(platform);
        when(realms.findAllByStoragePartition(platform)).thenReturn(List.of(registered));
        when(realms.findByRealmKeyForUpdate(REALM)).thenReturn(Optional.of(registered));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.REALM, "self", 1L, 7L)));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.SUBJECT, "alice")).thenReturn(Optional.empty());
        when(states.advanceRealmIfSubjectAbsent(eq(REALM), anyLong(), anyLong(), eq("alice"), anyLong(), any())).thenReturn(false);

        var transaction = new org.springframework.transaction.support.TransactionTemplate(transactionManager);
        assertThatThrownBy(() -> transaction.executeWithoutResult(status ->
                service.revokeSubject(new OAuthSubjectRevokeCommand("alice", "USER_CREATED"))))
                .isInstanceOf(org.springframework.dao.OptimisticLockingFailureException.class);
        verify(transactionManager).rollback(any());
        verify(states, never()).save(any(), any(), anyLong());
        verify(outbox, never()).enqueue(any());
    }

    @Test
    void existingSubjectGenerationUsesReplicaCandidateAndVersionedWrite() {
        TrustedRealmBO platform = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/platform"))
                .realmKey("platform").realmType(RealmTypeEnum.PLATFORM).storagePartitionId(9000L).trustVersion(0L).build();
        OAuthRealmBO registered = realmRow();
        when(managementRealms.platformRealm()).thenReturn(platform);
        when(realms.findAllByStoragePartition(platform)).thenReturn(List.of(registered));
        when(realms.findByRealmKeyForUpdate(REALM)).thenReturn(Optional.of(registered));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.REALM, "self", 1L, 7L)));
        OAuthSecurityStateBO subject = securityState(OAuthSecurityTargetEnum.SUBJECT, "alice", 3L, 7L);
        subject.setVersion(4L);
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.SUBJECT, "alice")).thenReturn(Optional.of(subject));
        when(states.save(eq(REALM), any(OAuthSecurityStateBO.class), anyLong())).thenAnswer(call -> call.getArgument(1));
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);

        service.revokeSubject(new OAuthSubjectRevokeCommand("alice", "ADMIN_REVOKE_ALL"));

        ArgumentCaptor<OAuthSecurityStateBO> changes = ArgumentCaptor.forClass(OAuthSecurityStateBO.class);
        verify(states).save(eq(REALM), changes.capture(), eq(4L));
        assertThat(changes.getValue().getGeneration()).isEqualTo(4L);
        verify(states, never()).findByTargetForUpdate(any(), any(), anyString());
        verify(states, never()).advanceRealmIfSubjectAbsent(any(), anyLong(), anyLong(), anyString(), anyLong(), any());
    }

    @Test
    void olderSubjectTaskIsConfirmedOnPrimaryWithoutReapplyingIt() {
        var task = subjectTask(5L, false);
        var current = securityState(OAuthSecurityTargetEnum.SUBJECT, "alice", 3L, 9L)
                .setDirectorySubjectRevision(8L).setDirectorySubjectFingerprint("a".repeat(64));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.SUBJECT, "alice")).thenReturn(Optional.of(current));
        when(states.fenceSubjectAtLeast(eq(REALM), eq(current), eq(5L), anyString(), any())).thenReturn(true);
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        service.applySubjectTask(REALM, task);
        verify(states).fenceSubjectAtLeast(eq(REALM), eq(current), eq(5L), anyString(), any());
        verify(states, never()).save(any(), any(), anyLong());
        verify(outbox, never()).enqueue(any());
    }

    @Test
    void sameSourceRevisionWithDifferentContentIsNotAcknowledged() {
        var task = subjectTask(5L, false);
        var current = securityState(OAuthSecurityTargetEnum.SUBJECT, "alice", 3L, 9L)
                .setDirectorySubjectRevision(5L).setDirectorySubjectFingerprint("a".repeat(64));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.SUBJECT, "alice")).thenReturn(Optional.of(current));
        when(states.fenceSubjectAtLeast(eq(REALM), eq(current), eq(5L), anyString(), any())).thenReturn(false);
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        assertThatThrownBy(() -> service.applySubjectTask(REALM, task))
                .isInstanceOf(org.springframework.dao.OptimisticLockingFailureException.class);
        verify(outbox, never()).enqueue(any());
    }

    @Test
    void failureToPersistFanoutRollsBackSourceRevocation() {
        TrustedRealmBO platform = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/platform"))
                .realmKey("platform").realmType(RealmTypeEnum.PLATFORM).storagePartitionId(9000L).trustVersion(0L).build();
        OAuthRealmBO registered = realmRow();
        when(managementRealms.platformRealm()).thenReturn(platform);
        when(realms.findAllByStoragePartition(platform)).thenReturn(List.of(registered));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.REALM, "self", 1L, 7L)));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.SUBJECT, "alice"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.SUBJECT, "alice", 2L, 7L)));
        when(states.save(eq(REALM), any(OAuthSecurityStateBO.class), anyLong())).thenAnswer(call -> call.getArgument(1));
        org.mockito.Mockito.doThrow(new org.springframework.dao.OptimisticLockingFailureException("history delayed"))
                .when(subjectTasks).enqueueForSubject(any(), any(), anyString(), anyLong(), org.mockito.ArgumentMatchers.anyBoolean(), anyString());
        var tx = new org.springframework.transaction.support.TransactionTemplate(transactionManager);
        assertThatThrownBy(() -> tx.executeWithoutResult(status -> service.revokeSubject(
                new OAuthSubjectRevokeCommand("alice", "USER_DISABLED"))))
                .isInstanceOf(org.springframework.dao.OptimisticLockingFailureException.class);
        verify(transactionManager).rollback(any());
    }

    @Test
    void newerSubjectTaskAdvancesGenerationAndPublishesInTheTargetTransaction() {
        var task = subjectTask(9L, false);
        var current = securityState(OAuthSecurityTargetEnum.SUBJECT, "alice", 3L, 8L)
                .setDirectorySubjectRevision(5L).setDirectorySubjectOrderedRevision(5L).setDirectorySubjectFingerprint("a".repeat(64));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.SUBJECT, "alice")).thenReturn(Optional.of(current));
        when(states.findByTarget(REALM, OAuthSecurityTargetEnum.REALM, "self"))
                .thenReturn(Optional.of(securityState(OAuthSecurityTargetEnum.REALM, "self", 1L, 8L)));
        when(states.save(eq(REALM), any(OAuthSecurityStateBO.class), anyLong())).thenAnswer(call -> call.getArgument(1));
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        service.applySubjectTask(REALM, task);
        var captured = ArgumentCaptor.forClass(OAuthSecurityStateBO.class);
        verify(states, org.mockito.Mockito.times(2)).save(eq(REALM), captured.capture(), anyLong());
        var subject = captured.getAllValues().get(1);
        assertThat(subject.getDirectorySubjectRevision()).isEqualTo(9L);
        assertThat(subject.getDirectorySubjectOrderedRevision()).isEqualTo(9L);
        assertThat(subject.getDirectorySubjectFingerprint()).matches("[0-9a-f]{64}");
        assertThat(subject.getGeneration()).isEqualTo(4L);
        assertThat(subject.isEnabled()).isFalse();
        var message = ArgumentCaptor.forClass(top.egon.cola.component.outbox.api.OutboxMessage.class);
        verify(outbox).enqueue(message.capture());
        assertThat(message.getValue().headers()).containsEntry("oauth-subject-source-revision", "9")
                .containsEntry("oauth-subject-previous-revision", "5");
        verify(realms, never()).findByRealmKeyForUpdate(any());
        verify(states, never()).findByTargetForUpdate(any(), any(), anyString());
    }

    private static top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.SubjectRevocationTaskBO subjectTask(long revision, boolean enabled) {
        var task = new top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.SubjectRevocationTaskBO();
        task.setTargetTenantId("1001"); task.setIdentitySub("alice"); task.setSourceRevision(revision);
        task.setSubjectEnabled(enabled); task.setReasonCode("USER_DISABLED"); return task;
    }

    private static OAuthSecurityStateBO securityState(
            OAuthSecurityTargetEnum targetType, String targetKey, long generation, long revision) {
        return OAuthSecurityStateBO.builder().id(1L).version(0L).targetType(targetType).targetKey(targetKey)
                .generation(generation).enabled(true).revision(revision).reasonCode("INITIALIZED").build();
    }

    private static void assertAuthorizationRevocationPassesPersistenceGuards(OAuthAuthorizationBO current, OAuthAuthorizationBO changed) {
        var mapper = mock(top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.OAuthAuthorizationMapper.class);
        var converter = mock(top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter.OAuthAuthorizationConverter.class);
        var cipher = mock(top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthPayloadCipherComponent.class);
        var row = new top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.po.OAuthAuthorizationPO();
        row.setId(current.getId()); row.setVersion(current.getVersion()); row.setClientPk(current.getClientPk());
        row.setPrincipalName(current.getPrincipalName()); row.setPrincipalType(current.getPrincipalType()); row.setGrantType(current.getGrantType());
        row.setAudiences(current.getAudiences()); row.setAuthTime(current.getAuthTime()); row.setAcr(current.getAcr());
        row.setAbsoluteExpiresAt(current.getAbsoluteExpiresAt()); row.setRequestedScopes(current.getRequestedScopes());
        row.setResourceUri(current.getResourceUri()); row.setAuthenticationJtiDigest(current.getAuthenticationJtiDigest());
        row.setClientBrowserBindingDigest(current.getClientBrowserBindingDigest()); row.setInteractionId(current.getInteractionId());
        row.setDeviceSessionId(current.getDeviceSessionId());
        when(mapper.selectActiveById(1001L, current.getId())).thenReturn(row);
        when(converter.toTarget(eq(REALM), eq(cipher), any(), anyString(), eq(row))).thenReturn(current);
        when(converter.toSource(eq(REALM), eq(cipher), any(), anyString(), eq(changed)))
                .thenReturn(new top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.po.OAuthAuthorizationPO());
        when(mapper.updateExpectedVersion(eq(1001L), any(), eq(current.getVersion()))).thenReturn(1);
        var repository = new top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.impl.OAuthAuthorizationRepositoryImpl(
                mapper, new top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties(), converter,
                cipher, new com.fasterxml.jackson.databind.ObjectMapper(), () -> "service:tianquan-shoubing", Clock.fixed(NOW, ZoneOffset.UTC));

        repository.save(REALM, changed, current.getVersion());
        verify(mapper).updateExpectedVersion(eq(1001L), any(), eq(current.getVersion()));
    }

    private static OAuthClientBO client() {
        return OAuthClientBO.builder().id(501L).version(0L).clientId("web-client")
                .clientName("Web Client").clientType(OAuthClient.ClientType.PUBLIC)
                .purpose(top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.OAuthClientPurposeEnum.USER)
                .status(OAuthClient.Status.ACTIVE).credentialVersion(0L).build();
    }

    private static OAuthAuthorizationBO authorization() {
        return OAuthAuthorizationBO.builder().id(700L).version(0L).clientPk(501L).principalName("alice")
                .principalType("USER").grantType("authorization_code").authorizedScopes(List.of("openid"))
                .audiences(List.of("https://api.example/resource")).status("ACTIVE")
                .attributes(OAuthAuthorizationAttributesBO.builder().schemaVersion(1)
                        .securitySnapshot(OAuthSecuritySnapshotBO.builder().realmGeneration(1L)
                                .clientGeneration(2L).subjectGeneration(3L).readyEpoch("epoch")
                                .revision(9L).build()).authTime(NOW).acr("urn:test").build())
                .absoluteExpiresAt(NOW.plusSeconds(3600)).build();
    }

    private static OAuthTokenBO token() {
        return OAuthTokenBO.builder().id(701L).version(0L).authorizationPk(700L)
                .tokenType(OAuthTokenTypeEnum.ACCESS).tokenDigest(TOKEN_DIGEST).jti("123456")
                .issuedAt(NOW.minusSeconds(60)).expiresAt(NOW.plusSeconds(600))
                .metadata(OAuthTokenMetadataBO.builder().schemaVersion(1).build()).build();
    }

    private static OAuthRevocationBO pendingJti() {
        return OAuthRevocationBO.builder().id(800L).version(0L).targetType(OAuthSecurityTargetEnum.JTI)
                .targetKey("123456").reasonCode("ADMIN_REVOKE").revokedAt(NOW)
                .expiresAt(NOW.plusSeconds(630)).revision(10L).build();
    }

    private static OAuthRealmBO realmRow() {
        return OAuthRealmBO.builder().id(1001L).version(0L).issuer(REALM.getIssuer())
                .realmKey(REALM.getRealmKey()).realmType(REALM.getRealmType()).businessTenantId(1001L)
                .storagePartitionId(1001L).status("ACTIVE").trustVersion(0L).build();
    }
}
