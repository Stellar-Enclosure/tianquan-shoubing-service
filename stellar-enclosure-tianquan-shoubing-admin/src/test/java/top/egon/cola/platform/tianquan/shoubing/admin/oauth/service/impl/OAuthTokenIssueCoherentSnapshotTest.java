package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;
import top.egon.cola.component.outbox.api.TransactionalOutbox;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationAttributesBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthConsentBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthSecuritySnapshotBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.command.ConsumeOAuthTokenCommand;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthenticationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthorizationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthConsentRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.bo.OAuthGrantBO;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthGrantRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthTokenBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthTokenMetadataBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthTokenTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthTokenRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.TokenRevocationService;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthSecurityProjectionComponent;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;
import top.egon.cola.platform.tianquan.shoubing.core.port.ResourceServerStore;
import top.egon.cola.platform.tianquan.shoubing.core.port.TenantMembershipPort;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ClientCredentialsAccessPolicy;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ClientResourceGrant;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ResourceGrantType;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ResourceServer;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ResourceServerStatus;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class OAuthTokenIssueCoherentSnapshotTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");
    private static final URI RESOURCE = URI.create("https://api.example/orders");
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/1001"))
            .realmKey("tenant:1001").realmType(RealmTypeEnum.TENANT).storagePartitionId(1001L)
            .businessTenantId(1001L).trustVersion(0L).build();
    private final OAuthTokenRepository tokens = mock(OAuthTokenRepository.class);
    private final OAuthAuthorizationRepository authorizations = mock(OAuthAuthorizationRepository.class);
    private final OAuthClientRepository clients = mock(OAuthClientRepository.class);
    private final OAuthGrantRepository grants = mock(OAuthGrantRepository.class);
    private final OAuthConsentRepository consents = mock(OAuthConsentRepository.class);
    private final OAuthRealmRepository realms = mock(OAuthRealmRepository.class);
    private final OAuthAuditRepository audits = mock(OAuthAuditRepository.class);
    private final TransactionalOutbox outbox = mock(TransactionalOutbox.class);
    private final OAuthSecurityProjectionComponent projection = mock(OAuthSecurityProjectionComponent.class);
    private final ResourceServerStore resources = mock(ResourceServerStore.class);
    private final TokenRevocationService revocations = mock(TokenRevocationService.class);
    private final PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
    private OAuthTokenIssueServiceImpl service;
    private OAuthTokenBO token;
    private ConsumeOAuthTokenCommand command;

    @BeforeEach
    void setUp() {
        org.springframework.transaction.support.TransactionSynchronizationManager.initSynchronization();
        org.springframework.transaction.support.TransactionSynchronizationManager.setActualTransactionActive(true);
        var snapshot = OAuthSecuritySnapshotBO.builder().realmGeneration(1L).clientGeneration(2L).subjectGeneration(3L).build();
        var authorization = OAuthAuthorizationBO.builder().id(700L).version(2L).clientPk(501L).principalName("alice")
                .principalType("USER").status("ACTIVE").authorizedScopes(List.of("openid"))
                .audiences(List.of(RESOURCE.toString())).absoluteExpiresAt(NOW.plusSeconds(600))
                .attributes(OAuthAuthorizationAttributesBO.builder().securitySnapshot(snapshot).build()).build();
        token = OAuthTokenBO.builder().id(701L).version(3L).authorizationPk(700L).tokenType(OAuthTokenTypeEnum.REFRESH)
                .tokenDigest("a".repeat(64)).expiresAt(NOW.plusSeconds(300)).refreshGeneration(0L)
                .metadata(OAuthTokenMetadataBO.builder().schemaVersion(1).invalidated(false).build()).build();
        var client = OAuthClientBO.builder().id(501L).clientId("client").status(OAuthClient.Status.ACTIVE).build();
        var consent = OAuthConsentBO.builder().status("ACTIVE").authorities(List.of("SCOPE_openid")).build();
        var target = new ResourceServer("orders", RESOURCE, "orders", "orders", "prod", "service", "orders",
                "orders:entry", Duration.ofMinutes(5), ResourceServerStatus.ACTIVE, 1L);
        var grant = OAuthGrantBO.builder().id(9L).clientPk(501L).resourceServerId("orders")
                .grantType(ResourceGrantType.USER_DELEGATION).status(ClientResourceGrant.Status.ACTIVE)
                .resourceVersion(1L).allowedScopes(List.of()).build();
        when(tokens.findByTokenDigest(realm, token.getTokenDigest())).thenReturn(Optional.of(token));
        when(authorizations.findById(realm, 700L)).thenReturn(Optional.of(authorization));
        when(realms.fenceActiveObservedVersion(realm)).thenReturn(true);
        when(clients.findById(realm, 501L)).thenReturn(Optional.of(client));
        when(clients.fenceObservedVersion(realm, client)).thenReturn(true);
        when(clients.fenceGrantObservedVersion(eq(realm), eq(client), anyLong(), any())).thenReturn(true);
        when(consents.findConsent(realm, 501L, "alice")).thenReturn(Optional.of(consent));
        when(resources.findByUri(RESOURCE)).thenReturn(Optional.of(target));
        when(grants.findGrant(realm, 501L, "orders", ResourceGrantType.USER_DELEGATION)).thenReturn(Optional.of(grant));
        when(manager.getTransaction(any())).thenAnswer(call -> new SimpleTransactionStatus());
        service = new OAuthTokenIssueServiceImpl(tokens, authorizations, clients, grants, consents, realms, audits,
                outbox, projection, mock(ClientCredentialsAccessPolicy.class), resources, Clock.fixed(NOW, ZoneOffset.UTC),
                mock(TenantMembershipPort.class), mock(OAuthAuthenticationRepository.class), revocations, 1001L);
        command = ConsumeOAuthTokenCommand.builder().tokenDigest(token.getTokenDigest()).clientPk(501L)
                .tokenType(OAuthTokenTypeEnum.REFRESH).build();
    }

    @org.junit.jupiter.api.AfterEach
    void clearFenceState() {
        org.springframework.transaction.support.TransactionSynchronizationManager.getSynchronizations().forEach(
                sync -> sync.afterCompletion(org.springframework.transaction.support.TransactionSynchronization.STATUS_ROLLED_BACK));
        org.springframework.transaction.support.TransactionSynchronizationManager.clearSynchronization();
        org.springframework.transaction.support.TransactionSynchronizationManager.setActualTransactionActive(false);
    }

    @Test
    void mismatchedReplicaVersionsRetryWithoutRevokingAValidRefreshFamily() {
        token.setRefreshGeneration(1L);
        when(tokens.findAtAuthorizationVersion(realm, token.getTokenDigest(), 700L, 2L)).thenReturn(Optional.empty());
        var transaction = new TransactionTemplate(manager);

        assertThatThrownBy(() -> transaction.execute(status -> service.consumeAndIssue(realm, command,
                () -> { throw new AssertionError("delegate must not run"); })))
                .isInstanceOf(TransientDataAccessResourceException.class);
        verify(manager).rollback(any());
        verify(authorizations, never()).findByIdForUpdate(any(), anyLong());
        verifyNoInteractions(revocations, audits, outbox);
    }

    @Test
    void primaryGrantMismatchRollsBackBeforeIssuingAToken() {
        when(clients.fenceGrantObservedVersion(eq(realm), any(), anyLong(), any())).thenReturn(false);
        var transaction = new TransactionTemplate(manager);
        assertThatThrownBy(() -> transaction.execute(status -> service.consumeAndIssue(realm, command,
                () -> { throw new AssertionError("delegate must not run"); })))
                .isInstanceOf(OptimisticLockingFailureException.class);
        verify(manager).rollback(any());
        verify(tokens, never()).findAtAuthorizationVersion(any(), anyString(), anyLong(), anyLong());
        verify(realms, never()).findByRealmKeyForUpdate(any());
        verify(clients, never()).findByClientIdForUpdate(any(), anyString());
        verify(grants, never()).findGrantForUpdate(any(), anyLong(), anyString(), any());
        verifyNoInteractions(audits, outbox);
    }

    @Test
    void coherentCandidateStillRollsBackWhenTheDelegateLosesItsWriteCas() {
        when(tokens.findAtAuthorizationVersion(realm, token.getTokenDigest(), 700L, 2L)).thenReturn(Optional.of(token));
        var transaction = new TransactionTemplate(manager);

        assertThatThrownBy(() -> transaction.execute(status -> service.consumeAndIssue(realm, command,
                () -> { throw new OptimisticLockingFailureException("stale token"); })))
                .isInstanceOf(OptimisticLockingFailureException.class);
        verify(manager).rollback(any());
        verify(authorizations, never()).findByIdForUpdate(any(), anyLong());
        verifyNoInteractions(audits, outbox);
    }

    @Test
    void replayDoesNotCommitDenialWhenTheObservedTokenDisappearsOnAnotherReplica() {
        token.setConsumedAt(NOW.minusSeconds(1));
        when(tokens.findAtAuthorizationVersion(realm, token.getTokenDigest(), 700L, 2L)).thenReturn(Optional.of(token));
        doThrow(new TransientDataAccessResourceException("observed token not visible"))
                .when(revocations).revokeKnown(eq(realm), any());
        var transaction = new TransactionTemplate(manager);

        assertThatThrownBy(() -> transaction.execute(status -> service.consumeAndIssue(realm, command,
                () -> { throw new AssertionError("delegate must not run"); })))
                .isInstanceOf(TransientDataAccessResourceException.class);
        verify(manager).rollback(any());
        verify(revocations).revokeKnown(eq(realm), any());
        verifyNoInteractions(audits, outbox);
    }
}
