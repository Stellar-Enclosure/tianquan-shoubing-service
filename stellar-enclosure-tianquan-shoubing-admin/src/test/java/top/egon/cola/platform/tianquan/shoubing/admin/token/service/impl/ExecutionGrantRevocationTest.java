package top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import top.egon.cola.component.outbox.api.OutboxMessage;
import top.egon.cola.component.outbox.api.OutboxReceipt;
import top.egon.cola.component.outbox.api.TransactionalOutbox;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthorizationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthExecutionPrimaryGuard;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthManagementRealmResolver;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthRevocationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSecurityStateBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthRevocationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthTokenRepository;
import top.egon.cola.platform.tianquan.shoubing.core.audit.OAuthSecurityChangedEvent;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class ExecutionGrantRevocationTest {
    private static final Instant NOW = Instant.parse("2026-10-29T00:00:00Z");
    private static final String ID = "9" + "1".repeat(62);
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/101"))
            .realmKey("tenant:101").realmType(RealmTypeEnum.TENANT).storagePartitionId(101L)
            .businessTenantId(101L).trustVersion(0L).build();
    private final OAuthRealmRepository realms = mock(OAuthRealmRepository.class);
    private final OAuthSecurityStateRepository states = mock(OAuthSecurityStateRepository.class);
    private final OAuthRevocationRepository revocations = mock(OAuthRevocationRepository.class);
    private final OAuthAuditRepository audits = mock(OAuthAuditRepository.class);
    private final TransactionalOutbox outbox = mock(TransactionalOutbox.class);
    private final OAuthExecutionPrimaryGuard guard = mock(OAuthExecutionPrimaryGuard.class);
    private TokenRevocationServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new TokenRevocationServiceImpl(realms, mock(OAuthClientRepository.class),
                mock(OAuthAuthorizationRepository.class), mock(OAuthTokenRepository.class), states, revocations, audits,
                outbox, mock(OAuthSecurityProjectionComponent.class), mock(OAuthManagementRealmResolver.class),
                Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofSeconds(30), mock(PlatformTransactionManager.class));
        service.setExecutionPrimary(guard);
        when(realms.fenceObservedVersion(realm)).thenReturn(true);
        when(states.findByTarget(realm, OAuthSecurityTargetEnum.REALM, "self"))
                .thenReturn(Optional.of(state()));
        when(states.advanceRealmIfRevocationAbsent(eq(realm), anyLong(), anyLong(), eq(OAuthSecurityTargetEnum.JTI),
                eq(ID), anyLong(), any())).thenReturn(true);
        when(revocations.fenceObservedVersion(eq(realm), any())).thenReturn(true);
        when(revocations.save(eq(realm), any(), anyLong())).thenAnswer(call -> {
            OAuthRevocationBO result = call.getArgument(1);
            if (result.getId() == null) result.setId(7L);
            return result;
        });
        when(states.save(eq(realm), any(), anyLong())).thenAnswer(call -> call.getArgument(1));
        when(audits.findByEventId(eq(realm), anyString())).thenReturn(Optional.empty());
        when(outbox.enqueue(any())).thenAnswer(call -> {
            OutboxMessage message = call.getArgument(0);
            return new OutboxReceipt(message.messageId(), message.idempotencyKey(), true);
        });
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
    }

    @AfterEach
    void clear() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.getSynchronizations().forEach(sync ->
                    sync.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));
            TransactionSynchronizationManager.clearSynchronization();
        }
        TransactionSynchronizationManager.setActualTransactionActive(false);
    }

    @Test
    void revocation_keeps_a_tombstone_for_the_run_deadline_and_publishes_one_audit_event() {
        when(revocations.findByTarget(realm, OAuthSecurityTargetEnum.JTI, ID)).thenReturn(Optional.empty());
        Instant deadline = NOW.plus(Duration.ofDays(2)).plusNanos(123);
        service.revokeExecutionGrant(realm, ID, deadline);
        var saved = ArgumentCaptor.forClass(OAuthRevocationBO.class);
        verify(revocations).save(eq(realm), saved.capture(), eq(0L));
        assertEquals("EXECUTION_GRANT_REVOKED", saved.getValue().getReasonCode());
        assertEquals(NOW.plus(Duration.ofDays(2)).plusSeconds(30).plusNanos(1_000), saved.getValue().getExpiresAt());
        assertEquals(NOW.plus(Duration.ofDays(2)).plusSeconds(30 + 86_400).plusNanos(1_000), saved.getValue().getRetainUntil());
        var message = ArgumentCaptor.forClass(OutboxMessage.class);
        verify(outbox).enqueue(message.capture());
        var event = (OAuthSecurityChangedEvent) message.getValue().payload();
        assertEquals("JTI", event.targetType());
        assertEquals(ID, event.targetKey());
        verify(audits).save(eq(realm), any(OAuthAuditBO.class), eq(0L));
    }

    @Test
    void short_deadlines_still_cover_every_existing_eight_hour_envelope() {
        when(revocations.findByTarget(realm, OAuthSecurityTargetEnum.JTI, ID)).thenReturn(Optional.empty());
        service.revokeExecutionGrant(realm, ID, NOW.plusSeconds(60));
        var saved = ArgumentCaptor.forClass(OAuthRevocationBO.class);
        verify(revocations).save(eq(realm), saved.capture(), eq(0L));
        assertEquals(NOW.plus(Duration.ofHours(8)).plusSeconds(30), saved.getValue().getExpiresAt());
    }

    @Test
    void duplicate_revocation_is_idempotent_but_a_longer_deadline_extends_the_tombstone() {
        OAuthRevocationBO existing = existing("EXECUTION_GRANT_REVOKED", NOW.plus(Duration.ofHours(8)).plusSeconds(30));
        when(revocations.findByTarget(realm, OAuthSecurityTargetEnum.JTI, ID)).thenReturn(Optional.of(existing));
        service.revokeExecutionGrant(realm, ID, NOW.plusSeconds(60));
        verify(revocations, never()).save(any(), any(), anyLong());
        verifyNoInteractions(outbox);

        // The primary fence advances the row version; use the observed successor for the update.
        service.revokeExecutionGrant(realm, ID, NOW.plus(Duration.ofDays(2)));
        var saved = ArgumentCaptor.forClass(OAuthRevocationBO.class);
        verify(revocations).save(eq(realm), saved.capture(), eq(2L));
        assertEquals(3L, saved.getValue().getVersion());
        assertEquals(NOW.plus(Duration.ofDays(2)).plusSeconds(30), saved.getValue().getExpiresAt());
        verify(outbox).enqueue(any());
    }

    @Test
    void another_revocation_namespace_and_invalid_ids_are_never_modified() {
        when(revocations.findByTarget(realm, OAuthSecurityTargetEnum.JTI, ID))
                .thenReturn(Optional.of(existing("TOKEN_REVOKED", NOW.plusSeconds(600))));
        assertThrows(OAuth2AuthenticationException.class, () -> service.revokeExecutionGrant(realm, ID, NOW.plusSeconds(60)));
        assertThrows(IllegalArgumentException.class, () -> service.revokeExecutionGrant(realm, "123", NOW.plusSeconds(60)));
        var platform = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/platform")).realmKey("platform")
                .realmType(RealmTypeEnum.PLATFORM).storagePartitionId(1L).trustVersion(0L).build();
        assertThrows(IllegalArgumentException.class, () -> service.revokeExecutionGrant(platform, ID, NOW.plusSeconds(60)));
        verify(revocations, never()).save(any(), any(), anyLong());
        verifyNoInteractions(outbox);
    }

    @Test
    void direct_legacy_construction_without_a_primary_guard_cannot_write() {
        org.springframework.test.util.ReflectionTestUtils.setField(service, "executionPrimary", null);
        var failure = assertThrows(OAuth2AuthenticationException.class,
                () -> service.revokeExecutionGrant(realm, ID, NOW.plusSeconds(60)));
        assertEquals("temporarily_unavailable", failure.getError().getErrorCode());
        verifyNoInteractions(realms, revocations, outbox);
    }

    private static OAuthSecurityStateBO state() {
        return OAuthSecurityStateBO.builder().id(1L).version(0L).targetType(OAuthSecurityTargetEnum.REALM)
                .targetKey("self").generation(1L).enabled(true).revision(5L).reasonCode("INITIALIZED").build();
    }

    private static OAuthRevocationBO existing(String reason, Instant expiry) {
        return OAuthRevocationBO.builder().id(7L).version(0L).targetType(OAuthSecurityTargetEnum.JTI).targetKey(ID)
                .reasonCode(reason).revokedAt(NOW).expiresAt(expiry).retainUntil(expiry.plusSeconds(86_400)).revision(5L).build();
    }
}
