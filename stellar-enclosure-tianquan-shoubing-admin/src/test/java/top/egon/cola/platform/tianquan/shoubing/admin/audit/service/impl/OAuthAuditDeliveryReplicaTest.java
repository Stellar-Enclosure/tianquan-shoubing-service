package top.egon.cola.platform.tianquan.shoubing.admin.audit.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditInboxBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditDeadLetterRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditInboxRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditReceiptRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditEvent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class OAuthAuditDeliveryReplicaTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");
    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
    private final OAuthAuditInboxRepository inboxes = mock(OAuthAuditInboxRepository.class);
    private final OAuthAuditReceiptRepository receipts = mock(OAuthAuditReceiptRepository.class);
    private final OAuthAuditDeadLetterRepository deadLetters = mock(OAuthAuditDeadLetterRepository.class);
    private final OAuthAuditRepository audits = mock(OAuthAuditRepository.class);
    private final PlatformTransactionManager transactions = mock(PlatformTransactionManager.class);
    private final TrustedRealmBO realm = mock(TrustedRealmBO.class);
    private final OAuthAuditDeliveryService service = new OAuthAuditDeliveryService(inboxes, receipts, deadLetters,
            audits, mapper, Clock.fixed(NOW, ZoneOffset.UTC), transactions);

    @Test
    void processesCommittedClaimWithoutRereadingLaggingReplica() {
        when(transactions.getTransaction(any())).thenAnswer(call -> new SimpleTransactionStatus());
        when(inboxes.saveObserved(any(), any(), any())).thenAnswer(call -> call.getArgument(2));
        when(audits.save(any(), any(), anyLong())).thenReturn(OAuthAuditBO.builder().id(23L).build());

        assertThat(service.process(realm, pending())).isTrue();

        verify(inboxes, times(2)).saveObserved(eq(realm), any(), any());
        verify(inboxes, never()).findByEventIdForUpdate(any(), anyString());
        verify(inboxes, never()).findByEventId(any(), anyString());
        verify(receipts).save(eq(realm), any(), eq(0L));
        verify(transactions, times(2)).commit(any());
        verify(transactions, never()).rollback(any());
    }

    @Test
    void intakeUsesInsertedSnapshotWhenReplicaHasNotReplayedIt() {
        when(transactions.getTransaction(any())).thenAnswer(call -> new SimpleTransactionStatus());
        when(realm.getIssuer()).thenReturn(URI.create("https://idp.example/tenants/1"));
        when(inboxes.save(any(), any(), anyLong())).thenAnswer(call -> {
            OAuthAuditInboxBO inserted = call.getArgument(1);
            return inserted.setId(11L);
        });
        when(inboxes.saveObserved(any(), any(), any())).thenAnswer(call -> call.getArgument(2));
        when(audits.save(any(), any(), anyLong())).thenReturn(OAuthAuditBO.builder().id(23L).build());
        var event = event();

        assertThatThrownBy(() -> service.append(realm, 2L, event.issuer().toString(), event.resource(), event))
                .isInstanceOf(IllegalStateException.class).hasMessage("OAUTH_AUDIT_CONFIRMATION_PENDING");

        verify(inboxes).findByEventId(realm, event.eventId());
        verify(inboxes, never()).findByEventIdForUpdate(any(), anyString());
        verify(inboxes, times(2)).saveObserved(eq(realm), any(), any());
        verify(receipts).save(eq(realm), any(), eq(0L));
    }

    @Test
    void lostOwnershipRollsBackAuditAndDoesNotWriteReceipt() {
        when(transactions.getTransaction(any())).thenAnswer(call -> new SimpleTransactionStatus());
        when(inboxes.saveObserved(any(), any(), any())).thenAnswer(call -> {
            OAuthAuditInboxBO observed = call.getArgument(1);
            if (observed.getVersion() == 1L) { throw new OptimisticLockingFailureException("claim lost"); }
            return call.getArgument(2);
        });
        when(audits.save(any(), any(), anyLong())).thenReturn(OAuthAuditBO.builder().id(23L).build());

        assertThat(service.process(realm, pending())).isFalse();

        verify(audits).save(eq(realm), any(), eq(0L));
        verify(receipts, never()).save(any(), any(), anyLong());
        verify(transactions).commit(any());
        verify(transactions).rollback(any());
    }

    @Test
    void concurrentClaimsFromTheSameReplicaVersionHaveOneWinner() throws Exception {
        var barrier = new CyclicBarrier(2);
        var winner = new AtomicBoolean();
        when(transactions.getTransaction(any())).thenAnswer(call -> new SimpleTransactionStatus());
        when(inboxes.saveObserved(any(), any(), any())).thenAnswer(call -> {
            OAuthAuditInboxBO observed = call.getArgument(1);
            if (observed.getVersion() == 0L) {
                barrier.await(5, TimeUnit.SECONDS);
                if (!winner.compareAndSet(false, true)) { throw new OptimisticLockingFailureException("claim lost"); }
            }
            return call.getArgument(2);
        });
        when(audits.save(any(), any(), anyLong())).thenReturn(OAuthAuditBO.builder().id(23L).build());

        OAuthAuditInboxBO candidate = pending();
        try (var workers = Executors.newFixedThreadPool(2)) {
            var first = workers.submit(() -> service.process(realm, candidate));
            var second = workers.submit(() -> service.process(realm, candidate));
            assertThat(java.util.List.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(true, false);
        }
        verify(audits).save(eq(realm), any(), eq(0L));
        verify(receipts).save(eq(realm), any(), eq(0L));
        verify(transactions, times(2)).commit(any());
        verify(transactions).rollback(any());
    }

    private OAuthAuditInboxBO pending() {
        var event = event();
        return OAuthAuditInboxBO.builder().id(11L).version(0L).eventId(event.eventId())
                .eventFingerprint(OAuthAuditDeliveryService.fingerprint(event)).schemaVersion(1).sourceClientPk(2L)
                .sourceIssuer(event.issuer().toString()).sourceResourceUri(event.resource()).eventPayload(mapper.valueToTree(event))
                .occurredAt(event.occurredAt()).receivedAt(NOW.minusSeconds(1)).state("PENDING").attemptCount(0)
                .nextAttemptAt(NOW).claimGeneration(0L).processingDeadline(NOW.plusSeconds(300))
                .retainUntil(NOW.plusSeconds(1000)).build();
    }

    private static TokenUsageAuditEvent event() {
        return new TokenUsageAuditEvent("event-1", 1, URI.create("https://idp.example/tenants/1"),
                "https://api.example/orders", null, null, null, "SUCCESS", "JWT_ACCEPTED", NOW.minusSeconds(1), null);
    }
}
