package top.egon.cola.platform.tianquan.shoubing.admin.audit.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditDeadLetterBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditInboxBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditReceiptBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditDeadLetterRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditInboxRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditReceiptRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditEvent;

/** Persistent intake, leased recovery and immutable confirmation without a second authority store. */
@Service("oauthAuditDeliveryService")
@RequiredArgsConstructor(onConstructor_ = @Autowired)
@Slf4j
public class OAuthAuditDeliveryService {

    private static final long RETENTION_SECONDS = 180L * 86_400;
    private static final long PROCESSING_SECONDS = 86_400;
    private static final long LEASE_SECONDS = 30;
    private static final int MAX_ATTEMPTS = 100;

    @Qualifier("oAuthAuditInboxRepository") private final OAuthAuditInboxRepository inboxes;
    @Qualifier("oAuthAuditReceiptRepository") private final OAuthAuditReceiptRepository receipts;
    @Qualifier("oAuthAuditDeadLetterRepository") private final OAuthAuditDeadLetterRepository deadLetters;
    @Qualifier("oAuthAuditRepository") private final OAuthAuditRepository audits;
    @Qualifier("jacksonObjectMapper") private final ObjectMapper mapper;
    @Qualifier("egonColaMybatisPlusClock") private final Clock clock;
    @Qualifier("transactionManager") private final PlatformTransactionManager transactionManager;

    @org.springframework.transaction.annotation.Transactional(propagation = org.springframework.transaction.annotation.Propagation.NOT_SUPPORTED)
    public OAuthAuditReceiptBO append(TrustedRealmBO realm, long sourceClientPk, String sourceIssuer,
            String sourceResource, TokenUsageAuditEvent event) {
        Objects.requireNonNull(realm, "realm").validateTrustedPartition();
        Objects.requireNonNull(event, "event");
        Instant now = now();
        if (sourceClientPk <= 0 || sourceIssuer == null || !event.issuer().equals(realm.getIssuer())
                || !event.resource().equals(sourceResource)
                || event.occurredAt().isAfter(now.plusSeconds(60))
                || !event.occurredAt().isAfter(now.minusSeconds(RETENTION_SECONDS))) {
            throw new IllegalArgumentException("OAUTH_AUDIT_SOURCE_OR_TIME_INVALID");
        }
        JsonNode payload = mapper.valueToTree(event);
        String fingerprint = fingerprint(event);
        Instant retainUntil = (event.occurredAt().isAfter(now) ? event.occurredAt() : now).plusSeconds(RETENTION_SECONDS);
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        transaction.setPropagationBehavior(org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        transaction.setName("oauthAuditIntake");
        AuditIntakeResult intake = transaction.execute(status -> {
            var existing = inboxes.findByEventId(realm, event.eventId()).orElse(null);
            if (existing != null) {
                requireSameEvent(existing, sourceClientPk, sourceIssuer, sourceResource, fingerprint);
                return new AuditIntakeResult(existing, false);
            }
            var inserted = inboxes.save(realm, OAuthAuditInboxBO.builder().eventId(event.eventId()).eventFingerprint(fingerprint)
                    .schemaVersion(1).sourceClientPk(sourceClientPk).sourceIssuer(sourceIssuer).sourceResourceUri(sourceResource)
                    .eventPayload(payload).occurredAt(event.occurredAt()).receivedAt(now).state("PENDING")
                    .attemptCount(0).nextAttemptAt(now).claimGeneration(0L)
                    .processingDeadline(now.plusSeconds(PROCESSING_SECONDS)).retainUntil(retainUntil).build(), 0L);
            // Never expose a new due PENDING row before the synchronous producer owns its first lease.
            return new AuditIntakeResult(claim(realm, inserted, now), true);
        });
        var receipt = intake.claimed() ? storeAndConfirm(realm, intake.inbox())
                : receipts.findByEventId(realm, event.eventId()).orElse(null);
        if (receipt == null && !intake.claimed()) {
            receipt = processForReceipt(realm, intake.inbox());
        }
        if (receipt == null) {
            receipt = receipts.findByEventId(realm, event.eventId()).orElse(null);
        }
        if (receipt == null || !receipt.getEventFingerprint().equals(fingerprint)
                || receipt.getSourceClientPk() != sourceClientPk || !receipt.getSourceIssuer().equals(sourceIssuer)
                || !receipt.getSourceResourceUri().equals(sourceResource)) {
            throw new IllegalStateException("OAUTH_AUDIT_CONFIRMATION_PENDING");
        }
        return receipt;
    }

    public int drain(TrustedRealmBO realm) {
        int completed = 0;
        for (var due : inboxes.findDue(realm, now(), 100)) {
            if (process(realm, due)) { completed++; }
        }
        return completed;
    }

    boolean process(TrustedRealmBO realm, OAuthAuditInboxBO current) {
        return processForReceipt(realm, current) != null;
    }

    private OAuthAuditReceiptBO processForReceipt(TrustedRealmBO realm, OAuthAuditInboxBO current) {
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        transaction.setPropagationBehavior(org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        transaction.setName("oauthAuditClaim");
        try {
            OAuthAuditInboxBO claimed = transaction.execute(status -> {
                if (terminal(current.getState())) { return null; }
                Instant now = now();
                if ("PROCESSING".equals(current.getState()) && current.getLeaseUntil().isAfter(now)
                        || "PENDING".equals(current.getState()) && current.getNextAttemptAt().isAfter(now)) { return null; }
                if (!current.getProcessingDeadline().isAfter(now) || current.getAttemptCount() >= MAX_ATTEMPTS) {
                    finishDead(realm, current, "EXPIRED", "OAUTH_AUDIT_DEADLINE_REACHED", now);
                    return null;
                }
                return claim(realm, current, now);
            });
            if (claimed == null) {
                return receipts.findByEventId(realm, current.getEventId()).orElse(null);
            }
            return storeAndConfirm(realm, claimed);
        } catch (OptimisticLockingFailureException conflict) {
            log.debug("OAuth audit claim deferred; failureType={}", conflict.getClass().getSimpleName());
            return null;
        }
    }

    private OAuthAuditInboxBO claim(TrustedRealmBO realm, OAuthAuditInboxBO current, Instant now) {
        Instant lease = now.plusSeconds(LEASE_SECONDS);
        if (lease.isAfter(current.getProcessingDeadline())) {
            lease = current.getProcessingDeadline();
        }
        return inboxes.saveObserved(realm, current, current.toBuilder().version(current.getVersion() + 1)
                .state("PROCESSING").attemptCount(current.getAttemptCount() + 1)
                .claimGeneration(current.getClaimGeneration() + 1).claimOwner(UUID.randomUUID().toString())
                .claimToken(UUID.randomUUID().toString()).leaseUntil(lease).build());
    }

    private OAuthAuditReceiptBO storeAndConfirm(TrustedRealmBO realm, OAuthAuditInboxBO claimed) {
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        transaction.setPropagationBehavior(org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        transaction.setName("oauthAuditStoreAndConfirm");
        try {
            return transaction.execute(status -> {
                // The committed claim may not yet be visible on a replica; its version fences the later update.
                if (!claimed.getLeaseUntil().isAfter(now())) {
                    return null;
                }
                TokenUsageAuditEvent event;
                try {
                    event = mapper.treeToValue(claimed.getEventPayload(), TokenUsageAuditEvent.class);
                } catch (com.fasterxml.jackson.core.JsonProcessingException | IllegalArgumentException invalid) {
                    return finishDead(realm, claimed, "DEAD", "OAUTH_AUDIT_EVENT_INVALID", now());
                }
                if (!fingerprint(event).equals(claimed.getEventFingerprint())) {
                    return finishDead(realm, claimed, "DEAD", "OAUTH_AUDIT_PAYLOAD_CONFLICT", now());
                }
                OAuthAuditBO stored = audits.save(realm, OAuthAuditBO.builder().eventId(event.eventId()).publicId(event.eventId())
                        .eventType("TOKEN_USE_VERIFIED").subjectRef(event.subjectRef()).clientRef(event.clientRef()).tokenRef(event.tokenRef())
                        .resourceRef(event.resource()).result(event.result()).reasonCode(event.reasonCode()).traceId(event.traceId())
                        .occurredAt(event.occurredAt()).payload(JsonNodeFactory.instance.objectNode()).auditKind("OAUTH")
                        .eventFingerprint(claimed.getEventFingerprint()).sourceClientPk(claimed.getSourceClientPk())
                        .sourceIssuer(claimed.getSourceIssuer()).retainUntil(claimed.getRetainUntil()).build(), 0L);
                Instant confirmed = now();
                inboxes.saveObserved(realm, claimed, terminal(claimed, "STORED", null, confirmed));
                // TransactionTemplate returns only after commit; a delayed read replica cannot undo this proof.
                return receipts.save(realm, receipt(claimed, "STORED", stored.getId(), confirmed), 0L);
            });
        } catch (OptimisticLockingFailureException conflict) {
            log.debug("OAuth audit confirmation deferred; failureType={}", conflict.getClass().getSimpleName());
            return null;
        }
    }

    private OAuthAuditReceiptBO finishDead(TrustedRealmBO realm, OAuthAuditInboxBO current, String outcome, String reason, Instant now) {
        deadLetters.save(realm, OAuthAuditDeadLetterBO.builder().inboxPk(current.getId()).eventId(current.getEventId())
                .eventFingerprint(current.getEventFingerprint()).failureCode(reason).attemptCount(current.getAttemptCount())
                .firstReceivedAt(current.getReceivedAt()).terminalAt(now).retainUntil(current.getRetainUntil()).build(), 0L);
        inboxes.saveObserved(realm, current, terminal(current, outcome, reason, now));
        return receipts.save(realm, receipt(current, outcome, null, now), 0L);
    }

    private static OAuthAuditInboxBO terminal(OAuthAuditInboxBO current, String state, String reason, Instant now) {
        return current.toBuilder().version(current.getVersion() + 1).state(state).terminalAt(now).failureCode(reason)
                .claimOwner(null).claimToken(null).leaseUntil(null).build();
    }

    private static OAuthAuditReceiptBO receipt(OAuthAuditInboxBO inbox, String outcome, Long auditPk, Instant confirmed) {
        return OAuthAuditReceiptBO.builder().receiptId(UUID.randomUUID().toString()).inboxPk(inbox.getId()).eventId(inbox.getEventId())
                .eventFingerprint(inbox.getEventFingerprint()).sourceClientPk(inbox.getSourceClientPk()).sourceIssuer(inbox.getSourceIssuer())
                .sourceResourceUri(inbox.getSourceResourceUri()).outcome(outcome).auditPk(auditPk).confirmedAt(confirmed)
                .retainUntil(inbox.getRetainUntil()).build();
    }

    private static void requireSameEvent(OAuthAuditInboxBO current, long client, String issuer, String resource, String digest) {
        if (current.getSourceClientPk() != client || !Objects.equals(current.getSourceIssuer(), issuer)
                || !Objects.equals(current.getSourceResourceUri(), resource) || !Objects.equals(current.getEventFingerprint(), digest)) {
            throw new IllegalArgumentException("OAUTH_AUDIT_EVENT_ID_REUSED");
        }
    }

    public static String fingerprint(TokenUsageAuditEvent event) {
        return top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditFingerprint.of(event);
    }

    private record AuditIntakeResult(OAuthAuditInboxBO inbox, boolean claimed) {}

    private static boolean terminal(String state) { return "STORED".equals(state) || "DEAD".equals(state) || "EXPIRED".equals(state); }
    private Instant now() { return clock.instant().truncatedTo(ChronoUnit.MICROS); }
}
