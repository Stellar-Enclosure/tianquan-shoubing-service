package top.egon.cola.platform.tianquan.shoubing.contract.state;

import java.time.Instant;

/** A durable database outcome bound to the exact sender and event content. */
public record IdentityAuditReceipt(
        String receiptId,
        String eventId,
        String eventFingerprint,
        String sourceIssuer,
        String sourceClientId,
        String resource,
        String outcome,
        Instant confirmedAt
) { }
