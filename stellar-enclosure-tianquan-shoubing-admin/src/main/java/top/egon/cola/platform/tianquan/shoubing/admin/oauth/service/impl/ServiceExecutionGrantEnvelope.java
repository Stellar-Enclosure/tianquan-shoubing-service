package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Owner-sealed SERVICE identity evidence for one bounded execution intent. */
record ServiceExecutionGrantEnvelope(int schemaVersion, String grantId, ExecutionGrantEnvelope.ServiceBinding source,
        ExecutionGrantEnvelope.ServiceBinding verifier, long sourceRealmGeneration, long sourceClientGeneration,
        long sourceAuthorizationId, String sourceTokenDigest, String sourceTokenJti, Instant sourceTokenRetainUntil,
        String sourceSigningKeyId, String purpose, String intentId, String bindingSha256, String policySha256, boolean sessionRequired,
        Instant notBefore, Instant expiresAt, Instant intentDeadlineAt, StoredServiceExecutionProof subject) {
    ServiceExecutionGrantEnvelope {
        source = Objects.requireNonNull(source, "source");
        verifier = Objects.requireNonNull(verifier, "verifier");
        subject = Objects.requireNonNull(subject, "subject");
        if (schemaVersion != 1 || grantId == null || !grantId.matches("8[0-9]{62}")
                || sourceRealmGeneration < 0 || sourceClientGeneration < 0 || sourceAuthorizationId <= 0
                || sourceTokenDigest == null || !sourceTokenDigest.matches("[0-9a-f]{64}")
                || sourceTokenJti == null || !sourceTokenJti.matches("[1-9][0-9]{0,18}") || sourceTokenRetainUntil == null
                || sourceSigningKeyId == null || !sourceSigningKeyId.matches("[A-Za-z0-9_-]{1,128}")
                || purpose == null || !purpose.matches("[A-Z][A-Z0-9_]{0,95}") || !uuid(intentId)
                || bindingSha256 == null || !bindingSha256.matches("[0-9a-f]{64}")
                || policySha256 == null || !policySha256.matches("[0-9a-f]{64}")
                || notBefore == null || expiresAt == null || intentDeadlineAt == null || !expiresAt.isAfter(notBefore)
                || expiresAt.isAfter(intentDeadlineAt) || intentDeadlineAt.isAfter(ExecutionGrantEnvelope.MAX_INTENT_DEADLINE)
                || Duration.between(notBefore, expiresAt).compareTo(Duration.ofHours(8)) > 0
                || !source.resourceUri().equals(subject.resourceUri())
                || source.clientPk() == verifier.clientPk() || source.resourceUri().equals(verifier.resourceUri())
                || subject.clientPk() == verifier.clientPk() || subject.sourceResourceUri().equals(verifier.resourceUri())
                || expiresAt.isAfter(subject.tokenRetainUntil()) || expiresAt.isAfter(sourceTokenRetainUntil)
                || !grantId.equals(OpaqueExecutionGrantCodec.serviceGrantId(subject, source, purpose, intentId))) {
            throw new IllegalArgumentException("EXECUTION_SERVICE_GRANT_ENVELOPE_INVALID");
        }
    }

    private static boolean uuid(String value) {
        try { return value != null && UUID.fromString(value).toString().equals(value); }
        catch (IllegalArgumentException invalid) { return false; }
    }

    @Override public String toString() { return "ServiceExecutionGrantEnvelope[redacted]"; }
}
