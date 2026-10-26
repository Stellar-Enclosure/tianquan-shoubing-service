package top.egon.cola.platform.tianquan.shoubing.starter.audit;

import jakarta.validation.Valid;
import jakarta.validation.Validator;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.validation.annotation.Validated;
import top.egon.cola.component.common.core.validation.ValidationUtils;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuditReceipt;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditEvent;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditFingerprint;
import top.egon.cola.platform.tianquan.shoubing.core.observability.IdpSecurityMetricsRecorder;
import top.egon.cola.platform.tianquan.shoubing.core.observability.SecurityMetricObservationBO;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClientResolver;

/** Synchronous secret-free audit delivery; only an exact committed SQL receipt completes the handoff. */
@RequiredArgsConstructor
@Slf4j
@Validated
public class TokenUsageAuditComponent {
    @Qualifier("identityAuthorityClientResolver")
    private final IdentityAuthorityClientResolver authority;
    @Qualifier("idpClock")
    private final Clock clock;
    @Qualifier("defaultValidator")
    private final Validator validator;
    @Qualifier("idpSecurityMetricsRecorder")
    private final IdpSecurityMetricsRecorder metrics;
    private final AtomicBoolean metricFailureLogged = new AtomicBoolean();

    public IdentityAuditReceipt appendStrict(@Valid TokenUsageAuditEvent event) {
        TokenUsageAuditEvent value = new ValidationUtils(validator).validate(Objects.requireNonNull(event, "event"));
        IdentityAuditReceipt receipt;
        try {
            receipt = authority.forResource(value.issuer(), URI.create(value.resource())).appendAudit(value);
            if (receipt == null || receipt.receiptId() == null
                    || !UUID.fromString(receipt.receiptId()).toString().equals(receipt.receiptId())
                    || !value.eventId().equals(receipt.eventId()) || !fingerprint(value).equals(receipt.eventFingerprint())
                    || !value.issuer().toASCIIString().equals(receipt.sourceIssuer())
                    || receipt.sourceClientId() == null || receipt.sourceClientId().isBlank() || receipt.sourceClientId().length() > 200
                    || !value.resource().equals(receipt.resource()) || !"STORED".equals(receipt.outcome())
                    || receipt.confirmedAt() == null || receipt.confirmedAt().isAfter(clock.instant().plusSeconds(60))) {
                throw new IllegalStateException("IDENTITY_AUDIT_RECEIPT_INVALID");
            }
        } catch (RuntimeException failure) {
            observeMetric(SecurityMetricObservationBO.builder().signal("oauth.audit.delivery").result("FAILED").build());
            throw new IllegalStateException("OAUTH_AUDIT_DELIVERY_UNAVAILABLE", failure);
        }
        observeMetric(SecurityMetricObservationBO.builder().signal("oauth.audit.delivery").result("CONFIRMED").build());
        Duration age = Duration.between(receipt.confirmedAt(), clock.instant());
        observeMetric(SecurityMetricObservationBO.builder().signal("receipt.age").result("CONFIRMED")
                .duration(age.isNegative() ? Duration.ZERO : age).build());
        return receipt;
    }

    /** All callers use the same durable confirmation rule. */
    public IdentityAuditReceipt append(@Valid TokenUsageAuditEvent event) {
        return appendStrict(event);
    }

    /** A domain-separated non-reversible reference; raw token material never enters the audit payload. */
    public String reference(@jakarta.validation.constraints.NotNull URI issuer,
            @jakarta.validation.constraints.NotBlank @jakarta.validation.constraints.Pattern(regexp = "[1-9][0-9]{0,18}") String tokenId) {
        if (issuer == null || !issuer.isAbsolute() || !"https".equalsIgnoreCase(issuer.getScheme())
                || issuer.getHost() == null || issuer.getUserInfo() != null || issuer.getQuery() != null || issuer.getFragment() != null
                || tokenId == null || !tokenId.matches("[1-9][0-9]{0,18}")) {
            throw new IllegalArgumentException("OAUTH_AUDIT_REFERENCE_INVALID");
        }
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
                    ("oauth-token-reference-v1\n" + issuer.toASCIIString() + "\n" + tokenId).getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("OAUTH_AUDIT_FINGERPRINT_UNAVAILABLE", unavailable);
        }
    }

    public String fingerprint(@Valid TokenUsageAuditEvent event) {
        return TokenUsageAuditFingerprint.of(new ValidationUtils(validator).validate(event));
    }

    private void observeMetric(SecurityMetricObservationBO sample) {
        if (metrics == IdpSecurityMetricsRecorder.NOOP) { return; }
        try { metrics.record(sample); }
        catch (RuntimeException failure) {
            if (metricFailureLogged.compareAndSet(false, true)) {
                log.warn("Audit observation unavailable; failureType={}", failure.getClass().getSimpleName());
            }
        }
    }
}
