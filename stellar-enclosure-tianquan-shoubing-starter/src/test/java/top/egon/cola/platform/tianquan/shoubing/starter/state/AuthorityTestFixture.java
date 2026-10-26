package top.egon.cola.platform.tianquan.shoubing.starter.state;

import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuditReceipt;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditEvent;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditFingerprint;

/** SQL authority response fixture; it does not simulate or claim database transaction durability. */
public final class AuthorityTestFixture {
    private AuthorityTestFixture() { }

    public static IdentityAuditReceipt receipt(TokenUsageAuditEvent event) {
        return new IdentityAuditReceipt(UUID.randomUUID().toString(), event.eventId(), TokenUsageAuditFingerprint.of(event),
                event.issuer().toASCIIString(), "controlled-service", event.resource(), "STORED", event.occurredAt());
    }

    public static Map<String, String> eventFields(TokenUsageAuditEvent event) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("eventId", event.eventId()); fields.put("schemaVersion", Integer.toString(event.schemaVersion()));
        fields.put("issuer", event.issuer().toASCIIString()); fields.put("resource", event.resource());
        fields.put("result", event.result()); fields.put("reasonCode", event.reasonCode());
        fields.put("occurredAt", event.occurredAt().toString());
        if (event.subjectRef() != null) { fields.put("subjectRef", event.subjectRef()); }
        if (event.clientRef() != null) { fields.put("clientRef", event.clientRef()); }
        if (event.tokenRef() != null) { fields.put("tokenRef", event.tokenRef()); }
        if (event.traceId() != null) { fields.put("traceId", event.traceId()); }
        return Map.copyOf(fields);
    }

    public static TokenUsageAuditEvent event() {
        return new TokenUsageAuditEvent("event-1", 1, URI.create("https://idp.example/tenants/1001"),
                "https://api.example/orders", "a".repeat(64), "b".repeat(64), "c".repeat(64),
                "SUCCESS", "TOKEN_USE_VERIFIED", Instant.parse("2026-10-10T00:00:00Z"), "trace-1");
    }

    public static IdentityAuthorityClient confirmingAuditClient() {
        return new IdentityAuthorityClient() {
            @Override public top.egon.cola.platform.tianquan.shoubing.contract.state.IdentitySecurityStateResponse resolve(
                    top.egon.cola.platform.tianquan.shoubing.contract.state.IdentitySecurityStateRequest request) {
                throw new UnsupportedOperationException("state is not configured by this fixture");
            }
            @Override public IdentityAuditReceipt appendAudit(TokenUsageAuditEvent event) { return receipt(event); }
        };
    }

    public static String[] settings() {
        String prefix = "egon.cola.platform.tianquan.shoubing.";
        return new String[]{prefix + "enabled=true", prefix + "resource-uri=https://api.example/orders",
                prefix + "trusted-issuers.tenant.issuer=https://idp.example/tenants/1001",
                prefix + "trusted-issuers.tenant.jwks-uri=https://idp.example/tenants/1001/.well-known/jwks.json",
                prefix + "trusted-issuers.tenant.realm-key=tenant:1001", prefix + "trusted-issuers.tenant.realm-type=TENANT",
                prefix + "trusted-issuers.tenant.tenant-id=1001", prefix + "trusted-issuers.tenant.status=ACTIVE",
                prefix + "trusted-issuers.tenant.trust-version=1", prefix + "usage-observation.enabled=true",
                prefix + "usage-observation.receiver=TIANSHU", prefix + "usage-observation.fallback-issuer=https://idp.example/tenants/1001"};
    }
}
