package top.egon.cola.platform.tianquan.shoubing.admin.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuditReceipt;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditEvent;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditFingerprint;
import static org.junit.jupiter.api.Assertions.*;

class TokenUsageAuditReceiptContractTest {
    private static final Instant NOW = Instant.parse("2026-10-23T00:00:00Z");

    @Test void canonicalFingerprintBindsEventIdentityIssuerResourceAndDecision() {
        var first = event("one", "SUCCESS", "https://api.example/orders");
        String digest = TokenUsageAuditFingerprint.of(first);
        assertTrue(digest.matches("[0-9a-f]{64}"));
        assertEquals(digest, TokenUsageAuditFingerprint.of(event("one", "SUCCESS", "https://api.example/orders")));
        assertNotEquals(digest, TokenUsageAuditFingerprint.of(event("two", "SUCCESS", "https://api.example/orders")));
        assertNotEquals(digest, TokenUsageAuditFingerprint.of(event("one", "DENIED", "https://api.example/orders")));
        assertNotEquals(digest, TokenUsageAuditFingerprint.of(event("one", "SUCCESS", "https://api.example/other")));
    }

    @Test void receiptSerializationContainsOnlyStableBindingAndCommittedOutcome() throws Exception {
        var event = event("one", "SUCCESS", "https://api.example/orders");
        var receipt = new IdentityAuditReceipt("receipt-1", event.eventId(), TokenUsageAuditFingerprint.of(event),
                event.issuer().toString(), "orders-service", event.resource(), "STORED", NOW);
        var mapper = new ObjectMapper().findAndRegisterModules();
        String json = mapper.writeValueAsString(receipt);
        assertEquals(receipt, mapper.readValue(json, IdentityAuditReceipt.class));
        assertFalse(json.contains("accessToken")); assertFalse(json.contains("refreshToken"));
        assertFalse(json.contains("spool"));
    }

    @Test void unsupportedEventSchemaAndRawReferenceAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new TokenUsageAuditEvent("one", 2,
                URI.create("https://idp.example/tenants/1"), "https://api.example/orders", null, null, null,
                "SUCCESS", "JWT_ACCEPTED", NOW, null));
        assertThrows(IllegalArgumentException.class, () -> new TokenUsageAuditEvent("one", 1,
                URI.create("https://idp.example/tenants/1"), "https://api.example/orders", null, null, "raw-token",
                "SUCCESS", "JWT_ACCEPTED", NOW, null));
    }

    private static TokenUsageAuditEvent event(String id, String outcome, String resource) {
        return new TokenUsageAuditEvent(id, 1, URI.create("https://idp.example/tenants/1"), resource,
                "a".repeat(64), "b".repeat(64), "c".repeat(64), outcome, "JWT_ACCEPTED", NOW, null);
    }
}
