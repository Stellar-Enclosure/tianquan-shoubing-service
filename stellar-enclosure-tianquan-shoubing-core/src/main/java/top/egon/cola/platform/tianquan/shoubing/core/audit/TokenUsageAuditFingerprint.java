package top.egon.cola.platform.tianquan.shoubing.core.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.TreeMap;

/** Canonical event identity shared by the sender, inbox and durable receipt verifier. */
public final class TokenUsageAuditFingerprint {
    private TokenUsageAuditFingerprint() { }

    public static String of(TokenUsageAuditEvent event) {
        Objects.requireNonNull(event, "event");
        TreeMap<String, String> fields = new TreeMap<>();
        fields.put("eventId", event.eventId()); fields.put("schemaVersion", Integer.toString(event.schemaVersion()));
        fields.put("issuer", event.issuer().toASCIIString()); fields.put("resource", event.resource());
        fields.put("subjectRef", Objects.toString(event.subjectRef(), "")); fields.put("clientRef", Objects.toString(event.clientRef(), ""));
        fields.put("tokenRef", Objects.toString(event.tokenRef(), "")); fields.put("result", event.result()); fields.put("reasonCode", event.reasonCode());
        fields.put("occurredAt", event.occurredAt().toString()); fields.put("traceId", Objects.toString(event.traceId(), ""));
        StringBuilder canonical = new StringBuilder("oauth-audit/v1;");
        fields.forEach((name, value) -> canonical.append(name.length()).append(':').append(name)
                .append(value.getBytes(StandardCharsets.UTF_8).length).append(':').append(value));
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(canonical.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException unavailable) { throw new IllegalStateException("SHA_256_UNAVAILABLE", unavailable); }
    }
}
