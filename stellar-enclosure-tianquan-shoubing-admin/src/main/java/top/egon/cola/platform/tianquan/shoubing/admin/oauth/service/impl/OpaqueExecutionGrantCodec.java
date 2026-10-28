package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthPayloadCipherComponent;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.UUID;

/** Seals bounded execution evidence with the authority's existing realm-bound AEAD key. */
final class OpaqueExecutionGrantCodec {
    private static final String PURPOSE = "execution-grant";
    private static final String SERVICE_PURPOSE = "execution-service-grant";
    private static final int MAX_PLAINTEXT = 16_384;
    private static final int MAX_ENVELOPE = 32_768;
    private static final BigInteger DECIMAL_BOUND = BigInteger.TEN.pow(62);
    private final OAuthPayloadCipherComponent cipher;
    private final ObjectMapper mapper;

    OpaqueExecutionGrantCodec(OAuthPayloadCipherComponent cipher, ObjectMapper mapper) {
        this.cipher = Objects.requireNonNull(cipher, "cipher");
        this.mapper = Objects.requireNonNull(mapper, "mapper").copy()
                .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    }

    Ticket seal(TrustedRealmBO realm, ExecutionGrantEnvelope value) {
        Objects.requireNonNull(value, "value").user().requireRealm(realm);
        return new Ticket(value.grantId(), seal(realm, PURPOSE, value.grantId(), value));
    }

    ExecutionGrantEnvelope open(TrustedRealmBO realm, Ticket ticket) {
        Objects.requireNonNull(ticket, "ticket");
        ExecutionGrantEnvelope value = open(realm, PURPOSE, ticket.grantId(), ticket.ciphertext(), ExecutionGrantEnvelope.class);
        if (value == null || !ticket.grantId().equals(value.grantId())) throw invalid();
        value.user().requireRealm(realm);
        return value;
    }

    ServiceTicket sealService(TrustedRealmBO realm, ServiceExecutionGrantEnvelope value) {
        Objects.requireNonNull(value, "value").subject().requireRealm(realm);
        return new ServiceTicket(value.grantId(), seal(realm, SERVICE_PURPOSE, value.grantId(), value));
    }

    ServiceExecutionGrantEnvelope openService(TrustedRealmBO realm, ServiceTicket ticket) {
        Objects.requireNonNull(ticket, "ticket");
        var value = open(realm, SERVICE_PURPOSE, ticket.grantId(), ticket.ciphertext(), ServiceExecutionGrantEnvelope.class);
        if (value == null || !ticket.grantId().equals(value.grantId())) throw invalid();
        value.subject().requireRealm(realm);
        return value;
    }

    private String seal(TrustedRealmBO realm, String purpose, String grantId, Object value) {
        try {
            String json = mapper.writeValueAsString(value);
            if (json.getBytes(StandardCharsets.UTF_8).length > MAX_PLAINTEXT) throw invalid();
            return cipher.encrypt(realm, purpose, grantId, json);
        } catch (JsonProcessingException invalid) { throw invalid(); }
    }

    private <T> T open(TrustedRealmBO realm, String purpose, String grantId, String ciphertext, Class<T> type) {
        String json = cipher.decrypt(realm, purpose, grantId, ciphertext);
        if (json.getBytes(StandardCharsets.UTF_8).length > MAX_PLAINTEXT) throw invalid();
        try { return mapper.readValue(json, type); }
        catch (JsonProcessingException invalid) { throw invalid(); }
    }

    /** Decimal IDs longer than any access-token JTI keep the shared revocation namespace disjoint. */
    static String grantId(StoredUserExecutionProof user, ExecutionGrantEnvelope.ServiceBinding source,
                          String purpose, String intentId) {
        Objects.requireNonNull(user, "user");
        Objects.requireNonNull(source, "source");
        return grantId("tianquan-execution-grant-v1", "9", user.issuer(), user.tenantId(), source.resourceUri(), purpose, intentId);
    }

    static String serviceGrantId(StoredServiceExecutionProof subject, ExecutionGrantEnvelope.ServiceBinding source,
                                 String purpose, String intentId) {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(source, "source");
        return grantId("tianquan-service-execution-grant-v1", "8", subject.issuer(), subject.tenantId(),
                source.resourceUri(), purpose, intentId);
    }

    private static String grantId(String domain, String prefix, String issuer, long tenantId, String resource,
                                  String purpose, String intentId) {
        if (purpose == null || !purpose.matches("[A-Z][A-Z0-9_]{0,95}") || intentId == null || intentId.length() != 36) {
            throw invalid();
        }
        try {
            if (!UUID.fromString(intentId).toString().equals(intentId)) throw invalid();
        } catch (IllegalArgumentException malformed) {
            throw invalid();
        }
        try {
            var bytes = new ByteArrayOutputStream();
            try (var output = new DataOutputStream(bytes)) {
                for (String value : new String[]{domain, issuer, Long.toString(tenantId), resource, purpose, intentId}) {
                    byte[] encoded = Objects.requireNonNull(value, "grant identity").getBytes(StandardCharsets.UTF_8);
                    output.writeInt(encoded.length);
                    output.write(encoded);
                }
            }
            String decimal = new BigInteger(1, MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray()))
                    .mod(DECIMAL_BOUND).toString();
            return prefix + "0".repeat(62 - decimal.length()) + decimal;
        } catch (IOException | NoSuchAlgorithmException failure) {
            throw new IllegalStateException("EXECUTION_GRANT_DIGEST_UNAVAILABLE");
        }
    }

    record Ticket(String grantId, String ciphertext) {
        Ticket {
            if (grantId == null || !grantId.matches("9[0-9]{62}") || ciphertext == null
                    || !ciphertext.startsWith("ENC:v1:") || ciphertext.length() > MAX_ENVELOPE) throw invalid();
        }

        @Override public String toString() { return "ExecutionGrantTicket[redacted]"; }
    }

    record ServiceTicket(String grantId, String ciphertext) {
        ServiceTicket {
            if (grantId == null || !grantId.matches("8[0-9]{62}") || ciphertext == null
                    || !ciphertext.startsWith("ENC:v1:") || ciphertext.length() > MAX_ENVELOPE) throw invalid();
        }

        @Override public String toString() { return "ServiceExecutionGrantTicket[redacted]"; }
    }

    private static IllegalArgumentException invalid() { return new IllegalArgumentException("EXECUTION_GRANT_INVALID"); }
}
