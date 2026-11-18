package top.egon.cola.platform.tianquan.shoubing.starter.security;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.JwtException;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpProjectedFileComponent;

import java.net.URI;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/** Public verification material authenticated by its deployment projection, never by an HTTP response. */
@Slf4j
public final class ProjectedJwksTrustStore {

    static final int MAX_BYTES = 1024 * 1024;
    static final int MAX_ISSUERS = 1000;
    static final int MAX_KEYS_PER_ISSUER = 64;
    private static final Set<String> ENTRY_FIELDS = Set.of("issuer", "jwksUri", "trustVersion", "validUntil", "keys");
    private static final Set<String> KEY_FIELDS = Set.of("kty", "kid", "n", "e", "alg", "use", "key_ops");
    private final Path file;
    private final ObjectMapper mapper;
    private final Clock clock;
    private Map<URI, TrustedKeysVO> current = Map.of();
    private Map<URI, AcceptedVersionVO> highest = Map.of();
    private String documentDigest;

    public ProjectedJwksTrustStore(Path file, ObjectMapper mapper, Clock clock) {
        this.file = Objects.requireNonNull(file, "file");
        this.mapper = Objects.requireNonNull(mapper, "mapper").copy()
                .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Publishes one completely validated generation; failure leaves no candidate partially trusted. */
    public synchronized void reload() {
        try {
            byte[] bytes = IdpProjectedFileComponent.read(file, MAX_BYTES);
            String digest = digest(bytes);
            if (digest.equals(documentDigest)) {
                return;
            }
            JsonNode document = mapper.readTree(bytes);
            requireFields(document, Set.of("issuers"));
            JsonNode issuers = document.get("issuers");
            if (issuers == null || !issuers.isArray() || issuers.isEmpty() || issuers.size() > MAX_ISSUERS) {
                throw new IllegalArgumentException();
            }
            Map<URI, TrustedKeysVO> candidate = new LinkedHashMap<>();
            Map<URI, AcceptedVersionVO> nextHighest = new LinkedHashMap<>(highest);
            for (JsonNode item : issuers) {
                TrustedKeysVO entry = readEntry(item);
                if (candidate.putIfAbsent(entry.issuer(), entry) != null) { throw new IllegalArgumentException(); }
                String fingerprint = entryFingerprint(entry);
                AcceptedVersionVO previous = highest.get(entry.issuer());
                if (previous != null && (entry.trustVersion() < previous.version()
                        || previous.withdrawn() && entry.trustVersion() <= previous.version()
                        || entry.trustVersion() == previous.version() && !fingerprint.equals(previous.fingerprint()))) {
                    throw new IllegalArgumentException();
                }
                nextHighest.put(entry.issuer(), new AcceptedVersionVO(entry.trustVersion(), fingerprint, false));
            }
            nextHighest.replaceAll((issuer, accepted) -> candidate.containsKey(issuer) ? accepted
                    : new AcceptedVersionVO(accepted.version(), accepted.fingerprint(), true));
            if (nextHighest.size() > MAX_ISSUERS) { throw new IllegalArgumentException(); }
            current = Map.copyOf(candidate);
            highest = Map.copyOf(nextHighest);
            documentDigest = digest;
        } catch (Exception failure) {
            // File paths, malformed JSON and key material never enter public errors or logs.
            throw new UnavailableException();
        }
    }

    /** Rechecks the projection and its lifetime even when a Nimbus decoder has already been cached. */
    public synchronized TrustedKeysVO resolve(URI issuer, URI jwksUri, long minimumTrustVersion) {
        reload();
        TrustedKeysVO entry = current.get(issuer);
        if (entry == null || !entry.jwksUri().equals(jwksUri) || minimumTrustVersion < 0
                || entry.trustVersion() < minimumTrustVersion) { throw new UnavailableException(); }
        requireFresh(entry);
        return entry;
    }

    private TrustedKeysVO readEntry(JsonNode item) throws Exception {
        requireFields(item, ENTRY_FIELDS);
        URI issuer = canonical(text(item, "issuer")), jwks = canonical(text(item, "jwksUri"));
        if (!issuer.getHost().equalsIgnoreCase(jwks.getHost()) || effectivePort(issuer) != effectivePort(jwks)) {
            throw new IllegalArgumentException();
        }
        JsonNode version = item.get("trustVersion");
        if (version == null || !version.isIntegralNumber() || !version.canConvertToLong() || version.longValue() <= 0) {
            throw new IllegalArgumentException();
        }
        String until = text(item, "validUntil");
        if (!until.endsWith("Z")) { throw new IllegalArgumentException(); }
        Instant validUntil = Instant.parse(until);
        JsonNode keys = item.get("keys");
        if (keys == null || !keys.isArray() || keys.size() > MAX_KEYS_PER_ISSUER) { throw new IllegalArgumentException(); }
        Map<String, RSAKey> unique = new LinkedHashMap<>();
        for (JsonNode value : keys) {
            requireFields(value, KEY_FIELDS);
            String kid = text(value, "kid");
            if (!kid.matches("[\\x21-\\x7e]{1,128}") || !"RSA".equals(text(value, "kty"))) {
                throw new IllegalArgumentException();
            }
            Map<String, Object> keyMap = mapper.convertValue(value, new TypeReference<>() { });
            RSAKey key = RSAKey.parse(keyMap);
            if (key.isPrivate() || key.size() < 2048 || key.size() > 8192
                    || key.getAlgorithm() != null && !JWSAlgorithm.RS256.equals(key.getAlgorithm())
                    || key.getKeyUse() != null && !KeyUse.SIGNATURE.equals(key.getKeyUse())
                    || key.getKeyOperations() != null && !Set.of(KeyOperation.VERIFY).equals(key.getKeyOperations())) {
                throw new IllegalArgumentException();
            }
            var publicKey = key.toRSAPublicKey();
            if (!publicKey.getModulus().testBit(0) || publicKey.getPublicExponent().signum() <= 0
                    || !publicKey.getPublicExponent().testBit(0)
                    || publicKey.getPublicExponent().compareTo(java.math.BigInteger.valueOf(3)) < 0
                    || publicKey.getPublicExponent().compareTo(publicKey.getModulus()) >= 0
                    || unique.putIfAbsent(kid, key) != null) { throw new IllegalArgumentException(); }
        }
        TrustedKeysVO result = new TrustedKeysVO(issuer, jwks, version.longValue(), validUntil,
                unique.values().stream().sorted(Comparator.comparing(RSAKey::getKeyID)).toList());
        return result;
    }

    private void requireFresh(TrustedKeysVO entry) {
        if (!clock.instant().isBefore(entry.validUntil())) { throw new UnavailableException(); }
    }

    private String entryFingerprint(TrustedKeysVO entry) throws Exception {
        Map<String, Object> value = new TreeMap<>();
        value.put("issuer", entry.issuer().toASCIIString());
        value.put("jwksUri", entry.jwksUri().toASCIIString());
        value.put("trustVersion", entry.trustVersion());
        value.put("validUntil", entry.validUntil().toString());
        List<Map<String, Object>> keys = new ArrayList<>();
        entry.keys().forEach(key -> keys.add(new TreeMap<>(key.toJSONObject())));
        value.put("keys", keys);
        return digest(mapper.writeValueAsBytes(value));
    }

    private static String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static void requireFields(JsonNode node, Set<String> allowed) {
        if (node == null || !node.isObject()) { throw new IllegalArgumentException(); }
        node.fieldNames().forEachRemaining(field -> { if (!allowed.contains(field)) { throw new IllegalArgumentException(); } });
    }

    private static String text(JsonNode object, String field) {
        JsonNode value = object.get(field);
        if (value == null || !value.isTextual() || value.textValue().isBlank()) { throw new IllegalArgumentException(); }
        return value.textValue();
    }

    private static URI canonical(String value) {
        URI uri = URI.create(value);
        if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.isOpaque()
                || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                || uri.getPort() == 0 || uri.getPort() > 65535 || !uri.normalize().equals(uri)
                || !uri.toASCIIString().equals(value)) { throw new IllegalArgumentException(); }
        return uri;
    }

    private static int effectivePort(URI uri) { return uri.getPort() == -1 ? 443 : uri.getPort(); }

    public record TrustedKeysVO(URI issuer, URI jwksUri, long trustVersion, Instant validUntil, List<RSAKey> keys) {
        public TrustedKeysVO { keys = List.copyOf(keys); }
    }

    private record AcceptedVersionVO(long version, String fingerprint, boolean withdrawn) { }

    /** A material/transport failure is not proof that an access token is invalid. */
    public static final class UnavailableException extends JwtException {
        public UnavailableException() { super("IDP_PROJECTED_JWKS_UNAVAILABLE"); }
    }
}
