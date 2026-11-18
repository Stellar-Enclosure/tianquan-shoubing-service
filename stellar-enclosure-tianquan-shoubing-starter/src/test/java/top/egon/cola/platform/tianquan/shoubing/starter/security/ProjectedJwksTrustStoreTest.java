package top.egon.cola.platform.tianquan.shoubing.starter.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ProjectedJwksTrustStoreTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final URI ISSUER = URI.create("https://idp.example/tenants/1001");
    private static final URI JWKS = URI.create(ISSUER + "/oauth2/jwks");
    private static final URI OTHER = URI.create("https://idp.example/tenants/1002");
    private static final Instant NOW = Instant.parse("2026-11-18T12:00:00Z");
    private static RSAKey oldKey, newKey;
    @TempDir Path directory;

    @BeforeAll static void generateKeys() throws Exception {
        oldKey = new RSAKeyGenerator(2048).keyID("old").algorithm(JWSAlgorithm.RS256).generate();
        newKey = new RSAKeyGenerator(2048).keyID("new").algorithm(JWSAlgorithm.RS256).generate();
    }

    @Test void loadsOnlyTheExactIssuerJwksAndVersionFromTheProjection() throws Exception {
        var file = write(entry(ISSUER, 2, NOW.plusSeconds(600), oldKey));
        var store = store(file);
        var loaded = store.resolve(ISSUER, JWKS, 2);
        assertThat(loaded.keys()).extracting(RSAKey::getKeyID).containsExactly("old");
        assertThat(loaded.keys().getFirst().isPrivate()).isFalse();
        assertThat(loaded.trustVersion()).isEqualTo(2);
        assertUnavailable(() -> store.resolve(OTHER, URI.create(OTHER + "/oauth2/jwks"), 1));
        assertUnavailable(() -> store.resolve(ISSUER, URI.create(ISSUER + "/other"), 1));
        assertUnavailable(() -> store.resolve(ISSUER, JWKS, 3));
        assertThatThrownBy(() -> loaded.keys().clear()).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test void supportsOverlapThenWithdrawalWithoutRevivingAnOlderKeySet() throws Exception {
        var file = write(entry(ISSUER, 1, NOW.plusSeconds(600), oldKey));
        var store = store(file);
        store.reload();
        write(file, entry(ISSUER, 2, NOW.plusSeconds(600), oldKey, newKey));
        assertThat(store.resolve(ISSUER, JWKS, 1).keys()).hasSize(2);
        write(file, entry(ISSUER, 3, NOW.plusSeconds(600), newKey));
        assertThat(store.resolve(ISSUER, JWKS, 1).keys()).extracting(RSAKey::getKeyID).containsExactly("new");
        write(file, entry(ISSUER, 2, NOW.plusSeconds(600), oldKey, newKey));
        assertUnavailable(() -> store.resolve(ISSUER, JWKS, 1));
        write(file, entry(ISSUER, 3, NOW.plusSeconds(600), newKey));
        assertThat(store.resolve(ISSUER, JWKS, 1).keys()).extracting(RSAKey::getKeyID).containsExactly("new");
    }

    @Test void sameVersionConflictsAndReaddingAWithdrawnIssuerRequireAHigherVersion() throws Exception {
        var file = write(entry(ISSUER, 2, NOW.plusSeconds(600), oldKey), entry(OTHER, 1, NOW.plusSeconds(600), newKey));
        var store = store(file);
        store.reload();
        write(file, entry(ISSUER, 2, NOW.plusSeconds(600), newKey), entry(OTHER, 1, NOW.plusSeconds(600), newKey));
        assertUnavailable(store::reload);
        write(file, entry(OTHER, 1, NOW.plusSeconds(600), newKey));
        store.reload();
        write(file, entry(ISSUER, 2, NOW.plusSeconds(600), oldKey), entry(OTHER, 1, NOW.plusSeconds(600), newKey));
        assertUnavailable(store::reload);
        write(file, entry(ISSUER, 3, NOW.plusSeconds(600), oldKey), entry(OTHER, 1, NOW.plusSeconds(600), newKey));
        assertThat(store.resolve(ISSUER, JWKS, 3).keys()).hasSize(1);
    }

    @Test void expirationIsPerIssuerAndNeverExtendedByRereadingIdenticalBytes() throws Exception {
        var time = new AtomicReference<>(NOW);
        Clock clock = new Clock() {
            @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(java.time.ZoneId zone) { return this; }
            @Override public Instant instant() { return time.get(); }
        };
        var file = write(entry(ISSUER, 1, NOW.plusSeconds(1), oldKey), entry(OTHER, 1, NOW.plusSeconds(600), newKey));
        var store = new ProjectedJwksTrustStore(file, MAPPER, clock);
        store.reload();
        time.set(NOW.plusSeconds(1));
        assertUnavailable(() -> store.resolve(ISSUER, JWKS, 1));
        assertThat(store.resolve(OTHER, URI.create(OTHER + "/oauth2/jwks"), 1).keys()).hasSize(1);
        Files.delete(file);
        assertUnavailable(() -> store.resolve(OTHER, URI.create(OTHER + "/oauth2/jwks"), 1));
    }

    @Test void rejectsCorruptionUnknownFieldsAndOversizeRatherThanUsingAnUnboundedLastGoodSet() throws Exception {
        var file = write(entry(ISSUER, 1, NOW.plusSeconds(600), oldKey));
        var store = store(file);
        store.reload();
        for (String content : List.of("{broken", "{\"issuers\":[],\"trustedDigest\":\"from-http\"}",
                "{\"issuers\":[],\"issuers\":[]}", " ".repeat(ProjectedJwksTrustStore.MAX_BYTES + 1))) {
            Files.writeString(file, content);
            assertUnavailable(() -> store.resolve(ISSUER, JWKS, 1));
        }
    }

    @Test void rejectsWeakPrivateDuplicateAndInconsistentSigningKeys() throws Exception {
        var privateEntry = entry(ISSUER, 1, NOW.plusSeconds(600), oldKey);
        privateEntry.withArray("keys").set(0, MAPPER.valueToTree(oldKey.toJSONObject()));
        var duplicate = entry(ISSUER, 1, NOW.plusSeconds(600), oldKey, oldKey);
        var weak = entry(ISSUER, 1, NOW.plusSeconds(600), oldKey);
        ((ObjectNode) weak.withArray("keys").get(0)).put("n", com.nimbusds.jose.util.Base64URL.encode(
                java.math.BigInteger.ONE.shiftLeft(1023).setBit(0)).toString());
        var wrongUse = entry(ISSUER, 1, NOW.plusSeconds(600), oldKey);
        ((ObjectNode) wrongUse.withArray("keys").get(0)).put("use", "enc");
        var wrongAlg = entry(ISSUER, 1, NOW.plusSeconds(600), oldKey);
        ((ObjectNode) wrongAlg.withArray("keys").get(0)).put("alg", "RS512");
        var remote = entry(ISSUER, 1, NOW.plusSeconds(600), oldKey);
        ((ObjectNode) remote.withArray("keys").get(0)).put("x5u", "http://attacker/key");
        for (ObjectNode invalid : List.of(privateEntry, duplicate, weak, wrongUse, wrongAlg, remote)) {
            var file = write(invalid);
            assertUnavailable(() -> store(file).resolve(ISSUER, JWKS, 1));
        }
    }

    @Test void identicalKidNamesAcrossIssuersRemainIndependentAndAnEmptyTrustedSetProvesNoKeyIsAuthorized() throws Exception {
        RSAKey sameKid = new RSAKey.Builder(newKey).keyID("old").build();
        var file = write(entry(ISSUER, 1, NOW.plusSeconds(600), oldKey), entry(OTHER, 1, NOW.plusSeconds(600), sameKid));
        var store = store(file);
        assertThat(store.resolve(ISSUER, JWKS, 1).keys().getFirst().getModulus())
                .isNotEqualTo(store.resolve(OTHER, URI.create(OTHER + "/oauth2/jwks"), 1).keys().getFirst().getModulus());
        write(file, entry(ISSUER, 2, NOW.plusSeconds(600)), entry(OTHER, 1, NOW.plusSeconds(600), sameKid));
        assertThat(store.resolve(ISSUER, JWKS, 2).keys()).isEmpty();
    }

    private ProjectedJwksTrustStore store(Path file) {
        return new ProjectedJwksTrustStore(file, MAPPER, Clock.fixed(NOW, ZoneOffset.UTC));
    }
    private Path write(ObjectNode... entries) throws Exception {
        Path file = directory.resolve("trust.json").toAbsolutePath();
        write(file, entries);
        return file;
    }
    private void write(Path file, ObjectNode... entries) throws Exception {
        var document = MAPPER.createObjectNode();
        var issuers = document.putArray("issuers");
        for (var entry : entries) { issuers.add(entry); }
        MAPPER.writeValue(file.toFile(), document);
    }
    private ObjectNode entry(URI issuer, long version, Instant until, RSAKey... keys) {
        var value = MAPPER.createObjectNode();
        value.put("issuer", issuer.toASCIIString());
        value.put("jwksUri", issuer + "/oauth2/jwks");
        value.put("trustVersion", version);
        value.put("validUntil", until.toString());
        var array = value.putArray("keys");
        for (RSAKey key : keys) { array.add(MAPPER.valueToTree(key.toPublicJWK().toJSONObject())); }
        return value;
    }
    private void assertUnavailable(org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOf(ProjectedJwksTrustStore.UnavailableException.class)
                .hasMessage("IDP_PROJECTED_JWKS_UNAVAILABLE").hasNoCause();
    }
}
