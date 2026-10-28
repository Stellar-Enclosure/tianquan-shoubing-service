package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.config.OAuthKeyEncryptionProperties;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthPayloadCipherComponent;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class OpaqueExecutionGrantCodecTest {
    private static final Instant NOW = Instant.parse("2026-10-29T00:00:00Z");
    private static final String INTENT = "d4c0f428-12ca-487c-a600-303883a19031";
    private static final String PURPOSE = "TIANJI_AGENT_RUN_EXECUTION";
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/101"))
            .realmKey("tenant:101").realmType(RealmTypeEnum.TENANT).storagePartitionId(101L)
            .businessTenantId(101L).trustVersion(2L).build();
    @TempDir Path directory;
    private OAuthPayloadCipherComponent cipher;
    private ObjectMapper mapper;
    private OpaqueExecutionGrantCodec codec;

    @BeforeEach
    void setUp() throws Exception {
        Path key = directory.resolve("fixture-key");
        Files.write(key, new byte[32]);
        Files.setPosixFilePermissions(key, PosixFilePermissions.fromString("rw-------"));
        cipher = new OAuthPayloadCipherComponent(new OAuthKeyEncryptionProperties().setKeyId("test-key").setKeyFile(key));
        cipher.initializeKey();
        mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        codec = new OpaqueExecutionGrantCodec(cipher, mapper);
    }

    @Test
    void sealed_evidence_is_confidential_realm_bound_and_recoverable() {
        ExecutionGrantEnvelope envelope = envelope(INTENT, "c".repeat(64));
        var first = codec.seal(realm, envelope);
        var second = codec.seal(realm, envelope);
        assertEquals(first.grantId(), second.grantId());
        assertNotEquals(first.ciphertext(), second.ciphertext());
        assertEquals(envelope, codec.open(realm, first));
        assertFalse(first.ciphertext().contains("alice"));
        assertFalse(first.toString().contains(first.ciphertext()));
        assertFalse(envelope.toString().contains("alice"));
        assertThrows(IllegalArgumentException.class,
                () -> cipher.decrypt(realm, "token-metadata", first.grantId(), first.ciphertext()));
        TrustedRealmBO otherIssuer = TrustedRealmBO.builder().issuer(URI.create("https://other.example/tenants/101"))
                .realmKey("tenant:101").realmType(RealmTypeEnum.TENANT).storagePartitionId(101L)
                .businessTenantId(101L).trustVersion(2L).build();
        assertThrows(IllegalArgumentException.class, () -> codec.open(otherIssuer, first));
    }

    @Test
    void altered_ciphertext_or_grant_identifier_cannot_be_replayed() {
        var first = codec.seal(realm, envelope(INTENT, "c".repeat(64)));
        int offset = first.ciphertext().length() - 8;
        char original = first.ciphertext().charAt(offset);
        String altered = first.ciphertext().substring(0, offset) + (original == 'A' ? 'B' : 'A')
                + first.ciphertext().substring(offset + 1);
        assertThrows(IllegalArgumentException.class,
                () -> codec.open(realm, new OpaqueExecutionGrantCodec.Ticket(first.grantId(), altered)));
        String otherId = envelope("17d85a12-4080-4ce0-86a6-b7fc9555d9e1", "c".repeat(64)).grantId();
        assertThrows(IllegalArgumentException.class,
                () -> codec.open(realm, new OpaqueExecutionGrantCodec.Ticket(otherId, first.ciphertext())));
    }

    @Test
    void grant_id_is_stable_for_one_run_and_separate_from_normal_access_token_ids() {
        var original = envelope(INTENT, "c".repeat(64));
        var changedBinding = envelope(INTENT, "d".repeat(64));
        var anotherRun = envelope("17d85a12-4080-4ce0-86a6-b7fc9555d9e1", "c".repeat(64));
        assertEquals(original.grantId(), changedBinding.grantId());
        assertNotEquals(original.grantId(), anotherRun.grantId());
        var rotatedClient = new ExecutionGrantEnvelope.ServiceBinding(16, "replacement-service", "agent", "platform",
                "tianji", "test", "https://api.example/tianji");
        assertEquals(original.grantId(), OpaqueExecutionGrantCodec.grantId(original.user(), rotatedClient, PURPOSE, INTENT));
        assertThrows(IllegalArgumentException.class, () -> OpaqueExecutionGrantCodec.grantId(
                original.user(), original.source(), PURPOSE, "x".repeat(100_000)));
        assertTrue(original.grantId().matches("9[0-9]{62}"));
        assertTrue(original.grantId().length() > 19);
        assertEquals("972723622044314141421981409055292564705970325140163685520872518", original.grantId());
    }

    @Test
    void service_tickets_are_realm_bound_confidential_and_separate_from_user_tickets() {
        var envelope = serviceEnvelope(INTENT, "c".repeat(64));
        var first = codec.sealService(realm, envelope);
        var second = codec.sealService(realm, envelope);
        assertEquals(first.grantId(), second.grantId());
        assertNotEquals(first.ciphertext(), second.ciphertext());
        assertEquals(envelope, codec.openService(realm, first));
        assertTrue(first.grantId().matches("8[0-9]{62}"));
        assertFalse(first.ciphertext().contains("worker-service"));
        assertFalse(first.toString().contains(first.ciphertext()));
        assertFalse(envelope.toString().contains("worker-service"));
        assertThrows(IllegalArgumentException.class,
                () -> cipher.decrypt(realm, "execution-grant", first.grantId(), first.ciphertext()));
        assertThrows(IllegalArgumentException.class,
                () -> new OpaqueExecutionGrantCodec.Ticket(first.grantId(), first.ciphertext()));
        var user = codec.seal(realm, envelope(INTENT, "c".repeat(64)));
        assertThrows(IllegalArgumentException.class,
                () -> new OpaqueExecutionGrantCodec.ServiceTicket(user.grantId(), user.ciphertext()));
        var otherIssuer = TrustedRealmBO.builder().issuer(URI.create("https://other.example/tenants/101"))
                .realmKey("tenant:101").realmType(RealmTypeEnum.TENANT).storagePartitionId(101L)
                .businessTenantId(101L).trustVersion(2L).build();
        assertThrows(IllegalArgumentException.class, () -> codec.openService(otherIssuer, first));
    }

    @Test
    void service_tickets_reject_altered_identifiers_ciphertext_and_noncanonical_json() throws Exception {
        var value = serviceEnvelope(INTENT, "c".repeat(64));
        var ticket = codec.sealService(realm, value);
        String otherId = serviceEnvelope("17d85a12-4080-4ce0-86a6-b7fc9555d9e1", "c".repeat(64)).grantId();
        assertThrows(IllegalArgumentException.class, () -> codec.openService(realm,
                new OpaqueExecutionGrantCodec.ServiceTicket(otherId, ticket.ciphertext())));
        int offset = ticket.ciphertext().length() - 8;
        char original = ticket.ciphertext().charAt(offset);
        String altered = ticket.ciphertext().substring(0, offset) + (original == 'A' ? 'B' : 'A')
                + ticket.ciphertext().substring(offset + 1);
        assertThrows(IllegalArgumentException.class, () -> codec.openService(realm,
                new OpaqueExecutionGrantCodec.ServiceTicket(ticket.grantId(), altered)));
        String json = mapper.writeValueAsString(value);
        for (String invalid : List.of(json.replaceFirst("\\{", "{\"schemaVersion\":1,"),
                json.replaceFirst("\\{", "{\"unexpected\":true,"))) {
            String sealed = cipher.encrypt(realm, "execution-service-grant", value.grantId(), invalid);
            assertThrows(IllegalArgumentException.class, () -> codec.openService(realm,
                    new OpaqueExecutionGrantCodec.ServiceTicket(value.grantId(), sealed)));
        }
        assertThrows(IllegalArgumentException.class, () -> new OpaqueExecutionGrantCodec.ServiceTicket(
                value.grantId(), "ENC:v1:" + "x".repeat(32_769)));
    }

    @Test
    void service_grants_are_stable_per_intent_and_cannot_outlive_their_evidence() {
        var value = serviceEnvelope(INTENT, "c".repeat(64));
        var changedBinding = serviceEnvelope(INTENT, "d".repeat(64));
        var anotherIntent = serviceEnvelope("17d85a12-4080-4ce0-86a6-b7fc9555d9e1", "c".repeat(64));
        assertEquals(value.grantId(), changedBinding.grantId());
        assertNotEquals(value.grantId(), anotherIntent.grantId());
        assertNotEquals(value.grantId(), envelope(INTENT, "c".repeat(64)).grantId());
        assertThrows(IllegalArgumentException.class, () -> new ServiceExecutionGrantEnvelope(1, value.grantId(),
                value.source(), value.verifier(), 1, 2, 33, "e".repeat(64), "301", NOW.plusSeconds(300), "source-key",
                PURPOSE, INTENT, value.bindingSha256(), "f".repeat(64), false, NOW, NOW.plusSeconds(3_600),
                NOW.plusSeconds(7_200), value.subject()));
        assertThrows(IllegalArgumentException.class, () -> new ServiceExecutionGrantEnvelope(1, value.grantId(),
                value.source(), value.verifier(), 1, 2, 33, "e".repeat(64), "301", NOW.plusSeconds(86_400), "source-key",
                PURPOSE, INTENT, value.bindingSha256(), "f".repeat(64), false, NOW, NOW.plusSeconds(28_801),
                NOW.plusSeconds(86_400), value.subject()));
        assertThrows(IllegalArgumentException.class, () -> new ServiceExecutionGrantEnvelope(1, value.grantId(),
                value.source(), value.verifier(), 1, 2, 33, "e".repeat(64), "301", NOW.plusSeconds(86_400), "source-key",
                PURPOSE, INTENT, value.bindingSha256(), "f".repeat(64), false, NOW, NOW.plusSeconds(3_600),
                NOW.plusSeconds(300), value.subject()));
        assertThrows(IllegalArgumentException.class, () -> new ServiceExecutionGrantEnvelope(1, value.grantId(),
                value.source(), value.source(), 1, 2, 33, "e".repeat(64), "301", NOW.plusSeconds(86_400), "source-key",
                PURPOSE, INTENT, value.bindingSha256(), "f".repeat(64), false, NOW, NOW.plusSeconds(3_600),
                NOW.plusSeconds(7_200), value.subject()));
        var wrongResource = new ExecutionGrantEnvelope.ServiceBinding(15, "agent-service", "agent", "platform",
                "tianji", "test", "https://api.example/other");
        String wrongId = OpaqueExecutionGrantCodec.serviceGrantId(value.subject(), wrongResource, PURPOSE, INTENT);
        assertThrows(IllegalArgumentException.class, () -> new ServiceExecutionGrantEnvelope(1, wrongId,
                wrongResource, value.verifier(), 1, 2, 33, "e".repeat(64), "301", NOW.plusSeconds(86_400), "source-key",
                PURPOSE, INTENT, value.bindingSha256(), "f".repeat(64), false, NOW, NOW.plusSeconds(3_600),
                NOW.plusSeconds(7_200), value.subject()));
    }

    @Test
    void source_and_verifier_bindings_require_exact_current_service_identity() {
        var envelope = envelope(INTENT, "c".repeat(64));
        var source = envelope.source();
        var verifier = envelope.verifier();
        var sourceCaller = caller(source, source.appId(), NOW.plusSeconds(30), Set.of("scope:issue"));
        var verifierCaller = caller(verifier, verifier.appId(), NOW.plusSeconds(30), Set.of("scope:resolve"));
        assertTrue(source.matches(sourceCaller, envelope.user(), "scope:issue", NOW));
        assertTrue(verifier.matches(verifierCaller, envelope.user(), "scope:resolve", NOW));
        assertFalse(source.matches(verifierCaller, envelope.user(), "scope:issue", NOW));
        assertFalse(source.matches(caller(source, "other-app", NOW.plusSeconds(30), Set.of("scope:issue")),
                envelope.user(), "scope:issue", NOW));
        assertFalse(source.matches(caller(source, source.appId(), NOW, Set.of("scope:issue")),
                envelope.user(), "scope:issue", NOW));
        assertFalse(source.matches(sourceCaller, envelope.user(), "scope:resolve", NOW));
        assertFalse(source.matches(new OAuthAuthorityService.Caller(sourceCaller.principal(), realm,
                sourceCaller.clientPk(), URI.create("https://API.example/tianji"), 1L, 2L, 33L,
                "e".repeat(64), NOW.plusSeconds(86_400), "source-key"), envelope.user(), "scope:issue", NOW));
        var otherRealm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/102"))
                .realmKey("tenant:102").realmType(RealmTypeEnum.TENANT).storagePartitionId(102L)
                .businessTenantId(102L).trustVersion(2L).build();
        assertFalse(source.matches(new OAuthAuthorityService.Caller(sourceCaller.principal(), otherRealm,
                sourceCaller.clientPk(), sourceCaller.sourceResource(), 1L, 2L, 33L,
                "e".repeat(64), NOW.plusSeconds(86_400), "source-key"), envelope.user(), "scope:issue", NOW));
        assertFalse(source.matches(new OAuthAuthorityService.Caller(sourceCaller.principal(), realm,
                sourceCaller.clientPk(), sourceCaller.sourceResource()), envelope.user(), "scope:issue", NOW));
    }

    @Test
    void unknown_or_duplicate_payload_fields_and_oversized_tickets_are_rejected() throws Exception {
        var value = envelope(INTENT, "c".repeat(64));
        String json = mapper.writeValueAsString(value);
        for (String invalid : List.of(json.replaceFirst("\\{", "{\"schemaVersion\":1,"),
                json.replaceFirst("\\{", "{\"unexpected\":true,"))) {
            String sealed = cipher.encrypt(realm, "execution-grant", value.grantId(), invalid);
            assertThrows(IllegalArgumentException.class,
                    () -> codec.open(realm, new OpaqueExecutionGrantCodec.Ticket(value.grantId(), sealed)));
        }
        assertThrows(IllegalArgumentException.class,
                () -> new OpaqueExecutionGrantCodec.Ticket(value.grantId(), "ENC:v1:" + "x".repeat(32_769)));
    }

    @Test
    void a_grant_cannot_outlive_the_original_authority_or_change_its_resource() {
        var value = envelope(INTENT, "c".repeat(64));
        assertThrows(IllegalArgumentException.class, () -> new ExecutionGrantEnvelope(1, value.grantId(),
                value.source(), value.verifier(), 1, 2, 33, "e".repeat(64), "301", NOW.plusSeconds(86_400), "source-key",
                PURPOSE, INTENT, value.bindingSha256(), "f".repeat(64), false, NOW,
                NOW.plusSeconds(28_801), NOW.plusSeconds(86_400), value.user()));
        assertThrows(IllegalArgumentException.class, () -> new ExecutionGrantEnvelope(1, value.grantId(),
                value.source(), value.verifier(), 1, 2, 33, "e".repeat(64), "301", NOW.plusSeconds(86_400), "source-key",
                PURPOSE, INTENT, value.bindingSha256(), "f".repeat(64), false, NOW.minusSeconds(1),
                NOW.plusSeconds(3_600), NOW.plusSeconds(7_200), value.user()));
        assertThrows(IllegalArgumentException.class, () -> new ExecutionGrantEnvelope(1, value.grantId(),
                value.source(), value.source(), 1, 2, 33, "e".repeat(64), "301", NOW.plusSeconds(86_400), "source-key",
                PURPOSE, INTENT, value.bindingSha256(), "f".repeat(64), false, NOW,
                NOW.plusSeconds(3_600), NOW.plusSeconds(7_200), value.user()));
        assertThrows(IllegalArgumentException.class, () -> new ExecutionGrantEnvelope(1, value.grantId(),
                value.source(), value.verifier(), 1, 2, 33, "e".repeat(64), "301", NOW.plusSeconds(86_400), "source-key",
                PURPOSE, INTENT, value.bindingSha256(), "f".repeat(64), false, NOW,
                NOW.plusSeconds(3_600), NOW.plusSeconds(600), value.user()));
        var wrongResource = new ExecutionGrantEnvelope.ServiceBinding(15, "agent-service", "agent", "platform",
                "tianji", "test", "https://api.example/other");
        String id = OpaqueExecutionGrantCodec.grantId(value.user(), wrongResource, PURPOSE, INTENT);
        assertNotEquals(value.grantId(), id);
        assertThrows(IllegalArgumentException.class, () -> new ExecutionGrantEnvelope(1, id, wrongResource,
                value.verifier(), 1, 2, 33, "e".repeat(64), "301", NOW.plusSeconds(86_400), "source-key",
                PURPOSE, INTENT, value.bindingSha256(), "f".repeat(64), false, NOW, NOW.plusSeconds(3_600),
                NOW.plusSeconds(7_200), value.user()));
    }

    private static ExecutionGrantEnvelope envelope(String intent, String binding) {
        var user = new StoredUserExecutionProof("https://idp.example/tenants/101", 101, 2, "alice",
                "https://api.example/tianji", 12, "web", 22, "a".repeat(64), "302", "key-1",
                Set.of("openid", "tianji:agent:start"), 1, 2, 3, "b".repeat(64), "PASSWORD",
                NOW.getEpochSecond(), NOW.plusSeconds(28_800).getEpochSecond(), NOW.plusSeconds(28_800).getEpochSecond(),
                0, NOW.plusSeconds(86_400));
        var source = new ExecutionGrantEnvelope.ServiceBinding(15, "agent-service", "agent", "platform",
                "tianji", "test", "https://api.example/tianji");
        var verifier = new ExecutionGrantEnvelope.ServiceBinding(20, "rbac-service", "rbac", "platform",
                "jianshen", "test", "https://api.example/jianshen");
        String id = OpaqueExecutionGrantCodec.grantId(user, source, PURPOSE, intent);
        return new ExecutionGrantEnvelope(1, id, source, verifier, 1, 2, 33, "e".repeat(64), "301",
                NOW.plusSeconds(86_400), "source-key", PURPOSE, intent, binding, "f".repeat(64), false,
                NOW, NOW.plusSeconds(3_600), NOW.plusSeconds(7_200), user);
    }

    private static ServiceExecutionGrantEnvelope serviceEnvelope(String intent, String binding) {
        var subject = new StoredServiceExecutionProof("https://idp.example/tenants/101", 101, 2, "worker-service",
                "https://api.example/tianji", 1, 31, "worker-service", "worker", "ops", "process", "test",
                "https://api.example/process", "31:7", 51, "a".repeat(64), "501", "worker-key",
                Set.of("tianji:agent:linked:submit"), 1, 2, NOW.plusSeconds(86_400));
        var source = new ExecutionGrantEnvelope.ServiceBinding(15, "agent-service", "agent", "platform",
                "tianji", "test", "https://api.example/tianji");
        var verifier = new ExecutionGrantEnvelope.ServiceBinding(20, "rbac-service", "rbac", "platform",
                "jianshen", "test", "https://api.example/jianshen");
        String id = OpaqueExecutionGrantCodec.serviceGrantId(subject, source, PURPOSE, intent);
        return new ServiceExecutionGrantEnvelope(1, id, source, verifier, 1, 2, 33, "e".repeat(64), "301",
                NOW.plusSeconds(86_400), "source-key", PURPOSE, intent, binding, "f".repeat(64), false,
                NOW, NOW.plusSeconds(3_600), NOW.plusSeconds(7_200), subject);
    }

    private OAuthAuthorityService.Caller caller(ExecutionGrantEnvelope.ServiceBinding binding, String appId,
                                                  Instant expiresAt, Set<String> scopes) {
        var principal = new ServiceIdentityPrincipal(binding.clientId(), "101", binding.clientId(), "301",
                URI.create("https://api.example/idp"), 1, scopes, binding.businessCode(), binding.applicationCode(),
                binding.environment(), "credential", NOW.minusSeconds(60), expiresAt, appId, ServiceTokenContext.TENANT);
        return new OAuthAuthorityService.Caller(principal, realm, binding.clientPk(), URI.create(binding.resourceUri()), 1L, 2L,
                33L, "e".repeat(64), NOW.plusSeconds(86_400), "source-key");
    }
}
