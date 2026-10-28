package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.config.OAuthKeyEncryptionProperties;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthRevocationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthRevocationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.TokenRevocationService;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthPayloadCipherComponent;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.contract.execution.ExecutionGrantContract;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class OAuthExecutionGrantServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-29T00:00:00Z");
    private static final String PURPOSE = "TIANJI_AGENT_RUN_EXECUTION";
    private static final String INTENT = "d4c0f428-12ca-487c-a600-303883a19031";
    private static final URI TARGET = URI.create("https://api.example/tianji");
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/101"))
            .realmKey("tenant:101").realmType(RealmTypeEnum.TENANT).storagePartitionId(101L)
            .businessTenantId(101L).trustVersion(2L).build();
    private final OAuthExecutionGrantProperties.Service source = new OAuthExecutionGrantProperties.Service(
            11, "agent-service", "agent", "platform", "tianji", "test", TARGET.toASCIIString());
    private final OAuthExecutionGrantProperties.Service verifier = new OAuthExecutionGrantProperties.Service(
            20, "rbac-service", "rbac", "platform", "jianshen", "test", "https://api.example/jianshen");
    private final OAuthAuthorityService authority = mock(OAuthAuthorityService.class);
    private final OAuthExecutionPrimaryGuard primary = mock(OAuthExecutionPrimaryGuard.class);
    private final OAuthRevocationRepository revocations = mock(OAuthRevocationRepository.class);
    private final TokenRevocationService revocationWriter = mock(TokenRevocationService.class);
    private final Clock clock = mock(Clock.class);
    @TempDir Path directory;
    private OAuthPayloadCipherComponent cipher;
    private ObjectMapper mapper;
    private OAuthExecutionGrantService service;
    private StoredUserExecutionProof user;
    private OAuthAuthorityService.Caller sourceCaller;
    private OAuthAuthorityService.Caller verifierCaller;

    @BeforeEach
    void setUp() throws Exception {
        Path key = directory.resolve("fixture-key");
        Files.write(key, new byte[32]);
        Files.setPosixFilePermissions(key, PosixFilePermissions.fromString("rw-------"));
        cipher = new OAuthPayloadCipherComponent(new OAuthKeyEncryptionProperties().setKeyId("test-key").setKeyFile(key));
        cipher.initializeKey();
        mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        when(clock.instant()).thenReturn(NOW);
        service = service(binding(Duration.ofHours(1), Set.of("tianji:agent:start"), Set.of("tianji:agent:read")));
        user = proof(Set.of("openid", "tianji:agent:start", "tianji:agent:read"));
        sourceCaller = caller(source, IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE, 21, "301", "e".repeat(64));
        verifierCaller = caller(verifier, IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE, 41, "401", "f".repeat(64));
        when(authority.captureExecutionUser(sourceCaller, TARGET, "user-proof")).thenReturn(user);
        when(authority.recheckExecutionUser(realm, user)).thenReturn(current(user, NOW.plusSeconds(28_800)));
    }

    @Test
    void feature_is_disabled_by_default() {
        new ApplicationContextRunner().withUserConfiguration(OAuthExecutionGrantService.class).run(context ->
                assertFalse(context.containsBean("oauthExecutionGrantService")));
        assertThrows(IllegalArgumentException.class, () -> new OAuthExecutionGrantService(
                new OAuthExecutionGrantProperties(false, List.of()), authority, primary, revocations, cipher, mapper, clock));
    }

    @Test
    void issue_and_independent_verifier_bind_identity_run_policy_and_scopes() {
        var issued = service.issue(sourceCaller, "user-proof", request(true, NOW.plusSeconds(7_200)));
        assertEquals(NOW.plusSeconds(3_600), issued.expiresAt());
        assertTrue(issued.ticket().grantId().matches("9[0-9]{62}"));
        assertFalse(issued.toString().contains(issued.ticket().ciphertext()));
        assertFalse(issued.ticket().ciphertext().contains("user-proof"));
        var result = service.resolve(verifierCaller, issued.ticket());
        assertEquals("alice", result.subject());
        assertEquals(101, result.tenantId());
        assertEquals(TARGET.toASCIIString(), result.resource());
        assertEquals(INTENT, result.intentId());
        assertEquals("c".repeat(64), result.bindingSha256());
        assertTrue(result.sessionRequired());
        assertEquals(issued.expiresAt(), result.expiresAt());
        assertEquals(NOW.plusSeconds(7_200), result.intentDeadlineAt());
        assertFalse(result.toString().contains("alice"));
        verify(authority).requireExecutionService(eq(sourceCaller), eq(source.binding()), eq(user),
                eq(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE));
        verify(authority).requireExecutionService(eq(verifierCaller), eq(verifier.binding()), eq(user),
                eq(IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE));
        verify(authority).requireRecordedExecutionSource(eq(realm), any(), eq(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE));
    }

    @Test
    void transport_contract_preserves_the_sealed_intent_and_fresh_user_revocation() {
        var request = new ExecutionGrantContract.IssueRequest("user-proof", PURPOSE, INTENT, "c".repeat(64),
                true, NOW.plusSeconds(7_200));
        var issued = service.issue(sourceCaller, request);
        var result = service.resolve(verifierCaller, new ExecutionGrantContract.ResolveRequest(issued.ticket()));
        assertEquals(issued.ticket().grantId(), result.grantId());
        assertEquals(request.purpose(), result.purpose()); assertEquals(request.intentId(), result.intentId());
        assertEquals(request.bindingSha256(), result.bindingSha256()); assertTrue(result.sessionRequired());
        assertEquals(request.deadlineAt(), result.intentDeadlineAt()); assertEquals(issued.expiresAt(), result.expiresAt());
        assertEquals("alice", result.subject()); assertEquals(user.scopes(), result.scopes());
        assertEquals(new ExecutionGrantContract.Source(source.clientId(), source.appId(), source.businessCode(),
                source.applicationCode(), source.environment()), result.source());
        var revokeCaller = caller(source, IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE, 51, "501", "1".repeat(64));
        when(authority.captureExecutionUser(revokeCaller, TARGET, "fresh-proof", IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE))
                .thenReturn(user);
        service.revoke(revokeCaller, new ExecutionGrantContract.RevokeRequest("fresh-proof", issued.ticket()));
        verify(revocationWriter).revokeExecutionGrant(realm, result.grantId(), request.deadlineAt());
    }

    @Test
    void revocation_blocks_resolution_and_all_reissuance_for_the_same_run() {
        var request = request(false, NOW.plusSeconds(1_800));
        var issued = service.issue(sourceCaller, "user-proof", request);
        when(revocations.findByTarget(realm, OAuthSecurityTargetEnum.JTI, issued.ticket().grantId()))
                .thenReturn(Optional.of(mock(OAuthRevocationBO.class)));
        assertRejected(() -> service.resolve(verifierCaller, issued.ticket()));
        assertRejected(() -> service.issue(sourceCaller, "user-proof", request));
    }

    @Test
    void user_scopes_session_requirement_and_deadline_fail_closed() {
        StoredUserExecutionProof noRead = proof(Set.of("openid", "tianji:agent:start"));
        when(authority.captureExecutionUser(sourceCaller, TARGET, "user-proof")).thenReturn(noRead);
        assertRejected(() -> service.issue(sourceCaller, "user-proof", request(true, NOW.plusSeconds(600))));
        StoredUserExecutionProof noStart = proof(Set.of("openid", "tianji:agent:read"));
        when(authority.captureExecutionUser(sourceCaller, TARGET, "user-proof")).thenReturn(noStart);
        assertRejected(() -> service.issue(sourceCaller, "user-proof", request(false, NOW.plusSeconds(600))));
        assertRejected(() -> service.issue(sourceCaller, "user-proof", request(false, NOW)));
        assertThrows(IllegalArgumentException.class, () -> new OAuthExecutionGrantService.IssueRequest(
                PURPOSE, "not-a-uuid", "c".repeat(64), false, NOW.plusSeconds(600)));
        assertThrows(IllegalArgumentException.class, () -> new OAuthExecutionGrantService.IssueRequest(
                PURPOSE, INTENT, "c".repeat(64), false, Instant.MAX));
    }

    @Test
    void wrong_verifier_tampering_and_policy_drift_are_rejected() {
        var issued = service.issue(sourceCaller, "user-proof", request(false, NOW.plusSeconds(1_800)));
        assertRejected(() -> service.resolve(sourceCaller, issued.ticket()));
        String ciphertext = issued.ticket().ciphertext();
        int position = ciphertext.length() - 8;
        String changed = ciphertext.substring(0, position) + (ciphertext.charAt(position) == 'A' ? 'B' : 'A')
                + ciphertext.substring(position + 1);
        assertRejected(() -> service.resolve(verifierCaller, new OpaqueExecutionGrantCodec.Ticket(issued.ticket().grantId(), changed)));
        var changedPolicy = service(binding(Duration.ofMinutes(30), Set.of("tianji:agent:start"), Set.of("tianji:agent:read")));
        assertRejected(() -> changedPolicy.resolve(verifierCaller, issued.ticket()));
    }

    @Test
    void expiry_during_verification_or_shortened_authority_never_returns_a_grant() {
        when(clock.instant()).thenReturn(NOW, NOW.plusSeconds(400));
        assertRejected(() -> service.issue(sourceCaller, "user-proof", request(false, NOW.plusSeconds(1_800))));
        when(clock.instant()).thenReturn(NOW);
        var issued = service.issue(sourceCaller, "user-proof", request(false, NOW.plusSeconds(1_800)));
        when(authority.recheckExecutionUser(realm, user)).thenReturn(current(user, NOW.plusSeconds(60)));
        assertRejected(() -> service.resolve(verifierCaller, issued.ticket()));
        when(authority.recheckExecutionUser(realm, user)).thenReturn(current(user, NOW.plusSeconds(28_800)));
        when(clock.instant()).thenReturn(NOW.plusSeconds(1_800));
        assertRejected(() -> service.resolve(verifierCaller, issued.ticket()));
    }

    @Test
    void identity_or_scope_drift_from_the_authority_cannot_widen_a_grant() {
        when(authority.recheckExecutionUser(realm, user)).thenReturn(new OAuthAuthorityService.ExecutionUserCurrent(
                user.issuer(), user.tenantId(), "another-user", user.resourceUri(), user.scopes(), NOW.plusSeconds(28_800)));
        var failure = assertThrows(OAuth2AuthenticationException.class,
                () -> service.issue(sourceCaller, "user-proof", request(false, NOW.plusSeconds(600))));
        assertEquals("temporarily_unavailable", failure.getError().getErrorCode());
        when(authority.recheckExecutionUser(realm, user)).thenReturn(current(user, NOW.plusSeconds(28_800)));
        var issued = service.issue(sourceCaller, "user-proof", request(false, NOW.plusSeconds(600)));
        when(authority.recheckExecutionUser(realm, user)).thenReturn(new OAuthAuthorityService.ExecutionUserCurrent(
                user.issuer(), user.tenantId(), user.subject(), user.resourceUri(), Set.of("tianji:agent:start", "extra"),
                NOW.plusSeconds(28_800)));
        failure = assertThrows(OAuth2AuthenticationException.class, () -> service.resolve(verifierCaller, issued.ticket()));
        assertEquals("temporarily_unavailable", failure.getError().getErrorCode());
    }

    @Test
    void fresh_owner_and_current_source_revoke_the_stable_run_identifier() {
        var issued = service.issue(sourceCaller, "user-proof", request(false, NOW.plusSeconds(7_200)));
        var revokeCaller = caller(source, IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE, 51, "501", "1".repeat(64));
        when(authority.captureExecutionUser(revokeCaller, TARGET, "fresh-proof", IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE))
                .thenReturn(user);
        service.revoke(revokeCaller, "fresh-proof", issued.ticket());
        verify(authority).requireExecutionService(eq(revokeCaller), eq(source.binding()), eq(user),
                eq(IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE));
        verify(revocationWriter).revokeExecutionGrant(realm, issued.ticket().grantId(), NOW.plusSeconds(7_200));
    }

    @Test
    void a_different_user_or_unconfigured_service_cannot_revoke_another_users_grant() {
        var issued = service.issue(sourceCaller, "user-proof", request(false, NOW.plusSeconds(600)));
        var revokeCaller = caller(source, IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE, 51, "501", "1".repeat(64));
        StoredUserExecutionProof other = new StoredUserExecutionProof(user.issuer(), user.tenantId(), user.issuerTrustVersion(),
                "other-user", user.resourceUri(), user.clientPk(), user.clientId(), user.authorizationId(), user.tokenDigest(),
                user.tokenJti(), user.signingKeyId(), user.scopes(), user.realmGeneration(), user.clientGeneration(),
                user.subjectGeneration(), user.authenticationJtiDigest(), user.acr(), user.authenticationTime(),
                user.authenticationExpiresAt(), user.authorizationExpiresAt(), user.refreshGeneration(), user.tokenRetainUntil());
        when(authority.captureExecutionUser(revokeCaller, TARGET, "fresh-proof", IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE))
                .thenReturn(other);
        assertRejected(() -> service.revoke(revokeCaller, "fresh-proof", issued.ticket()));
        verifyNoInteractions(revocationWriter);
    }

    @Test
    void a_replacement_source_client_can_revoke_the_old_clients_grant() {
        var issued = service.issue(sourceCaller, "user-proof", request(false, NOW.plusSeconds(600)));
        var replacement = new OAuthExecutionGrantProperties.Service(16, "replacement", "agent", "platform",
                "tianji", "test", TARGET.toASCIIString());
        var changed = new OAuthExecutionGrantProperties.Binding(realm.getIssuer().toASCIIString(), 101, replacement, verifier,
                PURPOSE, Set.of("tianji:agent:start"), Set.of("tianji:agent:read"), Duration.ofHours(1));
        var replacementService = service(changed);
        var revokeCaller = caller(replacement, IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE, 51, "501", "1".repeat(64));
        when(authority.captureExecutionUser(revokeCaller, TARGET, "fresh-proof", IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE))
                .thenReturn(user);
        replacementService.revoke(revokeCaller, "fresh-proof", issued.ticket());
        verify(revocationWriter).revokeExecutionGrant(realm, issued.ticket().grantId(), NOW.plusSeconds(600));
    }

    @Test
    void a_fresh_user_can_revoke_an_expired_copy_before_the_run_deadline() {
        var issued = service.issue(sourceCaller, "user-proof", request(false, NOW.plusSeconds(7_200)));
        when(clock.instant()).thenReturn(NOW.plusSeconds(3_700));
        var principal = new ServiceIdentityPrincipal(source.clientId(), "101", source.clientId(), "501",
                URI.create("https://api.example/idp"), 1, Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE),
                source.businessCode(), source.applicationCode(), source.environment(), "credential",
                NOW.plusSeconds(3_600), NOW.plusSeconds(4_000), source.appId(), ServiceTokenContext.TENANT);
        var freshCaller = new OAuthAuthorityService.Caller(principal, realm, source.clientPk(), TARGET, 1L, 2L,
                51L, "1".repeat(64), NOW.plusSeconds(86_400), "source-key");
        when(authority.captureExecutionUser(freshCaller, TARGET, "fresh-proof", IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE))
                .thenReturn(user);
        service.revoke(freshCaller, "fresh-proof", issued.ticket());
        verify(revocationWriter).revokeExecutionGrant(realm, issued.ticket().grantId(), NOW.plusSeconds(7_200));
    }

    @Test
    void an_older_revocation_implementation_cannot_report_success() {
        var issued = service.issue(sourceCaller, "user-proof", request(false, NOW.plusSeconds(600)));
        var revokeCaller = caller(source, IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE, 51, "501", "1".repeat(64));
        when(authority.captureExecutionUser(revokeCaller, TARGET, "fresh-proof", IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE))
                .thenReturn(user);
        doThrow(new UnsupportedOperationException("fixture internal detail")).when(revocationWriter)
                .revokeExecutionGrant(realm, issued.ticket().grantId(), NOW.plusSeconds(600));
        var failure = assertThrows(OAuth2AuthenticationException.class,
                () -> service.revoke(revokeCaller, "fresh-proof", issued.ticket()));
        assertEquals("temporarily_unavailable", failure.getError().getErrorCode());
        assertFalse(failure.toString().contains("fixture internal detail"));
        var oldConstructor = new OAuthExecutionGrantService(new OAuthExecutionGrantProperties(true,
                List.of(binding(Duration.ofHours(1), Set.of("tianji:agent:start"), Set.of("tianji:agent:read")))),
                authority, primary, revocations, cipher, mapper, clock);
        failure = assertThrows(OAuth2AuthenticationException.class,
                () -> oldConstructor.revoke(revokeCaller, "fresh-proof", issued.ticket()));
        assertEquals("temporarily_unavailable", failure.getError().getErrorCode());
    }

    private OAuthExecutionGrantService service(OAuthExecutionGrantProperties.Binding binding) {
        return new OAuthExecutionGrantService(new OAuthExecutionGrantProperties(true, List.of(binding)), authority,
                primary, revocations, cipher, mapper, clock, revocationWriter);
    }

    private OAuthExecutionGrantProperties.Binding binding(Duration max, Set<String> required, Set<String> session) {
        return new OAuthExecutionGrantProperties.Binding(realm.getIssuer().toASCIIString(), 101, source, verifier,
                PURPOSE, required, session, max);
    }

    private static OAuthExecutionGrantService.IssueRequest request(boolean session, Instant deadline) {
        return new OAuthExecutionGrantService.IssueRequest(PURPOSE, INTENT, "c".repeat(64), session, deadline);
    }

    private StoredUserExecutionProof proof(Set<String> scopes) {
        return new StoredUserExecutionProof(realm.getIssuer().toASCIIString(), 101, 2, "alice", TARGET.toASCIIString(),
                12, "web", 22, "a".repeat(64), "302", "user-key", scopes, 1, 2, 3,
                "b".repeat(64), "PASSWORD", NOW.getEpochSecond(), NOW.plusSeconds(28_800).getEpochSecond(),
                NOW.plusSeconds(28_800).getEpochSecond(), 0, NOW.plusSeconds(86_400));
    }

    private static OAuthAuthorityService.ExecutionUserCurrent current(StoredUserExecutionProof proof, Instant validUntil) {
        return new OAuthAuthorityService.ExecutionUserCurrent(proof.issuer(), proof.tenantId(), proof.subject(),
                proof.resourceUri(), proof.scopes(), validUntil);
    }

    private OAuthAuthorityService.Caller caller(OAuthExecutionGrantProperties.Service binding, String scope,
                                                long authorization, String jti, String digest) {
        var principal = new ServiceIdentityPrincipal(binding.clientId(), "101", binding.clientId(), jti,
                URI.create("https://api.example/idp"), 1, Set.of(scope), binding.businessCode(), binding.applicationCode(),
                binding.environment(), "credential", NOW.minusSeconds(60), NOW.plusSeconds(300), binding.appId(), ServiceTokenContext.TENANT);
        return new OAuthAuthorityService.Caller(principal, realm, binding.clientPk(), URI.create(binding.resourceUri()),
                1L, 2L, authorization, digest, NOW.plusSeconds(86_400), "source-key");
    }

    private static void assertRejected(Runnable operation) {
        var failure = assertThrows(OAuth2AuthenticationException.class, operation::run);
        assertEquals("invalid_grant", failure.getError().getErrorCode());
    }
}
