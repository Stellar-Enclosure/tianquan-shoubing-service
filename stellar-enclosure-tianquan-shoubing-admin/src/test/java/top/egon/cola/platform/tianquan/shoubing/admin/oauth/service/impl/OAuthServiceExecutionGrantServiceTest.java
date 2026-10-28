package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
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

class OAuthServiceExecutionGrantServiceTest {
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
    private final OAuthExecutionGrantProperties.Service worker = new OAuthExecutionGrantProperties.Service(
            31, "worker-service", "worker", "ops", "process", "test", "https://api.example/process");
    private final OAuthAuthorityService authority = mock(OAuthAuthorityService.class);
    private final OAuthExecutionPrimaryGuard primary = mock(OAuthExecutionPrimaryGuard.class);
    private final OAuthRevocationRepository revocations = mock(OAuthRevocationRepository.class);
    private final TokenRevocationService revocationWriter = mock(TokenRevocationService.class);
    private final Clock clock = mock(Clock.class);
    @TempDir Path directory;
    private OAuthPayloadCipherComponent cipher;
    private ObjectMapper mapper;
    private OAuthServiceExecutionGrantService service;
    private StoredServiceExecutionProof subject;
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
        service = service(binding(Duration.ofHours(1), Set.of("agent:submit"), Set.of("agent:session")));
        subject = proof(Set.of("agent:submit", "agent:session"));
        sourceCaller = caller(source, IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_ISSUE, 21, "301", "e".repeat(64), NOW);
        verifierCaller = caller(verifier, IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_RESOLVE, 41, "401", "f".repeat(64), NOW);
        when(authority.captureExecutionService(sourceCaller, TARGET, "worker-proof")).thenReturn(subject);
        when(authority.recheckExecutionService(realm, subject)).thenReturn(current(subject, NOW.plusSeconds(86_400)));
    }

    @Test
    void service_grants_are_disabled_without_explicit_bindings() {
        new ApplicationContextRunner().withUserConfiguration(OAuthServiceExecutionGrantService.class).run(context ->
                assertFalse(context.containsBean("oauthServiceExecutionGrantService")));
        assertThrows(IllegalArgumentException.class, () -> new OAuthServiceExecutionGrantService(
                new OAuthServiceExecutionGrantProperties(false, List.of()), authority, primary, revocations,
                cipher, mapper, clock, revocationWriter));
        assertThrows(IllegalArgumentException.class, () -> new OAuthServiceExecutionGrantProperties(true, List.of()));
        assertThrows(IllegalArgumentException.class, () -> new OAuthServiceExecutionGrantProperties(true,
                List.of(binding(Duration.ofHours(1), Set.of("agent:submit"), Set.of()),
                        binding(Duration.ofHours(2), Set.of("agent:submit"), Set.of()))));
        assertThrows(IllegalArgumentException.class, () -> new OAuthServiceExecutionGrantProperties.Binding(
                realm.getIssuer().toASCIIString(), 101, source, verifier, verifier, PURPOSE,
                Set.of("agent:submit"), Set.of(), Duration.ofHours(1)));
    }

    @Test
    void deployment_properties_bind_the_three_exact_services_and_scope_policy() {
        String p = "egon.tianquan-shoubing.service-execution-grants.";
        String b = p + "bindings[0].";
        new ApplicationContextRunner().withUserConfiguration(PropertiesConfiguration.class).withPropertyValues(
                p + "enabled=true", b + "issuer=https://idp.example/tenants/101", b + "tenant-id=101",
                b + "purpose=" + PURPOSE, b + "required-service-scopes[0]=agent:submit",
                b + "session-service-scopes[0]=agent:session", b + "max-lifetime=30m",
                b + "source.client-pk=11", b + "source.client-id=agent-service", b + "source.app-id=agent",
                b + "source.business-code=platform", b + "source.application-code=tianji", b + "source.environment=test",
                b + "source.resource-uri=https://api.example/tianji",
                b + "verifier.client-pk=20", b + "verifier.client-id=rbac-service", b + "verifier.app-id=rbac",
                b + "verifier.business-code=platform", b + "verifier.application-code=jianshen", b + "verifier.environment=test",
                b + "verifier.resource-uri=https://api.example/jianshen",
                b + "subject.client-pk=31", b + "subject.client-id=worker-service", b + "subject.app-id=worker",
                b + "subject.business-code=ops", b + "subject.application-code=process", b + "subject.environment=test",
                b + "subject.resource-uri=https://api.example/process")
                .run(context -> {
                    assertNull(context.getStartupFailure());
                    var bound = context.getBean(OAuthServiceExecutionGrantProperties.class);
                    assertTrue(bound.enabled());
                    assertEquals(binding(Duration.ofMinutes(30), Set.of("agent:submit"), Set.of("agent:session")),
                            bound.bindings().getFirst());
                });
    }

    @Test
    void issue_and_verifier_bind_source_subject_intent_and_session_scopes() {
        var issued = service.issue(sourceCaller, "worker-proof", request(true, NOW.plusSeconds(7_200)));
        assertEquals(NOW.plusSeconds(3_600), issued.expiresAt());
        assertTrue(issued.ticket().grantId().matches("8[0-9]{62}"));
        assertFalse(issued.ticket().ciphertext().contains("worker-proof"));
        assertFalse(issued.toString().contains(issued.ticket().ciphertext()));
        var resolution = service.resolve(verifierCaller, issued.ticket());
        assertEquals("worker-service", resolution.subject());
        assertEquals(101, resolution.tenantId());
        assertEquals(TARGET.toASCIIString(), resolution.resource());
        assertEquals(source.binding(), resolution.source());
        assertEquals(worker.binding(), resolution.subjectSource());
        assertEquals(INTENT, resolution.intentId());
        assertEquals("c".repeat(64), resolution.bindingSha256());
        assertTrue(resolution.sessionRequired());
        assertEquals(issued.expiresAt(), resolution.expiresAt());
        assertEquals(NOW.plusSeconds(7_200), resolution.intentDeadlineAt());
        assertEquals(subject.scopes(), resolution.scopes());
        assertFalse(resolution.toString().contains("worker-service"));
        verify(authority).requireServiceExecutionCaller(sourceCaller, source.binding(), subject,
                IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_ISSUE);
        verify(authority).requireServiceExecutionCaller(verifierCaller, verifier.binding(), subject,
                IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_RESOLVE);
        verify(authority).requireRecordedServiceExecutionSource(eq(realm), any(),
                eq(IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_ISSUE));
    }

    @Test
    void unconfigured_subject_wrong_source_or_user_scopes_cannot_issue() {
        var other = new StoredServiceExecutionProof(subject.issuer(), subject.tenantId(), subject.issuerTrustVersion(),
                "other-worker", subject.resourceUri(), subject.resourceVersion(), 32, "other-worker", subject.appId(),
                subject.businessCode(), subject.applicationCode(), subject.environment(), subject.sourceResourceUri(), "32:7",
                subject.authorizationId(), subject.tokenDigest(), subject.tokenJti(), subject.signingKeyId(), subject.scopes(),
                subject.realmGeneration(), subject.clientGeneration(), subject.tokenRetainUntil());
        when(authority.captureExecutionService(sourceCaller, TARGET, "worker-proof")).thenReturn(other);
        assertRejected(() -> service.issue(sourceCaller, "worker-proof", request(false, NOW.plusSeconds(600))));
        when(authority.captureExecutionService(sourceCaller, TARGET, "worker-proof")).thenReturn(subject);
        var oldScope = caller(source, IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE, 21, "301", "e".repeat(64), NOW);
        when(authority.captureExecutionService(oldScope, TARGET, "worker-proof")).thenReturn(subject);
        assertRejected(() -> service.issue(oldScope, "worker-proof", request(false, NOW.plusSeconds(600))));
        var wrongSource = new OAuthExecutionGrantProperties.Service(12, "other-agent", "agent", "platform", "tianji", "test", TARGET.toASCIIString());
        var outsider = caller(wrongSource, IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_ISSUE, 22, "302", "1".repeat(64), NOW);
        when(authority.captureExecutionService(outsider, TARGET, "worker-proof")).thenReturn(subject);
        assertRejected(() -> service.issue(outsider, "worker-proof", request(false, NOW.plusSeconds(600))));
    }

    @Test
    void subject_scopes_session_and_deadline_are_never_widened() {
        var noSession = proof(Set.of("agent:submit"));
        when(authority.captureExecutionService(sourceCaller, TARGET, "worker-proof")).thenReturn(noSession);
        assertRejected(() -> service.issue(sourceCaller, "worker-proof", request(true, NOW.plusSeconds(600))));
        var noSubmit = proof(Set.of("agent:session"));
        when(authority.captureExecutionService(sourceCaller, TARGET, "worker-proof")).thenReturn(noSubmit);
        assertRejected(() -> service.issue(sourceCaller, "worker-proof", request(false, NOW.plusSeconds(600))));
        assertRejected(() -> service.issue(sourceCaller, "worker-proof", request(false, NOW)));
        assertThrows(IllegalArgumentException.class, () -> new OAuthServiceExecutionGrantService.IssueRequest(
                PURPOSE, "not-a-uuid", "c".repeat(64), false, NOW.plusSeconds(600)));
        assertThrows(IllegalArgumentException.class, () -> new OAuthServiceExecutionGrantService.IssueRequest(
                PURPOSE, INTENT, "c".repeat(64), false, Instant.MAX));
    }

    @Test
    void wrong_verifier_policy_drift_or_tampered_ticket_is_rejected() {
        var issued = service.issue(sourceCaller, "worker-proof", request(false, NOW.plusSeconds(1_800)));
        assertRejected(() -> service.resolve(sourceCaller, issued.ticket()));
        var changedPolicy = service(binding(Duration.ofMinutes(30), Set.of("agent:submit"), Set.of("agent:session")));
        assertRejected(() -> changedPolicy.resolve(verifierCaller, issued.ticket()));
        String ciphertext = issued.ticket().ciphertext();
        int position = ciphertext.length() - 8;
        String changed = ciphertext.substring(0, position) + (ciphertext.charAt(position) == 'A' ? 'B' : 'A')
                + ciphertext.substring(position + 1);
        assertRejected(() -> service.resolve(verifierCaller,
                new OpaqueExecutionGrantCodec.ServiceTicket(issued.ticket().grantId(), changed)));
    }

    @Test
    void expiry_shortened_authority_and_identity_drift_fail_closed() {
        when(clock.instant()).thenReturn(NOW, NOW.plusSeconds(400));
        assertRejected(() -> service.issue(sourceCaller, "worker-proof", request(false, NOW.plusSeconds(1_800))));
        when(clock.instant()).thenReturn(NOW);
        var issued = service.issue(sourceCaller, "worker-proof", request(false, NOW.plusSeconds(1_800)));
        when(authority.recheckExecutionService(realm, subject)).thenReturn(current(subject, NOW.plusSeconds(60)));
        assertRejected(() -> service.resolve(verifierCaller, issued.ticket()));
        when(authority.recheckExecutionService(realm, subject)).thenReturn(new OAuthAuthorityService.ExecutionServiceCurrent(
                subject.issuer(), subject.tenantId(), "other", subject.resourceUri(), subject.sourceResourceUri(), subject.scopes(),
                NOW.plusSeconds(86_400)));
        var failure = assertThrows(OAuth2AuthenticationException.class, () -> service.resolve(verifierCaller, issued.ticket()));
        assertEquals("temporarily_unavailable", failure.getError().getErrorCode());
        when(authority.recheckExecutionService(realm, subject)).thenReturn(current(subject, NOW.plusSeconds(86_400)));
        when(clock.instant()).thenReturn(NOW.plusSeconds(1_800));
        assertRejected(() -> service.resolve(verifierCaller, issued.ticket()));
    }

    @Test
    void revocation_rejects_every_copy_and_reissuance_for_the_same_intent() {
        var request = request(false, NOW.plusSeconds(1_800));
        var issued = service.issue(sourceCaller, "worker-proof", request);
        when(revocations.findByTarget(realm, OAuthSecurityTargetEnum.JTI, issued.ticket().grantId()))
                .thenReturn(Optional.of(mock(OAuthRevocationBO.class)));
        assertRejected(() -> service.resolve(verifierCaller, issued.ticket()));
        assertRejected(() -> service.issue(sourceCaller, "worker-proof", request));
    }

    @Test
    void configured_source_can_revoke_after_subject_or_ticket_expiry() {
        var issued = service.issue(sourceCaller, "worker-proof", request(false, NOW.plusSeconds(7_200)));
        when(clock.instant()).thenReturn(NOW.plusSeconds(3_700));
        var revoker = caller(source, IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_REVOKE, 51, "501", "1".repeat(64),
                NOW.plusSeconds(3_600));
        service.revoke(revoker, issued.ticket());
        verify(authority).requireServiceExecutionCaller(revoker, source.binding(), subject,
                IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_REVOKE);
        verify(revocationWriter).revokeExecutionGrant(realm, issued.ticket().grantId(), NOW.plusSeconds(7_200));
        verify(authority, times(1)).recheckExecutionService(realm, subject);
    }

    @Test
    void a_replacement_source_with_the_same_resource_can_close_the_old_intent() {
        var issued = service.issue(sourceCaller, "worker-proof", request(false, NOW.plusSeconds(600)));
        var replacement = new OAuthExecutionGrantProperties.Service(16, "replacement", "agent", "platform",
                "tianji", "test", TARGET.toASCIIString());
        var changed = new OAuthServiceExecutionGrantProperties.Binding(realm.getIssuer().toASCIIString(), 101,
                replacement, verifier, worker, PURPOSE, Set.of("agent:submit"), Set.of(), Duration.ofHours(1));
        var revoker = caller(replacement, IdentityAuthorityScopes.SERVICE_EXECUTION_GRANT_REVOKE, 51, "501", "1".repeat(64), NOW);
        service(changed).revoke(revoker, issued.ticket());
        verify(revocationWriter).revokeExecutionGrant(realm, issued.ticket().grantId(), NOW.plusSeconds(600));
    }

    private OAuthServiceExecutionGrantProperties.Binding binding(Duration lifetime, Set<String> required, Set<String> session) {
        return new OAuthServiceExecutionGrantProperties.Binding(realm.getIssuer().toASCIIString(), 101,
                source, verifier, worker, PURPOSE, required, session, lifetime);
    }

    private OAuthServiceExecutionGrantService service(OAuthServiceExecutionGrantProperties.Binding binding) {
        return new OAuthServiceExecutionGrantService(new OAuthServiceExecutionGrantProperties(true, List.of(binding)),
                authority, primary, revocations, cipher, mapper, clock, revocationWriter);
    }

    private StoredServiceExecutionProof proof(Set<String> scopes) {
        return new StoredServiceExecutionProof(realm.getIssuer().toASCIIString(), 101, 2, "worker-service", TARGET.toASCIIString(),
                1, 31, "worker-service", "worker", "ops", "process", "test", "https://api.example/process", "31:7",
                51, "a".repeat(64), "501", "worker-key", scopes, 1, 2, NOW.plusSeconds(86_400));
    }

    private OAuthAuthorityService.ExecutionServiceCurrent current(StoredServiceExecutionProof value, Instant until) {
        return new OAuthAuthorityService.ExecutionServiceCurrent(value.issuer(), value.tenantId(), value.subject(), value.resourceUri(),
                value.sourceResourceUri(), value.scopes(), until);
    }

    private OAuthAuthorityService.Caller caller(OAuthExecutionGrantProperties.Service service, String scope,
            long authorizationId, String tokenId, String digest, Instant issuedAt) {
        var principal = new ServiceIdentityPrincipal(service.clientId(), "101", service.clientId(), tokenId,
                URI.create("https://api.example/idp"), 1, Set.of(scope), service.businessCode(), service.applicationCode(),
                service.environment(), "credential", issuedAt.minusSeconds(1), issuedAt.plusSeconds(300), service.appId(),
                ServiceTokenContext.TENANT);
        return new OAuthAuthorityService.Caller(principal, realm, service.clientPk(), URI.create(service.resourceUri()),
                1L, 2L, authorizationId, digest, NOW.plusSeconds(86_400), "source-key");
    }

    private OAuthServiceExecutionGrantService.IssueRequest request(boolean session, Instant deadline) {
        return new OAuthServiceExecutionGrantService.IssueRequest(PURPOSE, INTENT, "c".repeat(64), session, deadline);
    }

    private static void assertRejected(org.junit.jupiter.api.function.Executable action) {
        var failure = assertThrows(OAuth2AuthenticationException.class, action);
        assertEquals("invalid_grant", failure.getError().getErrorCode());
    }

    @EnableConfigurationProperties(OAuthServiceExecutionGrantProperties.class)
    static class PropertiesConfiguration { }
}
