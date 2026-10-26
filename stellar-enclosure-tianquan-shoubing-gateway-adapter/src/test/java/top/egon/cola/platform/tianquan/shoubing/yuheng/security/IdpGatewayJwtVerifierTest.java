package top.egon.cola.platform.tianquan.shoubing.yuheng.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.match.MockRestRequestMatchers;
import org.springframework.test.web.client.response.MockRestResponseCreators;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.web.client.RestTemplate;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import top.egon.cola.component.yuheng.contract.protocol.AccessZone;
import top.egon.cola.component.yuheng.contract.protocol.GatewayProtocol;
import top.egon.cola.component.yuheng.core.context.GatewayPrincipal;
import top.egon.cola.component.yuheng.core.security.*;
import top.egon.cola.platform.tianquan.shoubing.contract.OAuthSecurityVersionBO;
import top.egon.cola.platform.tianquan.shoubing.contract.state.*;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditEvent;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditFingerprint;
import top.egon.cola.platform.tianquan.shoubing.starter.audit.*;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.observability.IdpSecurityObservationReceiverEnum;
import top.egon.cola.platform.tianquan.shoubing.starter.security.*;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.converter.TokenUsageAuditEventConverter;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClient;

class IdpGatewayJwtVerifierTest {
    private static final Instant NOW = Instant.parse("2026-10-09T00:00:00Z");
    private static final URI ISSUER = URI.create("https://idp.example/tenants/1001");
    private static final URI RESOURCE = URI.create("https://api.example/orders");
    private final LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
    private final IdentityAuthorityClient authority = mock(IdentityAuthorityClient.class);
    private final List<TokenUsageAuditEvent> events = new java.util.concurrent.CopyOnWriteArrayList<>();
    private final AtomicReference<String> authorityThread = new AtomicReference<>();
    private TenantIssuerAuthenticationManagerComponent manager;
    private IdpGatewayJwtVerifier verifier;
    private RSAKey key;
    private MockRestServiceServer jwks;

    @BeforeEach void prepare() throws Exception {
        validator.afterPropertiesSet(); var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        var properties = new IdpStarterProperties(); properties.setResourceUri(RESOURCE);
        var trusted = new IdpStarterProperties.TrustedIssuerSettings();
        trusted.setIssuer(ISSUER.toASCIIString()); trusted.setJwksUri(ISSUER + "/.well-known/jwks.json");
        trusted.setRealmKey("tenant:1001"); trusted.setRealmType("TENANT"); trusted.setTenantId("1001");
        trusted.setStatus("ACTIVE"); trusted.setTrustVersion(1); properties.setTrustedIssuers(Map.of("tenant", trusted));
        manager = spy(new TenantIssuerAuthenticationManagerComponent(new TrustedIssuerRegistry(properties), properties, clock));
        manager.initialize();
        var rest = TenantIssuerAuthenticationManagerComponent.class.getDeclaredField("jwksRestOperations"); rest.setAccessible(true);
        jwks = MockRestServiceServer.bindTo((RestTemplate) rest.get(manager)).build();
        key = new RSAKeyGenerator(2048).keyID("key-1").algorithm(JWSAlgorithm.RS256).generate();
        jwks.expect(ExpectedCount.once(), MockRestRequestMatchers.requestTo(ISSUER + "/.well-known/jwks.json"))
                .andRespond(MockRestResponseCreators.withSuccess(new JWKSet(key.toPublicJWK()).toString(), MediaType.APPLICATION_JSON));
        doAnswer(call -> state(call.getArgument(0))).when(authority).resolve(any());
        doAnswer(call -> {
            TokenUsageAuditEvent event = call.getArgument(0); events.add(event);
            return receipt(event);
        }).when(authority).appendAudit(any());
        var producer = new TokenUsageAuditComponent(issuer -> authority, clock, validator, sample -> { });
        var converter = (TokenUsageAuditEventConverter) Class.forName(TokenUsageAuditEventConverter.class.getName() + "Impl").getConstructor().newInstance();
        var observations = new IdpObservedVerificationComponent(producer, converter,
                new OAuthUsageObservationProperties(true, ISSUER, false, IdpSecurityObservationReceiverEnum.BIZ),
                sample -> { }, clock, validator, RESOURCE);
        var principalConverter = (VerifiedPrincipalConverter) Class.forName(VerifiedPrincipalConverter.class.getName() + "Impl").getConstructor().newInstance();
        verifier = IdpGatewayJwtVerifier.createConfigured(GatewayResourceServerResolverTest.resolver(), clock, manager,
                issuer -> authority, principalConverter, observations);
    }
    @AfterEach void close() { validator.close(); }

    @Test void userAndServiceUseOneSignatureVerificationAndCurrentSqlStateWithExactAudit() throws Exception {
        for (boolean service : List.of(false, true)) {
            String token = token(service, RESOURCE);
            var result = verifier.verify(context(), token);
            assertThat(result.failure()).isEqualTo(AuthenticationFailure.NONE);
            assertThat(result.principal().tenantId()).isEqualTo("1001");
            assertThat(result.scopes()).containsExactlyInAnyOrder("orders:read", "orders:write");
            assertThat(result.proof().resource()).isEqualTo(RESOURCE);
            verify(manager).authenticate(token);
            assertThat(events.getLast().reasonCode()).isEqualTo("TOKEN_USE_VERIFIED");
            assertThat(events.getLast().resource()).isEqualTo(RESOURCE.toASCIIString());
            assertThat(events.getLast().traceId()).isEqualTo("trace");
            assertThat(events.getLast().toString()).doesNotContain(token);
        }
        verify(authority, times(2)).resolve(any()); verify(authority, times(2)).appendAudit(any()); jwks.verify();
    }

    @Test void wrongAudienceAndUnboundRoutesCannotReadAuthorityOrPublishIdentityReferences() throws Exception {
        assertThat(verifier.verify(context(), token(false, URI.create("https://api.example/other"))).failure()).isEqualTo(AuthenticationFailure.INVALID);
        var unknown = new GatewayAuthContext(AccessZone.PUBLIC, GatewayProtocol.HTTP, "operation", "route", "policy",
                "/orders", "GET", Set.of("bearer"), GatewayPrincipal.anonymous(), "127.0.0.1", "trace", "request",
                NOW.plusSeconds(5), "release", Map.of("tianquan-shoubing.resource-uri", "https://unknown.example"));
        assertThat(verifier.verify(unknown, "untrusted-token").failure()).isEqualTo(AuthenticationFailure.INVALID);
        verify(authority, never()).resolve(any());
        assertThat(events).hasSize(2).allSatisfy(event -> {
            assertThat(event.reasonCode()).isEqualTo("AUTHENTICATION_FAILED");
            assertThat(event.subjectRef()).isNull(); assertThat(event.clientRef()).isNull(); assertThat(event.tokenRef()).isNull();
        });
    }

    @Test void sqlAndAuditFailuresBecomeUnavailableOnBoundedWorkerWithoutAnAllowDecision() throws Exception {
        String token = token(true, RESOURCE); var provider = new IdpIdentityAuthenticationProvider(verifier);
        StepVerifier.create(Mono.from(provider.authenticate(context(), new GatewayCredential("bearer", token, Map.of()))))
                .assertNext(decision -> assertThat(decision.decision()).isEqualTo(SecurityDecision.ALLOW)).verifyComplete();
        assertThat(authorityThread.get()).startsWith("boundedElastic-");
        doThrow(new IllegalStateException("controlled SQL unavailable")).when(authority).resolve(any());
        StepVerifier.create(Mono.from(provider.authenticate(context(), new GatewayCredential("bearer", token, Map.of()))))
                .assertNext(decision -> assertThat(decision.decision()).isEqualTo(SecurityDecision.ERROR)).verifyComplete();
        doAnswer(call -> state(call.getArgument(0))).when(authority).resolve(any());
        doReturn(null).when(authority).appendAudit(any());
        StepVerifier.create(Mono.from(provider.authenticate(context(), new GatewayCredential("bearer", token, Map.of()))))
                .assertNext(decision -> assertThat(decision.decision()).isEqualTo(SecurityDecision.ERROR)).verifyComplete();
        verify(authority, times(3)).resolve(any());
    }

    @Test void committedRevocationRejectsNextRequestWithoutUsingThePriorPositiveDecision() throws Exception {
        String token = token(false, RESOURCE);
        assertThat(verifier.verify(context(), token).failure()).isEqualTo(AuthenticationFailure.NONE);
        doReturn(IdentitySecurityStateResponse.denied(IdentityStatePurpose.ACCESS_VALIDATION, "TOKEN_REVOKED"))
                .when(authority).resolve(any());
        assertThat(verifier.verify(context(), token).failure()).isEqualTo(AuthenticationFailure.INVALID);
        verify(authority, times(2)).resolve(any());
        assertThat(events.getLast().subjectRef()).isNull();
    }

    private IdentitySecurityStateResponse state(IdentitySecurityStateRequest request) throws Exception {
        authorityThread.set(Thread.currentThread().getName());
        var claims = SignedJWT.parse(request.getAccessToken()).getJWTClaimsSet(); boolean service = "SERVICE".equals(claims.getStringClaim("principal_type"));
        return IdentitySecurityStateResponse.builder().purpose(IdentityStatePurpose.ACCESS_VALIDATION).eligible(true).reasonCode("ACTIVE")
                .issuer(ISSUER.toASCIIString()).subject(claims.getSubject()).clientId(request.getExpectedClientId())
                .resource(request.getExpectedResource().toASCIIString()).authorizationId("801").authorizationExpiresAt(NOW.plusSeconds(3600).getEpochSecond())
                .securityVersion(new OAuthSecurityVersionBO(1, 2, service ? null : 3L)).build();
    }
    private IdentityAuditReceipt receipt(TokenUsageAuditEvent event) {
        return new IdentityAuditReceipt(UUID.randomUUID().toString(), event.eventId(), TokenUsageAuditFingerprint.of(event),
                event.issuer().toASCIIString(), "gateway-service", event.resource(), "STORED", NOW);
    }
    private String token(boolean service, URI audience) throws Exception {
        Map<String, Object> claims = new java.util.LinkedHashMap<>();
        claims.put("iss", ISSUER.toASCIIString()); claims.put("sub", service ? "orders-service" : "operator");
        claims.put("aud", List.of(audience.toASCIIString())); claims.put("iat", NOW.minusSeconds(1).getEpochSecond());
        claims.put("nbf", NOW.minusSeconds(1).getEpochSecond()); claims.put("exp", NOW.plusSeconds(300).getEpochSecond());
        claims.put("jti", service ? "902" : "901"); claims.put("tenant_id", "1001");
        claims.put("client_id", service ? "orders-service" : "browser-client"); claims.put("principal_type", service ? "SERVICE" : "USER");
        claims.put("scope_context", "TENANT"); claims.put("authorization_id", "801"); claims.put("client_registration_id", "501");
        claims.put("security_version", service ? Map.of("realm", 1L, "client", 2L) : Map.of("realm", 1L, "client", 2L, "subject", 3L));
        claims.put("scope", "orders:read orders:write");
        if (service) {
            claims.put("app_id", "orders"); claims.put("resource_version", 1L); claims.put("credential_id", "501:0");
            claims.put("source_biz", "commerce"); claims.put("source_app", "orders"); claims.put("source_env", "test");
        } else { claims.put("acr", "PASSWORD"); claims.put("auth_time", NOW.minusSeconds(5).getEpochSecond()); }
        var signed = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("key-1").type(new JOSEObjectType("at+jwt")).build(), JWTClaimsSet.parse(claims));
        signed.sign(new RSASSASigner(key)); return signed.serialize();
    }
    private GatewayAuthContext context() {
        return new GatewayAuthContext(AccessZone.PUBLIC, GatewayProtocol.HTTP, "operation", "route", "policy",
                "/orders", "GET", Set.of("bearer"), GatewayPrincipal.anonymous(), "127.0.0.1", "trace", "request",
                NOW.plusSeconds(5), "release", Map.of("tianquan-shoubing.resource-uri", RESOURCE.toASCIIString()));
    }
}
