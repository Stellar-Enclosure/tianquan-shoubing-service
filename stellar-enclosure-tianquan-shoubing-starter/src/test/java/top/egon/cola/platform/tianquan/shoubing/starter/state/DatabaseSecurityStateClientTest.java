package top.egon.cola.platform.tianquan.shoubing.starter.state;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;
import static top.egon.cola.platform.tianquan.shoubing.starter.state.AuthorityTestFixture.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import top.egon.cola.platform.tianquan.shoubing.contract.OAuthSecurityVersionBO;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.contract.state.*;
import top.egon.cola.platform.tianquan.shoubing.starter.client.*;
import top.egon.cola.platform.tianquan.shoubing.starter.security.OAuthRevocationReader;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TrustedIssuerRegistry;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.VerifiedJwtBO;
import top.egon.cola.platform.tianquan.shoubing.starter.security.impl.DatabaseOAuthRevocationReader;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties;

class DatabaseSecurityStateClientTest {
    private static final URI ISSUER = URI.create("https://idp.example/tenants/1001");
    private static final URI RESOURCE = URI.create("https://api.example/orders");
    private static final URI AUTHORITY = URI.create("https://idp-api.example");
    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
    private final IdpServiceOAuth2Client service = mock(IdpServiceOAuth2Client.class);
    private final IdpServiceTokenRequest context = new IdpServiceTokenRequest("authority", "orders", AUTHORITY,
            ServiceTokenContext.TENANT, "1001", Set.of(IdentityAuthorityScopes.STATE_RESOLVE, IdentityAuthorityScopes.AUDIT_APPEND));
    private MockRestServiceServer server;
    private HttpIdentityAuthorityClient client;

    @BeforeEach void prepare() {
        var builder = RestClient.builder(); server = MockRestServiceServer.bindTo(builder).build();
        client = new HttpIdentityAuthorityClient(AUTHORITY, builder.build(), mapper, service, context);
        when(service.authorizationKey(any())).thenReturn(new ServiceAuthorizationKey(ISSUER.toASCIIString(), "authority",
                "controlled-service", 1, "orders", AUTHORITY, ServiceTokenContext.TENANT, "1001", context.scopes()));
        when(service.authorize(any())).thenReturn(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                "controlled-service-token", Instant.now(), Instant.now().plusSeconds(60)));
    }

    @Test void accessProofIsBodyOnlyAndServiceCredentialUsesFixedAuthorityEndpoint() throws Exception {
        server.expect(requestTo(AUTHORITY + "/internal/v1/identity/security-state:resolve"))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer controlled-service-token"))
                .andExpect(content().json(mapper.writeValueAsString(request())))
                .andRespond(withSuccess(mapper.writeValueAsString(state()), MediaType.APPLICATION_JSON));
        assertThat(client.resolve(request()).getAuthorizationId()).isEqualTo("19");
        server.verify();
        verify(service).authorize(argThat(value -> value.scopes().equals(Set.of(IdentityAuthorityScopes.STATE_RESOLVE))));
    }

    @Test void existingTraceContextPropagatesToTheIdentityAuthority() throws Exception {
        var trace = top.egon.cola.component.common.trace.TraceContext.root();
        server.expect(requestTo(AUTHORITY + "/internal/v1/identity/security-state:resolve"))
                .andExpect(request -> assertThat(request.getHeaders().getFirst("traceparent"))
                        .startsWith("00-" + trace.traceId() + "-"))
                .andRespond(withSuccess(mapper.writeValueAsString(state()), MediaType.APPLICATION_JSON));
        try (var ignored = trace.open()) { assertThat(client.resolve(request()).isEligible()).isTrue(); }
        server.verify();
    }

    @Test void stateIsReadForEveryProofAndWrongTupleOrVersionNeverBecomesValid() {
        var port = mock(IdentityAuthorityClient.class); var resolver = mock(IdentityAuthorityClientResolver.class);
        when(resolver.forResource(ISSUER, RESOURCE)).thenReturn(port); when(port.resolve(any())).thenReturn(state());
        var reader = new DatabaseOAuthRevocationReader(resolver, RESOURCE); var proof = proof();
        assertThat(reader.check(proof).status()).isEqualTo(OAuthRevocationReader.Status.VALID);
        assertThat(reader.check(proof).status()).isEqualTo(OAuthRevocationReader.Status.VALID);
        verify(port, times(2)).resolve(any());
        for (String mismatch : new String[]{"issuer", "subject", "expiry", "version", "authorization", "client", "resource"}) {
            var response = state();
            switch (mismatch) {
                case "issuer" -> response.setIssuer("https://other.example");
                case "subject" -> response.setSubject("other");
                case "expiry" -> response.setAuthorizationExpiresAt(1L);
                case "version" -> response.setSecurityVersion(new OAuthSecurityVersionBO(99, 0, 0L));
                case "authorization" -> response.setAuthorizationId("999");
                case "client" -> response.setClientId("other");
                case "resource" -> response.setResource("https://other.example");
            }
            when(port.resolve(any())).thenReturn(response);
            assertThat(reader.check(proof).status()).isNotEqualTo(OAuthRevocationReader.Status.VALID);
        }
        when(port.resolve(any())).thenThrow(new IllegalStateException("controlled SQL timeout"));
        assertThat(reader.check(proof).status()).isEqualTo(OAuthRevocationReader.Status.UNAVAILABLE);
        doReturn(IdentitySecurityStateResponse.denied(IdentityStatePurpose.ACCESS_VALIDATION, "TOKEN_REVOKED")).when(port).resolve(any());
        assertThat(reader.check(proof).status()).isEqualTo(OAuthRevocationReader.Status.REVOKED);
    }

    @Test void auditReceiptMustMatchAuthenticatedServiceAndExactEvent() throws Exception {
        var good = receipt(event());
        server.expect(requestTo(AUTHORITY + "/internal/v1/identity/audit-events"))
                .andRespond(withSuccess(mapper.writeValueAsString(good), MediaType.APPLICATION_JSON));
        assertThat(client.appendAudit(event())).isEqualTo(good); server.verify();
        server.reset();
        var wrong = new IdentityAuditReceipt(good.receiptId(), good.eventId(), good.eventFingerprint(), good.sourceIssuer(),
                "different-service", good.resource(), "STORED", good.confirmedAt());
        server.expect(anything()).andRespond(withSuccess(mapper.writeValueAsString(wrong), MediaType.APPLICATION_JSON));
        assertThatThrownBy(() -> client.appendAudit(event())).hasMessage("IDENTITY_AUDIT_RECEIPT_INVALID");
    }

    @Test void oneService401MayRenewBut403UnavailableMalformedAndOversizedDoNotRetry() throws Exception {
        server.expect(anything()).andRespond(withStatus(HttpStatus.UNAUTHORIZED));
        server.expect(anything()).andRespond(withSuccess(mapper.writeValueAsString(state()), MediaType.APPLICATION_JSON));
        assertThat(client.resolve(request()).isEligible()).isTrue(); verify(service).invalidate(any()); server.verify();
        for (HttpStatus status : new HttpStatus[]{HttpStatus.FORBIDDEN, HttpStatus.SERVICE_UNAVAILABLE, HttpStatus.FOUND}) {
            server.reset(); server.expect(anything()).andRespond(withStatus(status));
            assertThatThrownBy(() -> client.resolve(request())).hasMessage("IDENTITY_AUTHORITY_HTTP_" + status.value()); server.verify();
        }
        for (String json : new String[]{"{\"purpose\":\"ACCESS_VALIDATION\",\"purpose\":\"REFRESH_CONTEXT\"}",
                mapper.writeValueAsString(state()) + " {}", "{\"unknown\":true}", " ".repeat(65_537)}) {
            server.reset(); server.expect(anything()).andRespond(withSuccess(json, MediaType.APPLICATION_JSON));
            assertThatThrownBy(() -> client.resolve(request())).isInstanceOf(HttpIdentityAuthorityClient.AuthorityUnavailableException.class);
        }
    }

    @Test void repeatedService401IsBoundedAndNeverTreatsBodyAsCredential() {
        server.expect(anything()).andRespond(withStatus(HttpStatus.UNAUTHORIZED));
        server.expect(anything()).andRespond(withStatus(HttpStatus.UNAUTHORIZED));
        assertThatThrownBy(() -> client.resolve(request())).hasMessage("IDENTITY_AUTHORITY_SERVICE_AUTHENTICATION_REJECTED");
        verify(service, times(2)).authorize(any()); server.verify();
    }

    @Test void destinationsAndTimeoutsAreBoundedBeforeRequests() {
        assertThatThrownBy(() -> HttpIdentityAuthorityClient.boundedTransport(Duration.ofSeconds(6))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HttpIdentityAuthorityClient(URI.create("http://untrusted.example"), RestClient.create(), mapper, service, context))
                .isInstanceOf(IllegalArgumentException.class);
        verifyNoInteractions(service);
    }

    @Test void configuredBindingsMatchStringIssuerIdentityAndRequireEveryActiveIssuer() {
        var starter = new IdpStarterProperties(); starter.setResourceUri(RESOURCE); starter.getServiceClient().setAppId("orders");
        var trusted = new IdpStarterProperties.TrustedIssuerSettings(); trusted.setIssuer(ISSUER.toASCIIString());
        trusted.setJwksUri(ISSUER + "/.well-known/jwks.json"); trusted.setRealmKey("tenant:1001");
        trusted.setRealmType("TENANT"); trusted.setTenantId("1001"); trusted.setStatus("ACTIVE"); trusted.setTrustVersion(1);
        starter.setTrustedIssuers(Map.of("tenant", trusted));
        var settings = new IdentityAuthorityProperties(); settings.setBaseUri(AUTHORITY);
        var binding = new IdentityAuthorityProperties.Binding(); binding.setIssuer(ISSUER); binding.setRegistrationId("authority");
        binding.setAudience(AUTHORITY); binding.setContext(ServiceTokenContext.TENANT); binding.setTenantId("1001");
        settings.setBindings(Map.of("tenant", binding));
        var resolver = new ConfiguredIdentityAuthorityClients(settings, starter, new TrustedIssuerRegistry(starter), service, mapper);
        assertThat(resolver.forResource(ISSUER, RESOURCE)).isInstanceOf(HttpIdentityAuthorityClient.class);
        assertThatThrownBy(() -> resolver.forIssuer(URI.create("https://other.example"))).hasMessage("IDENTITY_AUTHORITY_RESOURCE_UNBOUND");
        assertThatThrownBy(() -> resolver.forResource(ISSUER, URI.create("https://api.example/unbound")))
                .hasMessage("IDENTITY_AUTHORITY_RESOURCE_UNBOUND");
        var other = new IdentityAuthorityProperties.Binding(); other.setIssuer(ISSUER); other.setRegistrationId("authority");
        other.setAudience(AUTHORITY); other.setContext(ServiceTokenContext.TENANT); other.setTenantId("1001");
        other.setSourceResource(URI.create("https://api.example/second")); settings.setBindings(Map.of("first", binding, "second", other));
        var multiple = new ConfiguredIdentityAuthorityClients(settings, starter, new TrustedIssuerRegistry(starter), service, mapper);
        assertThat(multiple.forResource(ISSUER, other.getSourceResource())).isNotSameAs(multiple.forIssuer(ISSUER));
        binding.setTenantId("1002");
        assertThatThrownBy(() -> new ConfiguredIdentityAuthorityClients(settings, starter, new TrustedIssuerRegistry(starter), service, mapper))
                .hasMessage("IDENTITY_AUTHORITY_CONTEXT_INVALID");
        verify(service, never()).authorize(any());
    }

    private IdentitySecurityStateRequest request() {
        return IdentitySecurityStateRequest.builder().purpose(IdentityStatePurpose.ACCESS_VALIDATION)
                .accessToken("controlled-user-proof").expectedResource(RESOURCE).expectedClientId("browser").build();
    }
    private IdentitySecurityStateResponse state() {
        return IdentitySecurityStateResponse.builder().purpose(IdentityStatePurpose.ACCESS_VALIDATION).eligible(true).reasonCode("ACTIVE")
                .issuer(ISSUER.toASCIIString()).resource(RESOURCE.toASCIIString()).clientId("browser").subject("42")
                .authorizationId("19").authorizationExpiresAt(event().occurredAt().plusSeconds(3600).getEpochSecond())
                .securityVersion(new OAuthSecurityVersionBO(0, 0, 0L)).build();
    }
    private VerifiedJwtBO proof() {
        var proof = mock(VerifiedJwtBO.class);
        when(proof.getJwt()).thenReturn(Jwt.withTokenValue("controlled-user-proof").header("alg", "RS256").claim("client_id", "browser").build());
        when(proof.getTrustedIssuer()).thenReturn(new TrustedIssuerRegistry.TrustedIssuerVO(ISSUER, URI.create(ISSUER + "/jwks"),
                "tenant:1001", TrustedIssuerRegistry.RealmType.TENANT, "1001", TrustedIssuerRegistry.Status.ACTIVE, 1));
        when(proof.getSubject()).thenReturn("42"); when(proof.getAuthorizationId()).thenReturn("19");
        when(proof.getExpiresAt()).thenReturn(event().occurredAt().plusSeconds(300));
        when(proof.getSecurityVersion()).thenReturn(new OAuthSecurityVersionBO(0, 0, 0L));
        return proof;
    }
}
