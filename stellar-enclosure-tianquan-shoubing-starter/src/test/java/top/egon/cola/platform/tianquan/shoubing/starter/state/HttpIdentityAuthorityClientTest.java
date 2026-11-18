package top.egon.cola.platform.tianquan.shoubing.starter.state;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import top.egon.cola.platform.tianquan.shoubing.contract.OAuthSecurityVersionBO;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentitySecurityStateRequest;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentitySecurityStateResponse;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityStatePurpose;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingRegistry;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingVO;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingVO.Operation;
import top.egon.cola.platform.tianquan.shoubing.starter.client.ServiceAuthorizationKey;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HttpIdentityAuthorityClientTest {

    private static final URI ISSUER = URI.create("https://idp.example/tenants/1001");
    private static final URI BASE = URI.create("https://idp.example/prefix");
    private static final URI RESOURCE = URI.create("https://api.example/idp");
    private static final String RESOLVE = "/prefix/internal/v1/identity/security-state:resolve";
    private static final String AUDIT = "/prefix/internal/v1/identity/audit-events";
    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
    private final IdpServiceOAuth2Client oauth = mock(IdpServiceOAuth2Client.class);
    private final IdpTransportBindingRegistry bindings = mock(IdpTransportBindingRegistry.class);
    private final Queue<Reply> replies = new ConcurrentLinkedQueue<>();
    private final List<Captured> requests = new CopyOnWriteArrayList<>();
    private final IdpServiceTokenRequest service = new IdpServiceTokenRequest("authority", "application", RESOURCE,
            ServiceTokenContext.TENANT, "1001", Set.of(IdentityAuthorityScopes.STATE_RESOLVE,
                    IdentityAuthorityScopes.AUDIT_APPEND, IdentityAuthorityScopes.REFRESH_CONTEXT));
    private HttpServer server;
    private HttpIdentityAuthorityClient client;

    @BeforeEach
    void setup() throws Exception {
        when(oauth.authorizationKey(any())).thenAnswer(invocation -> {
            IdpServiceTokenRequest context = invocation.getArgument(0);
            return new ServiceAuthorizationKey(ISSUER.toASCIIString(), context.registrationId(), "controlled-service", 1,
                    context.appId(), context.audience(), context.context(), context.tenantId(), context.scopes());
        });
        when(oauth.authorizeBounded(any(), eq(ISSUER.toASCIIString()), any())).thenReturn(new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, "service-token-sentinel", Instant.now(), Instant.now().plusSeconds(300)));
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            requests.add(new Captured(exchange.getRequestURI().getRawPath(), exchange.getRequestMethod(),
                    exchange.getRequestHeaders().getFirst("Authorization"),
                    new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
            Reply reply = replies.poll();
            if (reply == null) {
                exchange.sendResponseHeaders(500, -1);
            } else {
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                if (reply.status() == 302) {
                    exchange.getResponseHeaders().set("Location", "http://127.0.0.1:" + server.getAddress().getPort() + "/redirected");
                }
                exchange.sendResponseHeaders(reply.status(), reply.body().length);
                exchange.getResponseBody().write(reply.body());
            }
            exchange.close();
        });
        server.start();
        for (var mapping : Map.of(Operation.AUTHORITY_RESOLVE, RESOLVE, Operation.AUTHORITY_AUDIT, AUDIT).entrySet()) {
            when(bindings.hasBindings("authority", mapping.getKey())).thenReturn(true);
            IdpTransportBindingVO binding = mock(IdpTransportBindingVO.class);
            when(binding.transport()).thenReturn(IdpTransportBindingVO.Transport.HTTP);
            when(binding.physicalUri()).thenReturn(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + mapping.getValue()));
            when(bindings.select(ISSUER, URI.create("https://idp.example" + mapping.getValue()), RESOURCE,
                    "authority", mapping.getKey(), "POST")).thenReturn(Optional.of(binding));
        }
        client = new HttpIdentityAuthorityClient(BASE, HttpIdentityAuthorityClient.boundedTransport(Duration.ofSeconds(1)),
                mapper, oauth, service, bindings, Map.of(), Duration.ofSeconds(1));
    }

    @AfterEach
    void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void callsTheBoundHttpOperationsOnlineAndKeepsTheCanonicalServiceIdentity() throws Exception {
        replies.add(json(200, active()));
        replies.add(json(200, active()));
        var event = AuthorityTestFixture.event();
        replies.add(json(200, AuthorityTestFixture.receipt(event)));
        assertThat(client.resolve(request()).isEligible()).isTrue();
        assertThat(client.resolve(request()).isEligible()).isTrue();
        assertThat(client.appendAudit(event).eventId()).isEqualTo(event.eventId());
        assertThat(requests).extracting(Captured::path).containsExactly(RESOLVE, RESOLVE, AUDIT);
        assertThat(requests).allSatisfy(request -> {
            assertThat(request.method()).isEqualTo("POST");
            assertThat(request.authorization()).isEqualTo("Bearer service-token-sentinel");
        });
        verify(oauth, times(3)).authorizeBounded(any(), eq(ISSUER.toASCIIString()), any());
        verify(oauth, never()).authorize(any());
    }

    @Test
    void keepsTransportFailuresDistinctFromVerifiedStateAndDoesNotReplayUnknownWrites() throws Exception {
        replies.add(json(503, Map.of("error", "unavailable")));
        assertThatThrownBy(() -> client.appendAudit(AuthorityTestFixture.event()))
                .isInstanceOf(HttpIdentityAuthorityClient.AuthorityUnavailableException.class);
        assertThat(requests).hasSize(1);
        replies.add(json(302, Map.of()));
        assertThatThrownBy(() -> client.resolve(request()))
                .isInstanceOf(HttpIdentityAuthorityClient.AuthorityUnavailableException.class);
        assertThat(requests).hasSize(2);
        replies.add(json(200, IdentitySecurityStateResponse.denied(IdentityStatePurpose.ACCESS_VALIDATION, "AUTHORIZATION_REVOKED")));
        assertThat(client.resolve(request()).isEligible()).isFalse();
        assertThat(requests).hasSize(3);
    }

    @Test
    void retriesOnlyAnExplicitAuthenticationRejectionAndPreservesTheSameOperation() throws Exception {
        replies.add(json(401, Map.of()));
        replies.add(json(200, active()));
        assertThat(client.resolve(request()).isEligible()).isTrue();
        assertThat(requests).extracting(Captured::path).containsExactly(RESOLVE, RESOLVE);
        verify(oauth).invalidateBounded(any(), eq(ISSUER.toASCIIString()), any());
    }

    @Test
    void rejectsResponseIdentityAndOversizedBodiesWithoutExposingProof() throws Exception {
        for (String field : List.of("issuer", "resource", "clientId")) {
            var response = mapper.valueToTree(active());
            ((com.fasterxml.jackson.databind.node.ObjectNode) response).put(field, "forged-value");
            replies.add(json(200, response));
            assertThatThrownBy(() -> client.resolve(request()))
                    .isInstanceOf(HttpIdentityAuthorityClient.AuthorityUnavailableException.class)
                    .hasMessage("IDENTITY_AUTHORITY_RESPONSE_INVALID");
        }
        replies.add(new Reply(200, new byte[65_537]));
        assertThatThrownBy(() -> client.resolve(request()))
                .isInstanceOf(HttpIdentityAuthorityClient.AuthorityUnavailableException.class);
    }

    @Test
    void failsAnExplicitMissingReferenceBeforeTokenOrNetworkAndKeepsLegacyHttpsOnly() {
        var reference = new IdpTransportBindingProperties.Reference("missing", 1);
        assertThatThrownBy(() -> new HttpIdentityAuthorityClient(BASE,
                HttpIdentityAuthorityClient.boundedTransport(Duration.ofSeconds(1)), mapper, oauth, service,
                IdpTransportBindingRegistry.empty(), Map.of(Operation.AUTHORITY_RESOLVE, reference), Duration.ofSeconds(1)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HttpIdentityAuthorityClient(URI.create("http://idp.example"),
                HttpIdentityAuthorityClient.boundedTransport(Duration.ofSeconds(1)), mapper, oauth, service))
                .isInstanceOf(IllegalArgumentException.class);
        verify(oauth, never()).authorizeBounded(any(), anyString(), any());
        assertThat(requests).isEmpty();
    }

    private Reply json(int status, Object value) throws Exception {
        return new Reply(status, mapper.writeValueAsBytes(value));
    }

    private static IdentitySecurityStateRequest request() {
        return IdentitySecurityStateRequest.builder().purpose(IdentityStatePurpose.ACCESS_VALIDATION)
                .accessToken("user-proof-sentinel").expectedResource(URI.create("https://api.example/orders"))
                .expectedClientId("browser-client").build();
    }

    private static IdentitySecurityStateResponse active() {
        return IdentitySecurityStateResponse.builder().purpose(IdentityStatePurpose.ACCESS_VALIDATION).eligible(true)
                .reasonCode("ACTIVE").issuer(ISSUER.toASCIIString()).resource("https://api.example/orders")
                .clientId("browser-client").subject("alice").authorizationId("authorization-1")
                .authorizationExpiresAt(Instant.now().plusSeconds(300).getEpochSecond())
                .securityVersion(new OAuthSecurityVersionBO(0, 0, 0L)).build();
    }

    private record Captured(String path, String method, String authorization, String body) { }
    private record Reply(int status, byte[] body) { }
}
