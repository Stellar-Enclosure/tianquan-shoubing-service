package top.egon.cola.platform.tianquan.shoubing.starter.execution;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.contract.execution.ExecutionGrantContract;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest;
import top.egon.cola.platform.tianquan.shoubing.starter.client.ServiceAuthorizationKey;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class HttpExecutionGrantClientTest {
    private static final Instant NOW = Instant.parse("2026-10-29T00:00:00Z");
    private static final URI ISSUER = URI.create("https://idp.example/tenants/101");
    private static final URI BASE = URI.create("https://idp.example/prefix");
    private static final String ID = "9" + "1".repeat(62);
    private static final String SECRET = "ENC:v1:key:nonce:ciphertext-sentinel";
    private static final String USER = "user-token-sentinel";
    private static final String INTENT = "00000000-0000-0000-0000-000000000123";
    private final ExecutionGrantContract.Ticket ticket = new ExecutionGrantContract.Ticket(ID, SECRET);
    private final ExecutionGrantContract.IssueRequest issue = new ExecutionGrantContract.IssueRequest(USER, "TEST_RUN", INTENT,
            "c".repeat(64), true, NOW.plusSeconds(600));
    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
    private final IdpServiceOAuth2Client oauth = mock(IdpServiceOAuth2Client.class);
    private final HttpClient http = mock(HttpClient.class);
    private final Queue<Reply> replies = new ArrayDeque<>();
    private final List<Captured> requests = new ArrayList<>();
    private final IdpServiceTokenRequest service = new IdpServiceTokenRequest("registration", "app", URI.create("https://api.example/idp"),
            ServiceTokenContext.TENANT, "101", Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE,
                    IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE, IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE));
    private HttpExecutionGrantClient client;

    @BeforeEach void setup() {
        when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        when(oauth.authorizationKey(any())).thenAnswer(invocation -> {
            IdpServiceTokenRequest request = invocation.getArgument(0);
            return new ServiceAuthorizationKey(ISSUER.toASCIIString(), request.registrationId(), "client", 1,
                    request.appId(), request.audience(), request.context(), request.tenantId(), request.scopes());
        });
        when(oauth.authorizeBounded(any(), anyString(), any())).thenReturn(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                "service-token-sentinel", NOW, NOW.plusSeconds(300)));
        when(http.<byte[]>sendAsync(any(), any())).thenAnswer(invocation -> {
            HttpRequest request = invocation.getArgument(0);
            HttpResponse.BodyHandler<byte[]> handler = invocation.getArgument(1);
            requests.add(new Captured(request, readBody(request)));
            Reply reply = replies.remove();
            var response = response(request, reply.status(), reply.contentType());
            var info = mock(HttpResponse.ResponseInfo.class);
            when(info.statusCode()).thenReturn(reply.status());
            var subscriber = handler.apply(info);
            subscriber.onSubscribe(new Flow.Subscription() { public void request(long n) { } public void cancel() { } });
            if (reply.body().length != 0) subscriber.onNext(List.of(ByteBuffer.wrap(reply.body())));
            subscriber.onComplete();
            return subscriber.getBody().thenApply(bytes -> { when(response.body()).thenReturn(bytes); return response; }).toCompletableFuture();
        });
        client = create(service, ISSUER, http, Duration.ofSeconds(1));
    }

    @Test void sends_least_privilege_requests_and_checks_returned_intent_identity() throws Exception {
        var issued = new ExecutionGrantContract.Issued(ticket, NOW.plusSeconds(300));
        var resolution = resolution(ISSUER.toASCIIString(), 101, ID, NOW.plusSeconds(300));
        add(200, mapper.writeValueAsBytes(issued)); add(200, mapper.writeValueAsBytes(resolution)); add(204, new byte[0]);
        assertEquals(issued, client.issue(issue));
        assertEquals(resolution, client.resolve(ticket));
        client.revoke(new ExecutionGrantContract.RevokeRequest(USER, ticket));
        assertEquals(3, requests.size());
        assertEquals("https://idp.example/prefix/internal/v1/identity/execution-grants:issue", requests.get(0).request().uri().toString());
        assertEquals("https://idp.example/prefix/internal/v1/identity/execution-grants:resolve", requests.get(1).request().uri().toString());
        assertEquals("https://idp.example/prefix/internal/v1/identity/execution-grants:revoke", requests.get(2).request().uri().toString());
        assertEquals(USER, mapper.readTree(requests.get(0).body()).get("userToken").asText());
        assertEquals(SECRET, mapper.readTree(requests.get(1).body()).get("ticket").get("ciphertext").asText());
        assertEquals("Bearer service-token-sentinel", requests.getFirst().request().headers().firstValue("Authorization").orElseThrow());
        var captured = org.mockito.ArgumentCaptor.forClass(IdpServiceTokenRequest.class);
        verify(oauth, times(3)).authorizeBounded(captured.capture(), eq(ISSUER.toString()), any());
        assertEquals(List.of(Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE),
                Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE), Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE)),
                captured.getAllValues().stream().map(IdpServiceTokenRequest::scopes).toList());
    }

    @Test void rejects_mismatched_issuer_tenant_grant_or_expiry_from_authority() throws Exception {
        for (var response : List.of(resolution("https://other.example/tenant", 101, ID, NOW.plusSeconds(60)),
                resolution(ISSUER.toString(), 102, ID, NOW.plusSeconds(60)),
                resolution(ISSUER.toString(), 101, "9" + "2".repeat(62), NOW.plusSeconds(60)),
                resolution(ISSUER.toString(), 101, ID, NOW),
                resolution(ISSUER.toString(), 101, ID, NOW.plusSeconds(601)))) {
            add(200, mapper.writeValueAsBytes(response));
            assertThrows(HttpExecutionGrantClient.ExecutionGrantUnavailableException.class, () -> client.resolve(ticket));
        }
        add(200, mapper.writeValueAsBytes(new ExecutionGrantContract.Issued(ticket, NOW.plusSeconds(601))));
        assertThrows(HttpExecutionGrantClient.ExecutionGrantUnavailableException.class, () -> client.issue(issue));
    }

    @Test void denies_only_explicit_authority_denial_and_never_retries_a_write() {
        add(403, "{\"error\":\"access_denied\"}".getBytes(StandardCharsets.UTF_8));
        assertThrows(HttpExecutionGrantClient.ExecutionGrantDeniedException.class, () -> client.issue(issue));
        add(403, "{\"error\":\"insufficient_scope\"}".getBytes(StandardCharsets.UTF_8));
        assertThrows(HttpExecutionGrantClient.ExecutionGrantUnavailableException.class, () -> client.issue(issue));
        add(401, "{}".getBytes(StandardCharsets.UTF_8));
        assertThrows(HttpExecutionGrantClient.ExecutionGrantUnavailableException.class, () -> client.issue(issue));
        verify(oauth, times(1)).invalidateBounded(argThat(request -> request.scopes().equals(Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE))), eq(ISSUER.toString()), any());
        add(302, new byte[0]);
        assertThrows(HttpExecutionGrantClient.ExecutionGrantUnavailableException.class, () -> client.issue(issue));
        assertEquals(4, requests.size());
    }

    @Test void bounds_and_strictly_parses_responses_without_leaking_credentials() throws Exception {
        add(200, new byte[ExecutionGrantContract.MAX_RESPONSE_BYTES + 1]);
        assertThrows(HttpExecutionGrantClient.ExecutionGrantUnavailableException.class, () -> client.resolve(ticket));
        String valid = mapper.writeValueAsString(resolution(ISSUER.toString(), 101, ID, NOW.plusSeconds(60)));
        for (String bad : List.of(valid + "{}", valid.replace("\"grantId\":", "\"grantId\":\"" + ID + "\",\"grantId\":"),
                "{\"error\":\"" + USER + SECRET + "\"}")) {
            add(200, bad.getBytes(StandardCharsets.UTF_8));
            var failure = assertThrows(HttpExecutionGrantClient.ExecutionGrantUnavailableException.class, () -> client.resolve(ticket));
            assertFalse(failure.toString().contains(USER)); assertFalse(failure.toString().contains(SECRET)); assertNull(failure.getCause());
        }
        replies.add(new Reply(200, mapper.writeValueAsBytes(resolution(ISSUER.toString(), 101, ID, NOW.plusSeconds(60))), "text/plain"));
        assertThrows(HttpExecutionGrantClient.ExecutionGrantUnavailableException.class, () -> client.resolve(ticket));
    }

    @Test void timeout_cancels_the_inflight_exchange_and_preserves_unknown_outcome() {
        var pending = new CompletableFuture<HttpResponse<byte[]>>();
        doReturn(pending).when(http).<byte[]>sendAsync(any(), any());
        var shortClient = create(service, ISSUER, http, Duration.ofMillis(40));
        assertThrows(HttpExecutionGrantClient.ExecutionGrantUnavailableException.class, () -> shortClient.issue(issue));
        assertTrue(pending.isCancelled()); verify(http, times(1)).sendAsync(any(), any());
    }

    @Test void token_acquisition_and_http_share_one_deadline() throws Exception {
        var token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "service-token-sentinel", NOW, NOW.plusSeconds(300));
        when(oauth.authorizeBounded(any(), anyString(), any())).thenAnswer(inv -> { Thread.sleep(150); return token; });
        add(200, mapper.writeValueAsBytes(new ExecutionGrantContract.Issued(ticket, NOW.plusSeconds(300))));
        var limited = create(service, ISSUER, http, Duration.ofSeconds(2));
        limited.issue(issue);
        assertTrue(requests.getFirst().request().timeout().orElseThrow().compareTo(Duration.ofMillis(1900)) < 0);
    }

    @Test void configuration_and_service_failures_fail_closed_without_secret_details() {
        assertThrows(IllegalArgumentException.class, () -> new HttpExecutionGrantClient(URI.create("http://idp.example"), ISSUER,
                service, oauth, mapper, Duration.ofSeconds(1), http, Clock.fixed(NOW, ZoneOffset.UTC)));
        assertThrows(HttpExecutionGrantClient.ExecutionGrantUnavailableException.class,
                () -> create(service, URI.create("https://other.example/tenant"), http, Duration.ofSeconds(1)));
        when(http.followRedirects()).thenReturn(HttpClient.Redirect.ALWAYS);
        assertThrows(IllegalArgumentException.class, () -> create(service, ISSUER, http, Duration.ofSeconds(1)));
        when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        var restricted = new IdpServiceTokenRequest(service.registrationId(), service.appId(), service.audience(), service.context(),
                service.tenantId(), Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE));
        var restrictedClient = create(restricted, ISSUER, http, Duration.ofSeconds(1));
        assertThrows(HttpExecutionGrantClient.ExecutionGrantUnavailableException.class, () -> restrictedClient.issue(issue));
        when(oauth.authorizeBounded(any(), anyString(), any())).thenThrow(new IllegalStateException(USER + SECRET));
        var failure = assertThrows(HttpExecutionGrantClient.ExecutionGrantUnavailableException.class, () -> client.issue(issue));
        assertFalse(failure.toString().contains(USER)); assertFalse(failure.toString().contains(SECRET)); assertNull(failure.getCause());
    }

    @Test void serializer_failures_cannot_expose_request_contents() {
        var module = new com.fasterxml.jackson.databind.module.SimpleModule();
        module.addSerializer(ExecutionGrantContract.IssueRequest.class, new com.fasterxml.jackson.databind.JsonSerializer<>() {
            @Override public void serialize(ExecutionGrantContract.IssueRequest value, com.fasterxml.jackson.core.JsonGenerator generator,
                                            com.fasterxml.jackson.databind.SerializerProvider provider) {
                throw new IllegalStateException(USER + SECRET);
            }
        });
        var unsafeMapper = new ObjectMapper().findAndRegisterModules().registerModule(module);
        var guarded = new HttpExecutionGrantClient(BASE, ISSUER, service, oauth, unsafeMapper, Duration.ofSeconds(1), http,
                Clock.fixed(NOW, ZoneOffset.UTC));
        var failure = assertThrows(HttpExecutionGrantClient.ExecutionGrantUnavailableException.class, () -> guarded.issue(issue));
        assertFalse(failure.toString().contains(USER)); assertFalse(failure.toString().contains(SECRET)); assertNull(failure.getCause());
        verify(http, never()).sendAsync(any(), any());
    }

    private HttpExecutionGrantClient create(IdpServiceTokenRequest context, URI issuer, HttpClient transport, Duration timeout) {
        return new HttpExecutionGrantClient(BASE, issuer, context, oauth, mapper, timeout, transport, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private void add(int status, byte[] body) { replies.add(new Reply(status, body, "application/json")); }

    private ExecutionGrantContract.Resolution resolution(String issuer, long tenant, String id, Instant expiry) {
        return new ExecutionGrantContract.Resolution(id, issuer, tenant, "alice", "https://api.example/tianji",
                new ExecutionGrantContract.Source("service", "agent", "platform", "tianji", "test"), issue.purpose(),
                INTENT, issue.bindingSha256(), true, expiry, issue.deadlineAt(), Set.of("agent:run"));
    }

    @SuppressWarnings("unchecked") private static HttpResponse<byte[]> response(HttpRequest request, int status, String contentType) {
        HttpResponse<byte[]> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(status); when(response.request()).thenReturn(request);
        when(response.headers()).thenReturn(HttpHeaders.of(Map.of("Content-Type", List.of(contentType)), (a, b) -> true));
        return response;
    }

    private static String readBody(HttpRequest request) {
        var result = new CompletableFuture<String>(); var output = new ByteArrayOutputStream();
        request.bodyPublisher().orElseThrow().subscribe(new Flow.Subscriber<>() {
            public void onSubscribe(Flow.Subscription subscription) { subscription.request(Long.MAX_VALUE); }
            public void onNext(ByteBuffer item) { byte[] bytes = new byte[item.remaining()]; item.get(bytes); output.writeBytes(bytes); }
            public void onError(Throwable error) { result.completeExceptionally(error); }
            public void onComplete() { result.complete(output.toString(StandardCharsets.UTF_8)); }
        });
        return result.join();
    }

    private record Reply(int status, byte[] body, String contentType) { }
    private record Captured(HttpRequest request, String body) { }
}
