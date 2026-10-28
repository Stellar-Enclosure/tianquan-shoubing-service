package top.egon.cola.platform.tianquan.shoubing.starter.execution;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller.OAuthExecutionGrantController;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller.filter.OAuthAuthorityAuthenticationFilter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthorityService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthExecutionGrantService;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.contract.execution.ExecutionGrantContract;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest;
import top.egon.cola.platform.tianquan.shoubing.starter.client.ServiceAuthorizationKey;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** Exercises the actual JSON client and MVC/filter contract with a controlled owner backend. */
class ExecutionGrantClientServerContractTest {
    @Test void client_and_authority_exchange_the_same_bound_intent() throws Exception {
        Instant now = Instant.parse("2026-10-29T00:00:00Z");
        URI issuer = URI.create("https://idp.example/tenants/101");
        var scopes = Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE, IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE,
                IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE);
        var principal = new ServiceIdentityPrincipal("service", "101", "service", "123", URI.create("https://api.example/idp"), 1L,
                scopes, "platform", "tianji", "test", "credential", now, now.plusSeconds(300), "agent", ServiceTokenContext.TENANT);
        var realm = TrustedRealmBO.builder().issuer(issuer).realmKey("tenant:101").realmType(RealmTypeEnum.TENANT)
                .storagePartitionId(101L).businessTenantId(101L).trustVersion(0L).build();
        var caller = new OAuthAuthorityService.Caller(principal, realm, 12L, URI.create("https://api.example/tianji"));
        var authority = mock(OAuthAuthorityService.class);
        when(authority.authenticateService(eq("service-proof"), anyString())).thenReturn(caller);
        var grants = mock(OAuthExecutionGrantService.class);
        var mapper = new ObjectMapper().findAndRegisterModules();
        var mvc = MockMvcBuilders.standaloneSetup(new OAuthExecutionGrantController(grants))
                .addFilters(new OAuthAuthorityAuthenticationFilter(authority, mapper)).build();
        String id = "9" + "1".repeat(62);
        var ticket = new ExecutionGrantContract.Ticket(id, "ENC:v1:key:nonce:sealed-fixture");
        var request = new ExecutionGrantContract.IssueRequest("user-proof", "TEST_RUN", "00000000-0000-0000-0000-000000000123",
                "c".repeat(64), true, now.plusSeconds(600));
        var issued = new ExecutionGrantContract.Issued(ticket, now.plusSeconds(300));
        var resolution = new ExecutionGrantContract.Resolution(id, issuer.toString(), 101, "alice", "https://api.example/tianji",
                new ExecutionGrantContract.Source("service", "agent", "platform", "tianji", "test"), request.purpose(),
                request.intentId(), request.bindingSha256(), true, issued.expiresAt(), request.deadlineAt(), Set.of("agent:run"));
        when(grants.issue(caller, request)).thenReturn(issued);
        when(grants.resolve(caller, new ExecutionGrantContract.ResolveRequest(ticket))).thenReturn(resolution);
        var oauth = mock(IdpServiceOAuth2Client.class);
        var context = new IdpServiceTokenRequest("registration", "agent", URI.create("https://api.example/idp"),
                ServiceTokenContext.TENANT, "101", scopes);
        when(oauth.authorizationKey(any())).thenAnswer(inv -> {
            IdpServiceTokenRequest value = inv.getArgument(0);
            return new ServiceAuthorizationKey(issuer.toString(), value.registrationId(), "service", 1, value.appId(),
                    value.audience(), value.context(), value.tenantId(), value.scopes());
        });
        when(oauth.authorize(any())).thenReturn(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "service-proof", now, now.plusSeconds(300)));
        var http = mock(HttpClient.class);
        when(http.followRedirects()).thenReturn(HttpClient.Redirect.NEVER);
        when(http.<byte[]>sendAsync(any(), any())).thenAnswer(inv -> {
            HttpRequest httpRequest = inv.getArgument(0);
            HttpResponse.BodyHandler<byte[]> handler = inv.getArgument(1);
            var actual = mvc.perform(post(httpRequest.uri().getRawPath()).contentType(MediaType.APPLICATION_JSON)
                    .header("Authorization", httpRequest.headers().firstValue("Authorization").orElseThrow())
                    .content(readBody(httpRequest))).andReturn().getResponse();
            @SuppressWarnings("unchecked") HttpResponse<byte[]> response = mock(HttpResponse.class);
            when(response.statusCode()).thenReturn(actual.getStatus());
            String contentType = actual.getContentType();
            when(response.headers()).thenReturn(HttpHeaders.of(contentType == null ? Map.of() : Map.of("Content-Type", List.of(contentType)), (a, b) -> true));
            var info = mock(HttpResponse.ResponseInfo.class); when(info.statusCode()).thenReturn(actual.getStatus());
            var subscriber = handler.apply(info);
            subscriber.onSubscribe(new Flow.Subscription() { public void request(long n) { } public void cancel() { } });
            subscriber.onNext(List.of(ByteBuffer.wrap(actual.getContentAsByteArray()))); subscriber.onComplete();
            return subscriber.getBody().thenApply(bytes -> { when(response.body()).thenReturn(bytes); return response; }).toCompletableFuture();
        });
        var client = new HttpExecutionGrantClient(URI.create("https://idp.example"), issuer, context, oauth, mapper,
                Duration.ofSeconds(1), http, Clock.fixed(now, ZoneOffset.UTC));
        assertEquals(issued, client.issue(request));
        assertEquals(resolution, client.resolve(ticket));
        var revoke = new ExecutionGrantContract.RevokeRequest("user-proof", ticket);
        client.revoke(revoke);
        verify(grants).revoke(caller, revoke);
        verify(authority).authenticateService("service-proof", IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE);
        verify(authority).authenticateService("service-proof", IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE);
        verify(authority).authenticateService("service-proof", IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE);
    }

    private static byte[] readBody(HttpRequest request) {
        var completed = new CompletableFuture<byte[]>(); var output = new ByteArrayOutputStream();
        request.bodyPublisher().orElseThrow().subscribe(new Flow.Subscriber<>() {
            public void onSubscribe(Flow.Subscription subscription) { subscription.request(Long.MAX_VALUE); }
            public void onNext(ByteBuffer bytes) { byte[] value = new byte[bytes.remaining()]; bytes.get(value); output.writeBytes(value); }
            public void onError(Throwable error) { completed.completeExceptionally(error); }
            public void onComplete() { completed.complete(output.toByteArray()); }
        });
        return completed.join();
    }
}
