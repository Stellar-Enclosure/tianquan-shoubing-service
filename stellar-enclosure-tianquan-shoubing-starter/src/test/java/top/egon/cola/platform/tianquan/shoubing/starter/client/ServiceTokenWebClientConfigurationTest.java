package top.egon.cola.platform.tianquan.shoubing.starter.client;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.reactive.JdkClientHttpConnector;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ServiceTokenWebClientConfigurationTest {

    private static final URI ISSUER = URI.create("https://identity.example/t/1001");
    private static final URI RESOURCE = URI.create("https://api.example/orders-resource");
    private static final URI ENDPOINT = URI.create("https://api.example/orders");
    private static final URI PHYSICAL = URI.create("http://orders-api.apps-prod.svc.cluster.local:8080/orders");
    private static final String REGISTRATION = "orders-client";

    @Test
    void mapsTheExactCanonicalIdentityToOneFixedPhysicalRequest() {
        IdpServiceTokenRequest request = tokenRequest(RESOURCE, "1001");
        IdpServiceOAuth2Client tokens = tokens(request);
        AtomicReference<ClientRequest> sent = new AtomicReference<>();

        ClientResponse response = filter(tokens, HttpMethod.GET).filter(call(HttpMethod.GET, ENDPOINT, request), outbound -> {
            sent.set(outbound);
            return Mono.just(ClientResponse.create(HttpStatus.OK).build());
        }).block(Duration.ofSeconds(4));

        assertThat(response.statusCode()).isEqualTo(HttpStatus.OK);
        assertThat(sent.get().url()).isEqualTo(PHYSICAL);
        assertThat(sent.get().method()).isEqualTo(HttpMethod.GET);
        assertThat(sent.get().headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer first-token");
        assertThat(sent.get().headers().containsHeader(HttpHeaders.COOKIE)).isFalse();
        assertThat(sent.get().cookies()).isEmpty();
        assertThat(request.audience()).isEqualTo(RESOURCE);
        verify(tokens).authorize(request);
    }

    @Test
    void optedInWrongPathMethodResourceOrPhysicalUriFailsBeforeTokenAcquisitionAndExchange() {
        IdpServiceTokenRequest request = tokenRequest(RESOURCE, "1001");
        IdpServiceOAuth2Client tokens = tokens(request);
        ExchangeFilterFunction filter = filter(tokens, HttpMethod.GET);
        AtomicInteger exchanges = new AtomicInteger();
        for (ClientRequest candidate : List.of(
                call(HttpMethod.GET, URI.create("https://api.example/orders/other"), request),
                call(HttpMethod.POST, ENDPOINT, request),
                call(HttpMethod.GET, ENDPOINT, tokenRequest(URI.create("https://api.example/other-resource"), "1001")),
                call(HttpMethod.GET, PHYSICAL, request))) {
            assertThatThrownBy(() -> filter.filter(candidate, outbound -> {
                exchanges.incrementAndGet();
                return Mono.just(ClientResponse.create(HttpStatus.OK).build());
            }).block(Duration.ofSeconds(4))).isInstanceOf(IllegalArgumentException.class);
        }
        assertThat(exchanges).hasValue(0);
        verify(tokens, never()).authorize(any());
    }

    @Test
    void mismatchedTrustedAuthorizationIdentityCannotSendAnotherTenantsBearer() {
        IdpServiceTokenRequest request = tokenRequest(RESOURCE, "1001");
        IdpServiceOAuth2Client tokens = tokens(request);
        when(tokens.authorizationKey(request)).thenReturn(ServiceAuthorizationKey.from(
                tokenRequest(RESOURCE, "1002"), ISSUER.toString(), "orders-service", 1));
        AtomicInteger exchanges = new AtomicInteger();

        assertThatThrownBy(() -> filter(tokens, HttpMethod.GET).filter(call(HttpMethod.GET, ENDPOINT, request), outbound -> {
            exchanges.incrementAndGet();
            return Mono.just(ClientResponse.create(HttpStatus.OK).build());
        }).block(Duration.ofSeconds(4))).isInstanceOf(IllegalArgumentException.class);

        assertThat(exchanges).hasValue(0);
        verify(tokens, never()).authorize(any());
    }

    @Test
    void credentialAndTargetOverrideHeadersAndCookiesAreRejectedBeforeAuthorization() {
        IdpServiceTokenRequest request = tokenRequest(RESOURCE, "1001");
        IdpServiceOAuth2Client tokens = tokens(request);
        ExchangeFilterFunction filter = filter(tokens, HttpMethod.GET);
        AtomicInteger exchanges = new AtomicInteger();
        for (String header : List.of(HttpHeaders.AUTHORIZATION, "Proxy-Authorization", HttpHeaders.HOST,
                HttpHeaders.COOKIE, "Forwarded", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port",
                "X-Original-URL", "X-Rewrite-URL", "X-Envoy-Original-Dst-Host", "X-Envoy-Original-Path")) {
            ClientRequest candidate = ClientRequest.from(call(HttpMethod.GET, ENDPOINT, request))
                    .header(header, "untrusted-value").build();
            assertThatThrownBy(() -> filter.filter(candidate, outbound -> {
                exchanges.incrementAndGet();
                return Mono.just(ClientResponse.create(HttpStatus.OK).build());
            }).block(Duration.ofSeconds(4))).isInstanceOf(IllegalArgumentException.class);
        }
        ClientRequest cookie = ClientRequest.from(call(HttpMethod.GET, ENDPOINT, request))
                .cookie("browser-session", "untrusted-cookie").build();
        assertThatThrownBy(() -> filter.filter(cookie, outbound -> {
            exchanges.incrementAndGet();
            return Mono.just(ClientResponse.create(HttpStatus.OK).build());
        }).block(Duration.ofSeconds(4))).isInstanceOf(IllegalArgumentException.class);
        ClientRequest customizer = ClientRequest.from(call(HttpMethod.GET, ENDPOINT, request))
                .httpRequest(nativeRequest -> nativeRequest.getHeaders().setBearerAuth("late-untrusted-token"))
                .build();
        assertThatThrownBy(() -> filter.filter(customizer, outbound -> {
            exchanges.incrementAndGet();
            return Mono.just(ClientResponse.create(HttpStatus.OK).build());
        }).block(Duration.ofSeconds(4))).isInstanceOf(IllegalArgumentException.class);
        assertThat(exchanges).hasValue(0);
        verify(tokens, never()).authorize(any());
    }

    @Test
    void get401CanReauthorizeOnlyOnceAndBothAttemptsKeepTheExactPhysicalBinding() {
        IdpServiceTokenRequest request = tokenRequest(RESOURCE, "1001");
        IdpServiceOAuth2Client tokens = tokens(request);
        when(tokens.authorize(request)).thenReturn(token("first-token"), token("second-token"));
        List<ClientRequest> attempts = new CopyOnWriteArrayList<>();

        ClientResponse response = filter(tokens, HttpMethod.GET).filter(call(HttpMethod.GET, ENDPOINT, request), outbound -> {
            attempts.add(outbound);
            return Mono.just(ClientResponse.create(HttpStatus.UNAUTHORIZED).build());
        }).block(Duration.ofSeconds(4));

        assertThat(response.statusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(attempts).hasSize(2).allSatisfy(attempt -> assertThat(attempt.url()).isEqualTo(PHYSICAL));
        assertThat(attempts).extracting(attempt -> attempt.headers().getFirst(HttpHeaders.AUTHORIZATION))
                .containsExactly("Bearer first-token", "Bearer second-token");
        verify(tokens, times(2)).authorize(request);
        verify(tokens, times(2)).invalidate(request);
    }

    @Test
    void post401IsNeverReplayedAndForbiddenOrRedirectResponsesDoNotTriggerReauthorization() {
        for (HttpStatus status : List.of(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN, HttpStatus.FOUND)) {
            IdpServiceTokenRequest request = tokenRequest(RESOURCE, "1001");
            IdpServiceOAuth2Client tokens = tokens(request);
            AtomicInteger exchanges = new AtomicInteger();
            HttpMethod method = status == HttpStatus.UNAUTHORIZED ? HttpMethod.POST : HttpMethod.GET;
            ClientResponse response = filter(tokens, method).filter(call(method, ENDPOINT, request), outbound -> {
                exchanges.incrementAndGet();
                return Mono.just(ClientResponse.create(status).header(HttpHeaders.LOCATION, "https://other.example/steal").build());
            }).block(Duration.ofSeconds(4));

            assertThat(response.statusCode()).isEqualTo(status);
            assertThat(exchanges).hasValue(1);
            verify(tokens).authorize(request);
            if (status == HttpStatus.UNAUTHORIZED) {
                verify(tokens).invalidate(request);
            } else {
                verify(tokens, never()).invalidate(any());
            }
        }
    }

    @Test
    void namedClientOwnsNoRedirectTransportAndIgnoresIncomingTransportAndRetryFilters() throws Exception {
        HttpServer target = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        HttpServer other = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicInteger targetHits = new AtomicInteger();
        AtomicInteger otherHits = new AtomicInteger();
        AtomicInteger inheritedFilterHits = new AtomicInteger();
        AtomicInteger inheritedExchangeHits = new AtomicInteger();
        List<String> cookies = new CopyOnWriteArrayList<>();
        AtomicReference<String> targetBearer = new AtomicReference<>();
        other.createContext("/steal", exchange -> {
            otherHits.incrementAndGet();
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        target.createContext("/orders", exchange -> {
            targetHits.incrementAndGet();
            cookies.add(String.valueOf(exchange.getRequestHeaders().getFirst(HttpHeaders.COOKIE)));
            targetBearer.set(exchange.getRequestHeaders().getFirst(HttpHeaders.AUTHORIZATION));
            exchange.getResponseHeaders().set(HttpHeaders.SET_COOKIE, "session=must-not-be-reused; Path=/");
            exchange.getResponseHeaders().set(HttpHeaders.LOCATION,
                    "http://127.0.0.1:" + other.getAddress().getPort() + "/steal");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        target.start();
        other.start();
        ServiceTokenWebClientConfiguration configuration = new ServiceTokenWebClientConfiguration();
        try {
            URI origin = URI.create("http://127.0.0.1:" + target.getAddress().getPort());
            IdpServiceTokenRequest request = tokenRequest(origin.resolve("/orders-resource"), "1001");
            IdpServiceOAuth2Client tokens = tokens(request);
            WebClient.Builder inherited = WebClient.builder()
                    .clientConnector(new JdkClientHttpConnector(HttpClient.newBuilder()
                            .followRedirects(HttpClient.Redirect.ALWAYS).build()))
                    .filter((outbound, next) -> {
                        inheritedFilterHits.incrementAndGet();
                        return next.exchange(outbound).retry(3);
                    })
                    .exchangeFunction(outbound -> {
                        inheritedExchangeHits.incrementAndGet();
                        return Mono.just(ClientResponse.create(HttpStatus.OK).build());
                    });
            WebClient client = configuration.serviceTokenWebClient(inherited, tokens);
            for (int invocation = 0; invocation < 2; invocation++) {
                Integer status = client.get().uri(origin.resolve("/orders"))
                        .attribute(ServiceTokenWebClientConfiguration.SERVICE_TOKEN_REQUEST_ATTRIBUTE, request)
                        .exchangeToMono(response -> Mono.just(response.statusCode().value())).block(Duration.ofSeconds(4));
                assertThat(status).isEqualTo(302);
            }
            assertThat(targetHits).hasValue(2);
            assertThat(otherHits).hasValue(0);
            assertThat(inheritedFilterHits).hasValue(0);
            assertThat(inheritedExchangeHits).hasValue(0);
            assertThat(targetBearer).hasValue("Bearer first-token");
            assertThat(cookies).containsExactly("null", "null");
        } finally {
            configuration.destroy();
            target.stop(0);
            other.stop(0);
        }
    }

    private static ExchangeFilterFunction filter(IdpServiceOAuth2Client tokens, HttpMethod method) {
        IdpTransportBindingVO binding = new IdpTransportBindingVO("orders-http", 1, ISSUER, ENDPOINT, RESOURCE,
                REGISTRATION, IdpTransportBindingVO.Operation.RESOURCE, method.name(), "/orders",
                "apps-prod", "orders-api", 8080, IdpTransportBindingVO.Transport.HTTP);
        return new ServiceTokenWebClientConfiguration().serviceTokenFilter(tokens,
                new IdpTransportBindingRegistry(List.of(binding)));
    }

    private static ClientRequest call(HttpMethod method, URI endpoint, IdpServiceTokenRequest request) {
        return ClientRequest.create(method, endpoint)
                .attribute(ServiceTokenWebClientConfiguration.SERVICE_TOKEN_REQUEST_ATTRIBUTE, request).build();
    }

    private static IdpServiceTokenRequest tokenRequest(URI resource, String tenant) {
        return new IdpServiceTokenRequest(REGISTRATION, "orders-app", resource, ServiceTokenContext.TENANT,
                tenant, Set.of("orders:read"));
    }

    private static IdpServiceOAuth2Client tokens(IdpServiceTokenRequest request) {
        IdpServiceOAuth2Client tokens = mock(IdpServiceOAuth2Client.class);
        when(tokens.authorizationKey(any())).thenAnswer(invocation -> ServiceAuthorizationKey.from(
                invocation.getArgument(0), ISSUER.toString(), "orders-service", 1));
        when(tokens.authorize(request)).thenReturn(token("first-token"));
        return tokens;
    }

    private static OAuth2AccessToken token(String value) {
        return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, value,
                Instant.parse("2026-11-18T00:00:00Z"), Instant.parse("2026-11-18T01:00:00Z"));
    }
}
