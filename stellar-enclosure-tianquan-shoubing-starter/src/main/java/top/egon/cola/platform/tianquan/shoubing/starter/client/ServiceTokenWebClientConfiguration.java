package top.egon.cola.platform.tianquan.shoubing.starter.client;

import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.webclient.autoconfigure.WebClientAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.reactive.JdkClientHttpConnector;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterAutoConfiguration;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest.IdpServiceTokenRequestException;

/** Adds a request-bound SERVICE Bearer token to one named WebClient. */
@AutoConfiguration
@AutoConfigureAfter({IdpStarterAutoConfiguration.class, WebClientAutoConfiguration.class})
@ConditionalOnBean({IdpServiceOAuth2Client.class, WebClient.Builder.class})
@ConditionalOnProperty(
        prefix = "egon.cola.platform.tianquan.shoubing.service-client",
        name = {"app-id", "registration-id"})
public class ServiceTokenWebClientConfiguration implements DisposableBean {

    /** WebClient attribute carrying the typed authorization request for exactly one call. */
    public static final String SERVICE_TOKEN_REQUEST_ATTRIBUTE =
            "egon.cola.platform.tianquan.shoubing.serviceTokenRequest";

    private HttpClient ownedHttpClient;

    @Bean(name = "serviceTokenWebClient")
    @ConditionalOnBean({IdpServiceOAuth2Client.class, WebClient.Builder.class})
    @ConditionalOnMissingBean(name = "serviceTokenWebClient")
    public WebClient serviceTokenWebClient(
            WebClient.Builder builder,
            @Qualifier("idpServiceOAuth2Client") IdpServiceOAuth2Client tokenClient,
            @Qualifier("idpTransportBindingRegistry") IdpTransportBindingRegistry bindings) {
        return builder.clone()
                // Preserve codecs/URI defaults, but own the credential-bearing terminal and retry policy.
                .filters(List::clear)
                .exchangeFunction(null)
                .clientConnector(new JdkClientHttpConnector(ownedHttpClient()))
                .filter(serviceTokenFilter(tokenClient, bindings))
                .build();
    }

    /** Keeps existing explicit callers on the HTTPS/loopback-only contract. */
    public WebClient serviceTokenWebClient(WebClient.Builder builder, IdpServiceOAuth2Client tokenClient) {
        return serviceTokenWebClient(builder, tokenClient, IdpTransportBindingRegistry.empty());
    }

    ExchangeFilterFunction serviceTokenFilter(IdpServiceOAuth2Client tokenClient) {
        return serviceTokenFilter(tokenClient, IdpTransportBindingRegistry.empty());
    }

    ExchangeFilterFunction serviceTokenFilter(IdpServiceOAuth2Client tokenClient,
                                             IdpTransportBindingRegistry registry) {
        IdpServiceOAuth2Client client = Objects.requireNonNull(tokenClient, "tokenClient");
        IdpTransportBindingRegistry bindings = Objects.requireNonNull(registry, "registry");
        return (request, next) -> Mono.defer(() -> {
            Object attribute = request.attributes().get(SERVICE_TOKEN_REQUEST_ATTRIBUTE);
            if (!(attribute instanceof IdpServiceTokenRequest tokenRequest)) {
                return Mono.error(new IdpServiceTokenRequestException(
                        "a typed SERVICE token request attribute is required"));
            }
            if (request.headers().containsHeader(HttpHeaders.AUTHORIZATION)) {
                return Mono.error(new IdpServiceTokenRequestException(
                        "caller-supplied Authorization is not allowed"));
            }
            rejectTransportOverrides(request);
            if (!sameOrigin(tokenRequest.audience(), request.url())) {
                return Mono.error(new IdpServiceTokenRequestException(
                        "SERVICE token audience and request origin do not match"));
            }
            ClientRequest outbound = request;
            if (bindings.hasBindings(tokenRequest.registrationId(), IdpTransportBindingVO.Operation.RESOURCE)) {
                ServiceAuthorizationKey identity = client.authorizationKey(tokenRequest);
                requireRequestIdentity(identity, tokenRequest);
                IdpTransportBindingVO binding = bindings.select(URI.create(identity.issuer()), request.url(),
                                tokenRequest.audience(), tokenRequest.registrationId(),
                                IdpTransportBindingVO.Operation.RESOURCE, request.method().name())
                        .orElseThrow(() -> new IdpServiceTokenRequestException("SERVICE transport binding is required"));
                if (binding.transport() != IdpTransportBindingVO.Transport.HTTP) {
                    return Mono.error(new IdpServiceTokenRequestException("SERVICE resource transport is invalid"));
                }
                outbound = ClientRequest.from(request).url(binding.physicalUri()).build();
            }
            return exchange(outbound, next, client, tokenRequest, false);
        });
    }

    private static void requireRequestIdentity(ServiceAuthorizationKey identity, IdpServiceTokenRequest request) {
        if (identity == null || !request.registrationId().equals(identity.registrationId())
                || !request.appId().equals(identity.appId()) || !request.audience().equals(identity.audience())
                || request.context() != identity.context() || !Objects.equals(request.tenantId(), identity.tenantId())
                || !request.scopes().equals(identity.scopes())) {
            throw new IdpServiceTokenRequestException("SERVICE authorization identity does not match the request");
        }
    }

    private static void rejectTransportOverrides(ClientRequest request) {
        if (!request.cookies().isEmpty() || request.httpRequest() != null) {
            throw new IdpServiceTokenRequestException("SERVICE cookies and native transport customizers are not allowed");
        }
        for (String name : request.headers().headerNames()) {
            String header = name.toLowerCase(Locale.ROOT);
            if (header.equals("cookie") || header.equals("proxy-authorization") || header.equals("host")
                    || header.equals(":authority") || header.equals("forwarded") || header.startsWith("x-forwarded-")
                    || header.equals("x-original-url") || header.equals("x-rewrite-url")
                    || header.equals("x-envoy-original-dst-host") || header.equals("x-envoy-original-path")) {
                throw new IdpServiceTokenRequestException("SERVICE credential and target override headers are not allowed");
            }
        }
    }

    private synchronized HttpClient ownedHttpClient() {
        if (ownedHttpClient == null) {
            ownedHttpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER)
                    .version(HttpClient.Version.HTTP_1_1)
                    .proxy(new ProxySelector() {
                        @Override
                        public List<Proxy> select(URI uri) {
                            return List.of(Proxy.NO_PROXY);
                        }

                        @Override
                        public void connectFailed(URI uri, SocketAddress address, IOException failure) {
                            // Direct transport has no proxy to mark failed; the connector reports the request failure.
                        }
                    }).build();
        }
        return ownedHttpClient;
    }

    @Override
    public synchronized void destroy() {
        if (ownedHttpClient != null) {
            ownedHttpClient.shutdownNow();
        }
    }

    private Mono<ClientResponse> exchange(
            ClientRequest request,
            ExchangeFunction next,
            IdpServiceOAuth2Client tokenClient,
            IdpServiceTokenRequest tokenRequest,
            boolean retried) {
        return Mono.fromCallable(() -> tokenClient.authorize(tokenRequest))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(token -> {
                    ClientRequest authenticated = ClientRequest.from(request)
                            .headers(headers -> headers.setBearerAuth(token.getTokenValue()))
                            .build();
                    return next.exchange(authenticated)
                            .flatMap(response -> afterExchange(
                                    response, request, next, tokenClient,
                                    tokenRequest, retried));
                });
    }

    private Mono<ClientResponse> afterExchange(
            ClientResponse response,
            ClientRequest request,
            ExchangeFunction next,
            IdpServiceOAuth2Client tokenClient,
            IdpServiceTokenRequest tokenRequest,
            boolean retried) {
        if (response.statusCode().value() != HttpStatus.UNAUTHORIZED.value()) {
            return Mono.just(response);
        }
        Mono<Void> invalidate = Mono.<Void>fromRunnable(
                        () -> tokenClient.invalidate(tokenRequest))
                .subscribeOn(Schedulers.boundedElastic());
        if (!retried && request.method() == HttpMethod.GET) {
            return response.releaseBody()
                    .then(invalidate)
                    .then(Mono.defer(() -> exchange(
                            request, next, tokenClient, tokenRequest, true)));
        }
        return invalidate.thenReturn(response);
    }

    private static boolean sameOrigin(URI audience, URI target) {
        if (!secureOrigin(audience) || !secureOrigin(target)) {
            return false;
        }
        return audience.getScheme().equalsIgnoreCase(target.getScheme())
                && audience.getHost().equalsIgnoreCase(target.getHost())
                && effectivePort(audience) == effectivePort(target);
    }

    private static boolean secureOrigin(URI uri) {
        if (uri == null || !uri.isAbsolute() || uri.isOpaque()
                || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getFragment() != null) {
            return false;
        }
        return "https".equalsIgnoreCase(uri.getScheme())
                || "http".equalsIgnoreCase(uri.getScheme())
                && loopback(uri.getHost());
    }

    private static boolean loopback(String host) {
        return "127.0.0.1".equals(host) || "localhost".equalsIgnoreCase(host)
                || "::1".equals(host) || "[::1]".equals(host);
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() >= 0) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }
}
