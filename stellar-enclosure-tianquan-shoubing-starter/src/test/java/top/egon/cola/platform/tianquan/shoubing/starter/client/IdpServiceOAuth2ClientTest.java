package top.egon.cola.platform.tianquan.shoubing.starter.client;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import org.springframework.util.MultiValueMap;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties.TrustedIssuerSettings;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TrustedIssuerRegistry;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.ProxySelector;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IdpServiceOAuth2ClientTest {

    private static final URI RESOURCE = URI.create(
            "https://api.example/prod/orders"
    );
    private static final String REGISTRATION_ID = "egon-tianquan-shoubing";
    private static final String ISSUER = "https://tianquan-shoubing.example";
    private static final String CLIENT_ID = "orders-key";
    private static final String APP_ID = "orders-app";
    private static final String TENANT_ISSUER_A = "https://idp.example/tenants/1001";
    private static final String TENANT_ISSUER_B = "https://idp.example/tenants/1001/alternate";
    private static final String TENANT_REGISTRATION_A = "orders-tenant-a";
    private static final String TENANT_REGISTRATION_B = "orders-tenant-b";
    private static final URI INTERNAL_TOKEN_ENDPOINT = URI.create(
            "http://tianquan-shoubing-http.permission-prod.svc.cluster.local:18080/oauth2/token");
    private final List<IdpServiceOAuth2Client> clients = new ArrayList<>();

    @AfterEach
    void closeClients() {
        clients.forEach(IdpServiceOAuth2Client::close);
    }

    @Test
    void projectedCredentialRotationUsesOneGenerationAcrossTheRealSpringManager(@TempDir Path directory)
            throws Exception {
        Path projection = directory.resolve("registrations.json");
        Files.writeString(projection, projectedRegistration(1L, "first-secret"));
        Class<?> repositoryType = Class.forName(
                "top.egon.cola.platform.tianquan.shoubing.starter.client.ProjectedClientRegistrationRepository");
        ClientRegistrationRepository registrations = (ClientRegistrationRepository) repositoryType
                .getConstructor(Path.class, com.fasterxml.jackson.databind.ObjectMapper.class, Map.class)
                .newInstance(projection, new com.fasterxml.jackson.databind.ObjectMapper(), Map.of(REGISTRATION_ID, 1L));
        repositoryType.getMethod("verifyAvailable").invoke(registrations);
        InMemoryOAuth2AuthorizedClientService store = new InMemoryOAuth2AuthorizedClientService(registrations);
        AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(registrations, store);
        IdpClientCredentialsRequestEntityConverter converter =
                new IdpClientCredentialsRequestEntityConverter(tokenBindings(1L));
        ClientCredentialsOAuth2AuthorizedClientProvider provider = new ClientCredentialsOAuth2AuthorizedClientProvider();
        List<String> secrets = new ArrayList<>();
        provider.setAccessTokenResponseClient(grant -> {
            assertThat(converter.convert(grant).getUrl()).isEqualTo(INTERNAL_TOKEN_ENDPOINT);
            secrets.add(grant.getClientRegistration().getClientSecret());
            return org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse
                    .withToken("projected-" + secrets.size()).tokenType(OAuth2AccessToken.TokenType.BEARER)
                    .expiresIn(300).scopes(Set.of("orders:read")).build();
        });
        manager.setAuthorizedClientProvider(provider);
        IdpStarterProperties properties = serviceProperties();
        IdpServiceOAuth2Client client = IdpServiceOAuth2Client.createConfigured(manager, converter,
                Clock.systemUTC(), Duration.ofSeconds(60), registrations, store,
                new TrustedIssuerRegistry(properties), properties);
        clients.add(client);
        IdpServiceTokenRequest request = request(REGISTRATION_ID, APP_ID,
                ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));

        assertThat(client.authorize(request).getTokenValue()).isEqualTo("projected-1");
        ServiceAuthorizationKey oldKey = client.authorizationKey(request);
        OAuth2AuthorizedClient firstStored = store.loadAuthorizedClient(REGISTRATION_ID, oldKey.principalName());
        assertThat(firstStored).isNotNull();
        Files.writeString(projection, projectedRegistration(2L, "second-secret"));

        assertThat(client.authorize(request).getTokenValue()).isEqualTo("projected-2");
        assertThat(client.authorize(request).getTokenValue()).isEqualTo("projected-2");
        assertThat(client.authorizationKey(request).credentialVersion()).isEqualTo(2L);
        assertThat(secrets).containsExactly("first-secret", "second-secret");
        OAuth2AuthorizedClient retiredStored = store.loadAuthorizedClient(REGISTRATION_ID, oldKey.principalName());
        assertThat(retiredStored).isNull();
        assertThat(client.cacheSize()).isEqualTo(1);

        // Material is checked even for a hot token; rejected input cannot silently keep serving that cache.
        Files.writeString(projection, projectedRegistration(2L, "tampered-private-secret"));
        assertThatThrownBy(() -> client.authorize(request))
                .isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class)
                .hasMessageContaining("registration_projection_unavailable").hasNoCause();
        assertThat(secrets).hasSize(2);
        Files.writeString(projection, projectedRegistration(2L, "second-secret"));
        assertThat(client.authorizeBounded(request, ISSUER, Duration.ofSeconds(2)).getTokenValue())
                .isEqualTo("projected-2");
        client.invalidateBounded(request, ISSUER, Duration.ofSeconds(2));
        assertThat(client.cacheSize()).isZero();
    }

    @Test
    void managedProjectionNeverFallsBackToTheCanonicalPublicTokenEndpoint(@TempDir Path directory) throws Exception {
        Path projection = directory.resolve("registrations.json");
        Files.writeString(projection, projectedRegistration(1L, "private-secret"));
        var registrations = new ProjectedClientRegistrationRepository(projection,
                new com.fasterxml.jackson.databind.ObjectMapper(), Map.of());
        var manager = mock(OAuth2AuthorizedClientManager.class);
        var store = new InMemoryOAuth2AuthorizedClientService(registrations);
        var properties = serviceProperties();
        properties.getServiceClient().setCredentialVersions(Map.of());
        var client = newClient(manager, store, Clock.systemUTC(), Duration.ofSeconds(60), properties, registrations);

        assertThatThrownBy(() -> client.authorize(request(REGISTRATION_ID, APP_ID,
                ServiceTokenContext.TENANT, "1001", Set.of("orders:read"))))
                .isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class)
                .hasMessageContaining("transport_binding_required");
        verify(manager, never()).authorize(any(OAuth2AuthorizeRequest.class));
    }

    @Test
    void idleRefreshEvictsWithAcceptedGenerationWhenProjectedFileIsMissing(@TempDir Path directory) throws Exception {
        Path projection = directory.resolve("registrations.json");
        Files.writeString(projection, projectedRegistration(1L, "private-secret"));
        var registrations = new ProjectedClientRegistrationRepository(projection,
                new com.fasterxml.jackson.databind.ObjectMapper(), Map.of());
        var store = new InMemoryOAuth2AuthorizedClientService(registrations);
        var manager = mock(OAuth2AuthorizedClientManager.class);
        var converter = new IdpClientCredentialsRequestEntityConverter(tokenBindings(1L));
        Instant now = Instant.parse("2026-11-18T00:00:00Z");
        MutableClock clock = new MutableClock(now);
        when(manager.authorize(any(OAuth2AuthorizeRequest.class))).thenAnswer(invocation -> {
            OAuth2AuthorizeRequest authorize = invocation.getArgument(0);
            var authorized = authorizedClient(authorize, registrations.findByRegistrationId(REGISTRATION_ID),
                    "cached-token", now, now.plusSeconds(300));
            store.saveAuthorizedClient(authorized, authorize.getPrincipal());
            return authorized;
        });
        var properties = serviceProperties();
        var client = IdpServiceOAuth2Client.createConfigured(manager, converter, clock, Duration.ofSeconds(60),
                registrations, store, new TrustedIssuerRegistry(properties), properties);
        clients.add(client);
        var request = request(REGISTRATION_ID, APP_ID, ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));
        client.authorize(request);
        ServiceAuthorizationKey key = client.authorizationKey(request);
        var generationsField = IdpServiceOAuth2Client.class.getDeclaredField("refreshGenerations");
        generationsField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<ServiceAuthorizationKey, Long> generations = (Map<ServiceAuthorizationKey, Long>) generationsField.get(client);
        long generation = generations.get(key);
        clock.advance(Duration.ofMinutes(3));
        Files.delete(projection);

        var refresh = IdpServiceOAuth2Client.class.getDeclaredMethod("refreshIfActive", ServiceAuthorizationKey.class, long.class);
        refresh.setAccessible(true);
        refresh.invoke(client, key, generation);

        assertThat(client.cacheSize()).isZero();
        registrations.withCurrentSnapshot(() -> {
            OAuth2AuthorizedClient stored = store.loadAuthorizedClient(REGISTRATION_ID, key.principalName());
            assertThat(stored).isNull();
        });
        verify(manager, times(1)).authorize(any(OAuth2AuthorizeRequest.class));
    }

    private static String projectedRegistration(long version, String secret) {
        return """
                {"registrations":[{"registrationId":"%s","issuer":"%s", "tokenUri":"%s/oauth2/token",
                "clientId":"%s","clientSecret":"%s","credentialVersion":%d}]}
                """.formatted(REGISTRATION_ID, ISSUER, ISSUER, CLIENT_ID, secret, version);
    }

    @Test
    void isolatesEveryAuthorizationDimension() {
        IdpServiceTokenRequest base = request(
                "egon-tianquan-shoubing",
                "orders-app",
                ServiceTokenContext.TENANT,
                "tenant-1",
                Set.of("orders:read", "orders:write")
        );
        ServiceAuthorizationKey key = key(base);

        assertThat(base.scopes()).containsExactly(
                "orders:read",
                "orders:write"
        );
        assertThat(key).isEqualTo(key(request(
                "egon-tianquan-shoubing",
                "orders-app",
                ServiceTokenContext.TENANT,
                "tenant-1",
                Set.of("orders:write", "orders:read")
        )));
        assertThat(key).isNotEqualTo(key(request(
                "egon-tianquan-shoubing",
                "orders-app",
                ServiceTokenContext.TENANT,
                "tenant-2",
                base.scopes()
        )));
        assertThat(key).isNotEqualTo(key(request(
                "egon-tianquan-shoubing",
                "other-app",
                ServiceTokenContext.TENANT,
                "tenant-1",
                base.scopes()
        )));
        assertThat(key).isNotEqualTo(key(request(
                "egon-tianquan-shoubing",
                "orders-app",
                ServiceTokenContext.PLATFORM,
                null,
                base.scopes()
        )));
        assertThat(key).isNotEqualTo(ServiceAuthorizationKey.from(
                base, "https://other.example", CLIENT_ID, 7L));
        assertThat(key).isNotEqualTo(ServiceAuthorizationKey.from(
                base, ISSUER, "other-client", 7L));
        assertThat(key).isNotEqualTo(ServiceAuthorizationKey.from(
                base, ISSUER, CLIENT_ID, 8L));
        ServiceAuthorizationKey bound = ServiceAuthorizationKey.from(base, ISSUER, CLIENT_ID, 7L,
                "identity-token", 1L);
        assertThat(bound).isNotEqualTo(key);
        assertThat(bound.principalName()).isNotEqualTo(key.principalName());
        for (ServiceAuthorizationKey changed : List.of(
                ServiceAuthorizationKey.from(base, ISSUER, CLIENT_ID, 7L, "identity-token", 2L),
                ServiceAuthorizationKey.from(base, ISSUER, CLIENT_ID, 7L, "replacement-token", 1L))) {
            assertThat(changed).isNotEqualTo(bound);
            assertThat(changed.principalName()).isNotEqualTo(bound.principalName());
        }
    }

    @Test
    void usesConfiguredRegistrationIdentityForBothCacheLayers() {
        OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
        OAuth2AuthorizedClientService authorizedClients =
                mock(OAuth2AuthorizedClientService.class);
        IdpStarterProperties properties = serviceProperties();
        Instant now = Instant.parse("2026-08-22T02:00:00Z");
        AtomicReference<String> managerPrincipal = new AtomicReference<>();
        when(manager.authorize(any(OAuth2AuthorizeRequest.class)))
                .thenAnswer(invocation -> {
                    OAuth2AuthorizeRequest authorizeRequest = invocation.getArgument(0);
                    managerPrincipal.set(authorizeRequest.getPrincipal().getName());
                    return authorizedClient(authorizeRequest, "identity-token", now,
                            now.plusSeconds(300));
                });

        IdpServiceOAuth2Client client = newClient(manager, authorizedClients,
                Clock.fixed(now, ZoneOffset.UTC), Duration.ofSeconds(60),
                properties, registrations(registration()));
        IdpServiceTokenRequest request = request(
                REGISTRATION_ID, APP_ID, ServiceTokenContext.TENANT, "1001",
                Set.of("orders:read"));

        assertThat(client.authorize(request).getTokenValue()).isEqualTo("identity-token");
        ServiceAuthorizationKey expected = ServiceAuthorizationKey.from(
                request, ISSUER, CLIENT_ID, 7L);
        assertThat(managerPrincipal).hasValue(expected.principalName());

        properties.getServiceClient().getCredentialVersions().clear();
        assertThatThrownBy(() -> client.authorize(request))
                .isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class)
                .hasMessageContaining("credential_version_unconfigured");
        properties.getServiceClient().getCredentialVersions().put(REGISTRATION_ID, 7L);
        IdpServiceTokenRequest remotePlaintext = request(REGISTRATION_ID, APP_ID,
                URI.create("http://api.attacker.example/orders"),
                ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));
        assertThatThrownBy(() -> client.authorize(remotePlaintext))
                .isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class)
                .hasMessageContaining("audience_invalid");
        verify(manager, times(1)).authorize(any(OAuth2AuthorizeRequest.class));
    }

    @Test
    @SuppressWarnings("deprecation")
    void compatibilityConstructorFailsClosedWithoutRegistrationIdentity() {
        OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
        Instant now = Instant.parse("2026-08-22T02:00:00Z");
        IdpServiceOAuth2Client client = new IdpServiceOAuth2Client(
                manager, Clock.fixed(now, ZoneOffset.UTC), Duration.ofSeconds(60));
        clients.add(client);
        IdpServiceTokenRequest request = request(REGISTRATION_ID, APP_ID,
                ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));

        assertThatThrownBy(() -> client.authorize(request))
                .isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class)
                .hasMessageContaining("registration_identity_unavailable");
        verify(manager, never()).authorize(any(OAuth2AuthorizeRequest.class));
    }

    @Test
    void partitionsTenantIssuersAndCredentialVersionsBeforeCallingTheManager() {
        ClientRegistration clientA = registration(
                TENANT_REGISTRATION_A, TENANT_ISSUER_A, "orders-key-a");
        ClientRegistration clientB = registration(
                TENANT_REGISTRATION_B, TENANT_ISSUER_B, "orders-key-b");
        IdpStarterProperties properties = multiIssuerProperties(
                TENANT_ISSUER_A, TENANT_ISSUER_B);
        properties.getServiceClient().getCredentialVersions().put(TENANT_REGISTRATION_A, 1L);
        properties.getServiceClient().getCredentialVersions().put(TENANT_REGISTRATION_B, 4L);
        ClientRegistrationRepository registrations = registrations(clientA, clientB);
        OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
        OAuth2AuthorizedClientService authorizedClients =
                mock(OAuth2AuthorizedClientService.class);
        Instant now = Instant.parse("2026-08-22T02:00:00Z");
        List<String> managerPrincipals = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger calls = new AtomicInteger();
        when(manager.authorize(any(OAuth2AuthorizeRequest.class)))
                .thenAnswer(invocation -> {
                    OAuth2AuthorizeRequest authorizeRequest = invocation.getArgument(0);
                    managerPrincipals.add(authorizeRequest.getPrincipal().getName());
                    return authorizedClient(
                            authorizeRequest,
                            "token-" + calls.incrementAndGet(),
                            now,
                            now.plusSeconds(300));
                });
        IdpServiceOAuth2Client client = newClient(manager, authorizedClients,
                Clock.fixed(now, ZoneOffset.UTC), Duration.ofSeconds(60),
                properties, registrations);
        IdpServiceTokenRequest requestA = request(TENANT_REGISTRATION_A, APP_ID, RESOURCE,
                ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));
        IdpServiceTokenRequest requestB = request(TENANT_REGISTRATION_B, APP_ID, RESOURCE,
                ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));

        assertThat(client.authorize(requestA).getTokenValue()).isEqualTo("token-1");
        assertThat(client.authorize(requestB).getTokenValue()).isEqualTo("token-2");
        assertThat(client.authorize(requestA).getTokenValue()).isEqualTo("token-1");
        properties.getServiceClient().getCredentialVersions().put(TENANT_REGISTRATION_A, 2L);
        assertThat(client.authorize(requestA).getTokenValue()).isEqualTo("token-3");

        assertThat(calls).hasValue(3);
        assertThat(managerPrincipals).hasSize(3).doesNotHaveDuplicates();

        IdpServiceTokenRequest wrongTenant = request(TENANT_REGISTRATION_A, APP_ID, RESOURCE,
                ServiceTokenContext.TENANT, "1002", Set.of("orders:read"));
        assertThatThrownBy(() -> client.authorize(wrongTenant))
                .isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class)
                .hasMessageContaining("issuer_context_mismatch");
        ClientRegistration untrusted = registration(
                "untrusted", "https://evil.example", "evil-key");
        properties.getServiceClient().getCredentialVersions().put("untrusted", 1L);
        ClientRegistrationRepository withUntrusted = registrations(clientA, clientB, untrusted);
        IdpServiceOAuth2Client untrustedClient = newClient(manager, authorizedClients,
                Clock.fixed(now, ZoneOffset.UTC), Duration.ofSeconds(60),
                properties, withUntrusted);
        assertThatThrownBy(() -> untrustedClient.authorize(request(
                "untrusted", APP_ID, RESOURCE, ServiceTokenContext.TENANT,
                "1001", Set.of("orders:read"))))
                .isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class)
                .hasMessageContaining("issuer_untrusted");
        assertThat(calls).hasValue(3);
    }

    @Test
    void coalescesConcurrentRenewalForOneAuthorizationKey() throws Exception {
        OAuth2AuthorizedClientManager manager = mock(
                OAuth2AuthorizedClientManager.class
        );
        OAuth2AuthorizedClientService authorizedClients =
                mock(OAuth2AuthorizedClientService.class);
        Instant now = Instant.parse("2026-08-22T02:00:00Z");
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        when(manager.authorize(any(OAuth2AuthorizeRequest.class)))
                .thenAnswer(invocation -> {
                    calls.incrementAndGet();
                    entered.countDown();
                    release.await();
                    OAuth2AuthorizeRequest authorizeRequest =
                            invocation.getArgument(0);
                    return authorizedClient(
                            authorizeRequest,
                            "fresh-token",
                            now,
                            now.plusSeconds(300));
                });

        var properties = serviceProperties();
        List<top.egon.cola.platform.tianquan.shoubing.core.observability.SecurityMetricObservationBO> observations =
                new java.util.concurrent.CopyOnWriteArrayList<>();
        IdpServiceOAuth2Client client = IdpServiceOAuth2Client.createConfigured(manager,
                new IdpClientCredentialsRequestEntityConverter(), Clock.fixed(now, ZoneOffset.UTC), Duration.ofSeconds(30),
                registrations(registration()), authorizedClients, new TrustedIssuerRegistry(properties), properties, observations::add);
        clients.add(client);
        IdpServiceTokenRequest request = request(
                "egon-tianquan-shoubing",
                "orders-app",
                ServiceTokenContext.TENANT,
                "tenant-1",
                Set.of("orders:read")
        );
        ExecutorService executor = Executors.newFixedThreadPool(4);
        try {
            List<Future<OAuth2AccessToken>> futures = new ArrayList<>();
            Callable<OAuth2AccessToken> call = () -> client.authorize(request);
            for (int i = 0; i < 4; i++) {
                futures.add(executor.submit(call));
            }
            assertThat(entered.await(2, java.util.concurrent.TimeUnit.SECONDS))
                    .isTrue();
            release.countDown();
            for (Future<OAuth2AccessToken> future : futures) {
                assertThat(future.get().getTokenValue())
                        .isEqualTo("fresh-token");
            }
            assertThat(calls).hasValue(1);
            assertThat(observations.stream().filter(value -> value.getSignal().equals("token.acquire.duration")).toList()).hasSize(1);
        } finally {
            release.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void removesExpiredFacadeAndAuthorizedClientEntriesBeforeRenewal() {
        Instant now = Instant.parse("2026-08-22T02:00:00Z");
        MutableClock clock = new MutableClock(now);
        OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
        OAuth2AuthorizedClientService authorizedClients =
                mock(OAuth2AuthorizedClientService.class);
        AtomicInteger calls = new AtomicInteger();
        when(manager.authorize(any(OAuth2AuthorizeRequest.class)))
                .thenAnswer(invocation -> {
                    int generation = calls.incrementAndGet();
                    OAuth2AuthorizeRequest authorizeRequest = invocation.getArgument(0);
                    return authorizedClient(authorizeRequest, "token-" + generation,
                            clock.instant(), clock.instant().plusSeconds(
                                    generation == 1 ? 90 : 300));
                });
        IdpServiceOAuth2Client client = newClient(manager, authorizedClients, clock,
                Duration.ofSeconds(60), serviceProperties(), registrations(registration()));
        IdpServiceTokenRequest request = request(REGISTRATION_ID, APP_ID,
                ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));

        assertThat(client.authorize(request).getTokenValue()).isEqualTo("token-1");
        clock.advance(Duration.ofSeconds(31));
        assertThat(client.authorize(request).getTokenValue()).isEqualTo("token-2");

        assertThat(calls).hasValue(2);
        verify(authorizedClients, times(1)).removeAuthorizedClient(
                eq(REGISTRATION_ID), any(String.class));
    }

    @Test
    void evictsTheUnderlyingAuthorizedClientWhenTheLocalCacheReachesItsBound() {
        Instant now = Instant.parse("2026-08-22T02:00:00Z");
        OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
        OAuth2AuthorizedClientService authorizedClients =
                mock(OAuth2AuthorizedClientService.class);
        AtomicInteger calls = new AtomicInteger();
        when(manager.authorize(any(OAuth2AuthorizeRequest.class)))
                .thenAnswer(invocation -> {
                    OAuth2AuthorizeRequest authorizeRequest = invocation.getArgument(0);
                    int index = calls.incrementAndGet();
                    return authorizedClient(authorizeRequest, "token-" + index,
                            now, now.plusSeconds(3600));
                });
        IdpServiceOAuth2Client client = newClient(manager, authorizedClients,
                Clock.fixed(now, ZoneOffset.UTC), Duration.ofSeconds(60),
                serviceProperties(), registrations(registration()));

        for (int index = 0; index <= 10_000; index++) {
            IdpServiceTokenRequest request = request(REGISTRATION_ID, APP_ID,
                    URI.create("https://api.example/prod/orders/" + index),
                    ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));
            client.authorize(request);
        }

        assertThat(calls).hasValue(10_001);
        assertThat(client.cacheSize()).isEqualTo(10_000);
        verify(authorizedClients, times(1)).removeAuthorizedClient(
                eq(REGISTRATION_ID), any(String.class));
    }

    @Test
    void proactivelyRefreshesRecentlyActiveKeysBeforeExpiry() throws Exception {
        OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
        OAuth2AuthorizedClientService authorizedClients =
                mock(OAuth2AuthorizedClientService.class);
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch refreshed = new CountDownLatch(1);
        when(manager.authorize(any(OAuth2AuthorizeRequest.class)))
                .thenAnswer(invocation -> {
                    int generation = calls.incrementAndGet();
                    OAuth2AuthorizeRequest authorizeRequest = invocation.getArgument(0);
                    Instant now = Instant.now();
                    if (generation > 1) {
                        refreshed.countDown();
                    }
                    return authorizedClient(authorizeRequest, "token-" + generation,
                            now, now.plusMillis(generation == 1 ? 2_000 : 300_000));
                });
        IdpServiceOAuth2Client client = newClient(manager, authorizedClients,
                Clock.systemUTC(), Duration.ofMillis(200), serviceProperties(),
                registrations(registration()));
        IdpServiceTokenRequest request = request(REGISTRATION_ID, APP_ID,
                ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));

        assertThat(client.authorize(request).getTokenValue()).isEqualTo("token-1");
        assertThat(refreshed.await(4, TimeUnit.SECONDS)).isTrue();
        assertThat(calls).hasValue(2);
    }

    @Test
    void serviceWebClientRetriesOneGet401ButNeverReplaysPostOrForbiddenRequests() {
        IdpServiceTokenRequest tokenRequest = request(REGISTRATION_ID, APP_ID,
                ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));
        IdpServiceOAuth2Client getTokenClient = mock(IdpServiceOAuth2Client.class);
        when(getTokenClient.authorize(tokenRequest)).thenReturn(
                accessToken("first", Instant.now()), accessToken("second", Instant.now()));
        AtomicInteger getExchanges = new AtomicInteger();
        ExchangeFilterFunction getFilter = new ServiceTokenWebClientConfiguration()
                .serviceTokenFilter(getTokenClient);
        WebClient getClient = WebClient.builder()
                .filter(getFilter)
                .exchangeFunction(request -> {
                    assertThat(request.headers().getFirst("Authorization"))
                            .startsWith("Bearer ");
                    return Mono.just(ClientResponse.create(getExchanges.incrementAndGet() == 1
                            ? HttpStatus.UNAUTHORIZED : HttpStatus.OK).build());
                })
                .build();

        Integer getStatus = getClient.get()
                .uri(URI.create(RESOURCE + "/item/1"))
                .attribute(ServiceTokenWebClientConfiguration.SERVICE_TOKEN_REQUEST_ATTRIBUTE,
                        tokenRequest)
                .exchangeToMono(response -> Mono.just(response.statusCode().value()))
                .block(Duration.ofSeconds(4));

        assertThat(getStatus).isEqualTo(HttpStatus.OK.value());
        assertThat(getExchanges).hasValue(2);
        verify(getTokenClient, times(1)).invalidate(tokenRequest);

        IdpServiceOAuth2Client postTokenClient = mock(IdpServiceOAuth2Client.class);
        when(postTokenClient.authorize(tokenRequest)).thenReturn(
                accessToken("post-token", Instant.now()));
        AtomicInteger postExchanges = new AtomicInteger();
        WebClient postClient = WebClient.builder()
                .filter(new ServiceTokenWebClientConfiguration()
                        .serviceTokenFilter(postTokenClient))
                .exchangeFunction(request -> {
                    postExchanges.incrementAndGet();
                    return Mono.just(ClientResponse.create(HttpStatus.UNAUTHORIZED).build());
                })
                .build();
        Integer postStatus = postClient.post()
                .uri(URI.create(RESOURCE + "/commands"))
                .attribute(ServiceTokenWebClientConfiguration.SERVICE_TOKEN_REQUEST_ATTRIBUTE,
                        tokenRequest)
                .exchangeToMono(response -> Mono.just(response.statusCode().value()))
                .block(Duration.ofSeconds(4));

        assertThat(postStatus).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(postExchanges).hasValue(1);
        verify(postTokenClient, times(1)).invalidate(tokenRequest);
    }

    @Test
    void serviceWebClientRejectsUnboundAndCrossOriginRequestsBeforeAuthorization() {
        IdpServiceTokenRequest tokenRequest = request(REGISTRATION_ID, APP_ID,
                ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));
        IdpServiceOAuth2Client tokenClient = mock(IdpServiceOAuth2Client.class);
        AtomicInteger exchanges = new AtomicInteger();
        WebClient client = WebClient.builder()
                .filter(new ServiceTokenWebClientConfiguration().serviceTokenFilter(tokenClient))
                .exchangeFunction(request -> {
                    exchanges.incrementAndGet();
                    return Mono.just(ClientResponse.create(HttpStatus.OK).build());
                })
                .build();

        assertThatThrownBy(() -> client.get()
                .uri(URI.create("https://api.example/prod/orders"))
                .exchangeToMono(response -> Mono.just(response.statusCode().value()))
                .block(Duration.ofSeconds(4)))
                .hasMessageContaining("typed SERVICE token request attribute is required");
        assertThatThrownBy(() -> client.get()
                .uri(URI.create("https://other.example/orders"))
                .attribute(ServiceTokenWebClientConfiguration.SERVICE_TOKEN_REQUEST_ATTRIBUTE,
                        tokenRequest)
                .exchangeToMono(response -> Mono.just(response.statusCode().value()))
                .block(Duration.ofSeconds(4)))
                .hasMessageContaining("audience and request origin do not match");
        assertThatThrownBy(() -> client.get()
                .uri(URI.create("https://api.example/prod/orders"))
                .headers(headers -> headers.setBearerAuth("caller-token"))
                .attribute(ServiceTokenWebClientConfiguration.SERVICE_TOKEN_REQUEST_ATTRIBUTE,
                        tokenRequest)
                .exchangeToMono(response -> Mono.just(response.statusCode().value()))
                .block(Duration.ofSeconds(4)))
                .hasMessageContaining("caller-supplied Authorization is not allowed");

        assertThat(exchanges).hasValue(0);
        verify(tokenClient, never()).authorize(any());
    }

    @Test
    void doesNotRetryForbiddenOrRedirectResponses() {
        IdpServiceTokenRequest tokenRequest = request(REGISTRATION_ID, APP_ID,
                ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));
        IdpServiceOAuth2Client tokenClient = mock(IdpServiceOAuth2Client.class);
        when(tokenClient.authorize(tokenRequest)).thenReturn(
                accessToken("one-shot", Instant.now()));
        AtomicInteger exchanges = new AtomicInteger();
        WebClient client = WebClient.builder()
                .filter(new ServiceTokenWebClientConfiguration().serviceTokenFilter(tokenClient))
                .exchangeFunction(request -> {
                    int attempt = exchanges.incrementAndGet();
                    return Mono.just(ClientResponse.create(attempt == 1
                            ? HttpStatus.FORBIDDEN : HttpStatus.FOUND)
                            .header("Location", "https://other.example/redirect")
                            .build());
                })
                .build();

        Integer status = client.get()
                .uri(URI.create("https://api.example/prod/orders"))
                .attribute(ServiceTokenWebClientConfiguration.SERVICE_TOKEN_REQUEST_ATTRIBUTE,
                        tokenRequest)
                .exchangeToMono(response -> Mono.just(response.statusCode().value()))
                .block(Duration.ofSeconds(4));

        assertThat(status).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(exchanges).hasValue(1);
        verify(tokenClient, never()).invalidate(tokenRequest);

        AtomicInteger redirects = new AtomicInteger();
        WebClient redirectClient = WebClient.builder()
                .filter(new ServiceTokenWebClientConfiguration().serviceTokenFilter(tokenClient))
                .exchangeFunction(request -> {
                    redirects.incrementAndGet();
                    return Mono.just(ClientResponse.create(HttpStatus.FOUND)
                            .header("Location", "https://other.example/redirect")
                            .build());
                })
                .build();
        Integer redirectStatus = redirectClient.get()
                .uri(URI.create("https://api.example/prod/orders"))
                .attribute(ServiceTokenWebClientConfiguration.SERVICE_TOKEN_REQUEST_ATTRIBUTE,
                        tokenRequest)
                .exchangeToMono(response -> Mono.just(response.statusCode().value()))
                .block(Duration.ofSeconds(4));
        assertThat(redirectStatus).isEqualTo(HttpStatus.FOUND.value());
        assertThat(redirects).hasValue(1);
        verify(tokenClient, never()).invalidate(tokenRequest);
    }

    @Test
    void rejectsTokenResponseWithBroaderScopesThanRequested() {
        OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
        OAuth2AuthorizedClientService authorizedClients =
                mock(OAuth2AuthorizedClientService.class);
        Instant now = Instant.parse("2026-08-22T02:00:00Z");
        when(manager.authorize(any(OAuth2AuthorizeRequest.class)))
                .thenAnswer(invocation -> {
                    OAuth2AuthorizeRequest authorizeRequest = invocation.getArgument(0);
                    OAuth2AccessToken broader = new OAuth2AccessToken(
                            OAuth2AccessToken.TokenType.BEARER,
                            "over-scoped",
                            now,
                            now.plusSeconds(300),
                            Set.of("orders:read", "orders:write"));
                    return new OAuth2AuthorizedClient(registration(),
                            authorizeRequest.getPrincipal().getName(), broader);
                });
        IdpServiceOAuth2Client client = newClient(manager, authorizedClients,
                Clock.fixed(now, ZoneOffset.UTC), Duration.ofSeconds(60),
                serviceProperties(), registrations(registration()));
        IdpServiceTokenRequest request = request(REGISTRATION_ID, APP_ID,
                ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));

        assertThatThrownBy(() -> client.authorize(request))
                .isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class)
                .hasMessageContaining("invalid_token_response");
        assertThat(client.cacheSize()).isZero();
        verify(authorizedClients, times(1)).removeAuthorizedClient(
                eq(REGISTRATION_ID), any(String.class));
    }

    @Test
    void doesNotFollowCrossOriginRedirectWithTheBearerHeader() throws IOException {
        HttpServer target = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        HttpServer other = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        ExecutorService targetExecutor = Executors.newSingleThreadExecutor();
        ExecutorService otherExecutor = Executors.newSingleThreadExecutor();
        AtomicInteger targetHits = new AtomicInteger();
        AtomicInteger otherHits = new AtomicInteger();
        AtomicReference<String> targetAuthorization = new AtomicReference<>();
        AtomicReference<String> otherAuthorization = new AtomicReference<>();
        target.setExecutor(targetExecutor);
        other.setExecutor(otherExecutor);
        other.createContext("/steal", exchange -> {
            otherHits.incrementAndGet();
            otherAuthorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            exchange.sendResponseHeaders(HttpStatus.OK.value(), -1);
            exchange.close();
        });
        target.createContext("/orders", exchange -> {
            targetHits.incrementAndGet();
            targetAuthorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            exchange.getResponseHeaders().set("Location",
                    "http://127.0.0.1:" + other.getAddress().getPort() + "/steal");
            exchange.sendResponseHeaders(HttpStatus.FOUND.value(), -1);
            exchange.close();
        });
        target.start();
        other.start();
        try {
            URI audience = URI.create(
                    "http://127.0.0.1:" + target.getAddress().getPort() + "/orders-resource");
            IdpServiceTokenRequest tokenRequest = request(REGISTRATION_ID, APP_ID, audience,
                    ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));
            IdpServiceOAuth2Client tokenClient = mock(IdpServiceOAuth2Client.class);
            when(tokenClient.authorize(tokenRequest)).thenReturn(
                    accessToken("localhost-token", Instant.now()));
            WebClient webClient = new ServiceTokenWebClientConfiguration()
                    .serviceTokenWebClient(WebClient.builder(), tokenClient);

            Integer status = webClient.get()
                    .uri(URI.create("http://127.0.0.1:"
                            + target.getAddress().getPort() + "/orders"))
                    .attribute(ServiceTokenWebClientConfiguration.SERVICE_TOKEN_REQUEST_ATTRIBUTE,
                            tokenRequest)
                    .exchangeToMono(response -> Mono.just(response.statusCode().value()))
                    .block(Duration.ofSeconds(4));

            assertThat(status).isEqualTo(HttpStatus.FOUND.value());
            assertThat(targetHits).hasValue(1);
            assertThat(targetAuthorization).hasValue("Bearer localhost-token");
            assertThat(otherHits).hasValue(0);
            assertThat(otherAuthorization.get()).isNull();
        } finally {
            target.stop(0);
            other.stop(0);
            targetExecutor.shutdownNow();
            otherExecutor.shutdownNow();
        }
    }

    @Test
    void keepsCanonicalOAuthIdentityWhileSendingTheGrantToTheFixedInternalTokenService() {
        ClientRegistration canonical = registration();
        var grant = new org.springframework.security.oauth2.client.endpoint
                .OAuth2ClientCredentialsGrantRequest(canonical);
        var converter = new IdpClientCredentialsRequestEntityConverter(tokenBindings(1));

        var entity = converter.convert(grant, RESOURCE, ServiceTokenContext.TENANT,
                "1001", Set.of("orders:write", "orders:read"));

        assertThat(entity.getUrl()).isEqualTo(INTERNAL_TOKEN_ENDPOINT);
        assertThat(entity.getMethod()).isEqualTo(org.springframework.http.HttpMethod.POST);
        assertThat(canonical.getProviderDetails().getIssuerUri()).isEqualTo(ISSUER);
        assertThat(canonical.getProviderDetails().getTokenUri()).isEqualTo(ISSUER + "/oauth2/token");
        assertThat(entity.getHeaders().getFirst("Authorization")).isEqualTo("Basic "
                + Base64.getEncoder().encodeToString((CLIENT_ID + ":orders-secret")
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        @SuppressWarnings("unchecked")
        MultiValueMap<String, String> body = (MultiValueMap<String, String>) entity.getBody();
        assertThat(body).containsOnlyKeys("grant_type", "resource", "tenant_id", "scope");
        assertThat(body.getFirst("grant_type")).isEqualTo("client_credentials");
        assertThat(body.getFirst("resource")).isEqualTo(RESOURCE.toASCIIString());
        assertThat(body.getFirst("tenant_id")).isEqualTo("1001");
        assertThat(body.getFirst("scope")).isEqualTo("orders:read orders:write");
    }

    @Test
    void preservesExternalCanonicalEndpointWhenTheUnboundRegistrationUsesItsTrustedStarterIssuer() {
        ClientRegistration external = ClientRegistration.withRegistrationId(REGISTRATION_ID)
                .clientId(CLIENT_ID).clientSecret("orders-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenUri(ISSUER + "/oauth2/token").build();
        var grant = new org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest(external);

        assertThat(new IdpClientCredentialsRequestEntityConverter().convert(grant, RESOURCE,
                ServiceTokenContext.TENANT, "1001", Set.of("orders:read")).getUrl())
                .isEqualTo(URI.create(ISSUER + "/oauth2/token"));
        assertThatThrownBy(() -> new IdpClientCredentialsRequestEntityConverter(tokenBindings(1))
                .convert(grant, RESOURCE, ServiceTokenContext.TENANT, "1001", Set.of("orders:read")))
                .isInstanceOf(IdpServiceTokenRequest.IdpServiceTokenRequestException.class)
                .hasMessage("OAuth token transport binding is invalid");
    }

    @Test
    void tokenBindingRevisionsPartitionBothCachesWithoutChangingTheCanonicalResourceOrRegistration() {
        var manager = mock(OAuth2AuthorizedClientManager.class);
        var authorized = mock(OAuth2AuthorizedClientService.class);
        Instant now = Instant.parse("2026-11-18T00:00:00Z");
        var converterV1 = new IdpClientCredentialsRequestEntityConverter(tokenBindings(1));
        var converterV2 = new IdpClientCredentialsRequestEntityConverter(tokenBindings(2));
        List<String> principals = new ArrayList<>();
        AtomicInteger acquisitions = new AtomicInteger();
        var grant = new org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest(registration());
        when(manager.authorize(any(OAuth2AuthorizeRequest.class))).thenAnswer(invocation -> {
            OAuth2AuthorizeRequest authorize = invocation.getArgument(0);
            principals.add(authorize.getPrincipal().getName());
            var active = acquisitions.get() == 0 ? converterV1 : converterV2;
            assertThat(active.convert(grant).getUrl()).isEqualTo(INTERNAL_TOKEN_ENDPOINT);
            return authorizedClient(authorize, "bound-" + acquisitions.incrementAndGet(), now, now.plusSeconds(300));
        });
        var properties = serviceProperties();
        var v1 = IdpServiceOAuth2Client.createConfigured(manager, converterV1, Clock.fixed(now, ZoneOffset.UTC),
                Duration.ofSeconds(60), registrations(registration()), authorized, new TrustedIssuerRegistry(properties), properties);
        var v2 = IdpServiceOAuth2Client.createConfigured(manager, converterV2, Clock.fixed(now, ZoneOffset.UTC),
                Duration.ofSeconds(60), registrations(registration()), authorized, new TrustedIssuerRegistry(properties), properties);
        clients.add(v1);
        clients.add(v2);
        var request = request(REGISTRATION_ID, APP_ID, ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));

        assertThat(v1.authorize(request).getTokenValue()).isEqualTo("bound-1");
        assertThat(v1.authorize(request).getTokenValue()).isEqualTo("bound-1");
        assertThat(v2.authorize(request).getTokenValue()).isEqualTo("bound-2");
        assertThat(acquisitions).hasValue(2);
        assertThat(principals).hasSize(2).doesNotHaveDuplicates();
        assertThat(v1.authorizationKey(request).bindingId()).isEqualTo("identity-token");
        assertThat(v1.authorizationKey(request).bindingVersion()).isEqualTo(1);
        assertThat(v2.authorizationKey(request).bindingVersion()).isEqualTo(2);
        assertThat(v2.authorizationKey(request).issuer()).isEqualTo(ISSUER);
        assertThat(v2.authorizationKey(request).audience()).isEqualTo(RESOURCE);
        assertThatThrownBy(() -> converterV1.convert(grant))
                .isInstanceOf(IdpServiceTokenRequest.IdpServiceTokenRequestException.class)
                .hasMessage("OAuth request parameters are required");
    }

    @Test
    void obtainsAndCachesAnOAuthTokenOverFixedInternalHttpWithoutFollowingRedirects() throws Exception {
        // The test HTTP proxy receives the literal .svc URI; production has no localhost mapping or DNS override.
        HttpServer proxy = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        HttpServer redirect = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicInteger proxyHits = new AtomicInteger();
        AtomicInteger redirectHits = new AtomicInteger();
        AtomicReference<URI> destination = new AtomicReference<>();
        AtomicReference<String> basic = new AtomicReference<>();
        AtomicReference<Map<String, String>> form = new AtomicReference<>();
        java.util.concurrent.atomic.AtomicBoolean sendRedirect = new java.util.concurrent.atomic.AtomicBoolean();
        redirect.createContext("/steal", exchange -> {
            redirectHits.incrementAndGet();
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        proxy.createContext("/", exchange -> {
            int call = proxyHits.incrementAndGet();
            destination.set(exchange.getRequestURI());
            basic.set(exchange.getRequestHeaders().getFirst("Authorization"));
            Map<String, String> parameters = new LinkedHashMap<>();
            for (String field : new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8).split("&")) {
                String[] parts = field.split("=", 2);
                parameters.put(URLDecoder.decode(parts[0], StandardCharsets.UTF_8),
                        URLDecoder.decode(parts.length == 1 ? "" : parts[1], StandardCharsets.UTF_8));
            }
            form.set(parameters);
            if (sendRedirect.get()) {
                exchange.getResponseHeaders().set("Location", "http://127.0.0.1:"
                        + redirect.getAddress().getPort() + "/steal");
                exchange.sendResponseHeaders(302, -1);
            } else {
                byte[] response = ("{\"access_token\":\"wire-" + call + "\",\"token_type\":\"Bearer\","
                        + "\"expires_in\":300,\"scope\":\"" + parameters.get("scope") + "\"}")
                        .getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, response.length);
                exchange.getResponseBody().write(response);
            }
            exchange.close();
        });
        proxy.start();
        redirect.start();
        try (HttpClient transport = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2))
                .followRedirects(HttpClient.Redirect.NEVER).proxy(ProxySelector.of(proxy.getAddress())).build()) {
            var factory = new org.springframework.http.client.JdkClientHttpRequestFactory(transport);
            factory.setReadTimeout(Duration.ofSeconds(2));
            var rest = org.springframework.web.client.RestClient.builder().requestFactory(factory)
                    .configureMessageConverters(converters -> {
                        converters.addCustomConverter(new org.springframework.http.converter.FormHttpMessageConverter());
                        converters.addCustomConverter(new org.springframework.security.oauth2.core.http.converter
                                .OAuth2AccessTokenResponseHttpMessageConverter());
                    }).defaultStatusHandler(new org.springframework.security.oauth2.client.http
                            .OAuth2ErrorResponseErrorHandler()).build();
            var converter = new IdpClientCredentialsRequestEntityConverter(tokenBindings(1));
            var registrations = registrations(registration());
            var store = new org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService(registrations);
            var provider = new org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider();
            provider.setAccessTokenResponseClient(grant -> {
                var entity = converter.convert(grant);
                return rest.method(entity.getMethod()).uri(entity.getUrl())
                        .headers(headers -> headers.addAll(entity.getHeaders())).body(entity.getBody())
                        .retrieve().body(org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse.class);
            });
            var manager = new org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager(
                    registrations, store);
            manager.setAuthorizedClientProvider(provider);
            var properties = serviceProperties();
            var client = IdpServiceOAuth2Client.createConfigured(manager, converter, Clock.systemUTC(),
                    Duration.ofSeconds(60), registrations, store, new TrustedIssuerRegistry(properties), properties);
            clients.add(client);
            var request = request(REGISTRATION_ID, APP_ID, ServiceTokenContext.TENANT, "1001",
                    Set.of("orders:write", "orders:read"));

            assertThat(client.authorize(request).getTokenValue()).isEqualTo("wire-1");
            assertThat(client.authorize(request).getTokenValue()).isEqualTo("wire-1");
            assertThat(proxyHits).hasValue(1);
            assertThat(destination).hasValue(INTERNAL_TOKEN_ENDPOINT);
            assertThat(basic).hasValue("Basic " + Base64.getEncoder()
                    .encodeToString((CLIENT_ID + ":orders-secret").getBytes(StandardCharsets.UTF_8)));
            assertThat(form.get()).containsExactlyInAnyOrderEntriesOf(Map.of("grant_type", "client_credentials",
                    "resource", RESOURCE.toASCIIString(), "tenant_id", "1001", "scope", "orders:read orders:write"));
            String previousPrincipal = client.authorizationKey(request).principalName();
            properties.getServiceClient().getCredentialVersions().put(REGISTRATION_ID, 8L);
            assertThat(client.authorize(request).getTokenValue()).isEqualTo("wire-2");
            OAuth2AuthorizedClient evicted = store.loadAuthorizedClient(REGISTRATION_ID, previousPrincipal);
            assertThat(evicted).isNull();
            assertThat(proxyHits).hasValue(2);

            client.invalidate(request);
            sendRedirect.set(true);
            assertThatThrownBy(() -> client.authorize(request))
                    .isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class);
            assertThat(proxyHits).hasValue(3);
            assertThat(redirectHits).hasValue(0);
        } finally {
            proxy.stop(0);
            redirect.stop(0);
        }
    }

    @Test
    void optedInTokenBindingsRejectWrongResourceAndCanonicalEndpointBeforeTheManager() {
        var manager = mock(OAuth2AuthorizedClientManager.class);
        var authorized = mock(OAuth2AuthorizedClientService.class);
        var properties = serviceProperties();
        var converter = new IdpClientCredentialsRequestEntityConverter(tokenBindings(1));
        for (String tokenUri : List.of(ISSUER + "/oauth2/other", INTERNAL_TOKEN_ENDPOINT.toString(),
                "http://127.0.0.1:18080/oauth2/token", "https://other.example/oauth2/token",
                ISSUER + "/oauth2/token?target=wrong", ISSUER + "/oauth2/token#wrong",
                "https://user:secret@tianquan-shoubing.example/oauth2/token")) {
            ClientRegistration registration = ClientRegistration.withClientRegistration(registration()).tokenUri(tokenUri).build();
            var client = IdpServiceOAuth2Client.createConfigured(manager, converter, Clock.systemUTC(),
                    Duration.ofSeconds(60), registrations(registration), authorized, new TrustedIssuerRegistry(properties), properties);
            clients.add(client);
            assertThatThrownBy(() -> client.authorize(request(REGISTRATION_ID, APP_ID,
                    ServiceTokenContext.TENANT, "1001", Set.of("orders:read"))))
                    .isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class)
                    .hasMessageNotContaining("user:secret").hasMessageNotContaining("127.0.0.1");
        }
        var client = IdpServiceOAuth2Client.createConfigured(manager, converter, Clock.systemUTC(),
                Duration.ofSeconds(60), registrations(registration()), authorized, new TrustedIssuerRegistry(properties), properties);
        clients.add(client);
        assertThatThrownBy(() -> client.authorize(request(REGISTRATION_ID, APP_ID,
                URI.create("https://api.example/prod/unapproved"), ServiceTokenContext.TENANT,
                "1001", Set.of("orders:read"))))
                .isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class)
                .hasMessageContaining("transport_binding_invalid");
        verify(manager, never()).authorize(any(OAuth2AuthorizeRequest.class));
    }

    @Test
    void failedAcquisitionClearsBoundParametersAndPlatformGrantsCarryNoTenant() {
        var manager = mock(OAuth2AuthorizedClientManager.class);
        var authorized = mock(OAuth2AuthorizedClientService.class);
        var properties = serviceProperties();
        var converter = new IdpClientCredentialsRequestEntityConverter(tokenBindings(1));
        var grant = new org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest(registration());
        when(manager.authorize(any(OAuth2AuthorizeRequest.class))).thenAnswer(invocation -> {
            var entity = converter.convert(grant);
            @SuppressWarnings("unchecked")
            MultiValueMap<String, String> body = (MultiValueMap<String, String>) entity.getBody();
            assertThat(entity.getUrl()).isEqualTo(INTERNAL_TOKEN_ENDPOINT);
            assertThat(body).doesNotContainKey("tenant_id");
            throw new org.springframework.security.oauth2.core.OAuth2AuthorizationException(
                    new org.springframework.security.oauth2.core.OAuth2Error("invalid_client"));
        });
        var client = IdpServiceOAuth2Client.createConfigured(manager, converter, Clock.systemUTC(),
                Duration.ofSeconds(60), registrations(registration()), authorized, new TrustedIssuerRegistry(properties), properties);
        clients.add(client);
        assertThatThrownBy(() -> client.authorize(request(REGISTRATION_ID, APP_ID,
                ServiceTokenContext.PLATFORM, null, Set.of("orders:read"))))
                .isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class)
                .hasMessageContaining("invalid_client");
        assertThatThrownBy(() -> converter.convert(grant))
                .isInstanceOf(IdpServiceTokenRequest.IdpServiceTokenRequestException.class)
                .hasMessage("OAuth request parameters are required");
    }

    @Test
    void converterUsesBasicHeaderAndOnlyStandardExtensionParameters()
            throws Exception {
        ClientRegistration registration = registration();
        var grant = new org.springframework.security.oauth2.client.endpoint
                .OAuth2ClientCredentialsGrantRequest(registration);
        IdpClientCredentialsRequestEntityConverter converter =
                new IdpClientCredentialsRequestEntityConverter();

        var entity = converter.convert(
                grant,
                RESOURCE,
                ServiceTokenContext.TENANT,
                "tenant-1",
                Set.of("orders:write", "orders:read")
        );

        assertThat(entity.getHeaders().getFirst("Authorization"))
                .startsWith("Basic ");
        @SuppressWarnings("unchecked")
        MultiValueMap<String, String> body =
                (MultiValueMap<String, String>) entity.getBody();
        assertThat(body.getFirst("grant_type"))
                .isEqualTo("client_credentials");
        assertThat(body.getFirst("resource")).isEqualTo(RESOURCE.toString());
        assertThat(body.getFirst("tenant_id")).isEqualTo("tenant-1");
        assertThat(body.getFirst("scope"))
                .isEqualTo("orders:read orders:write");
        assertThat(body).doesNotContainKey("client_secret")
                .doesNotContainKey("client_assertion");
    }

    @Test
    void observesOnlyActualServiceCacheLookupsAndTokenAcquisitions() {
        Instant now = Instant.parse("2026-10-10T00:00:00Z");
        MutableClock clock = new MutableClock(now);
        var manager = mock(OAuth2AuthorizedClientManager.class);
        var authorizedClients = mock(OAuth2AuthorizedClientService.class);
        var properties = serviceProperties();
        List<top.egon.cola.platform.tianquan.shoubing.core.observability.SecurityMetricObservationBO> observations = new ArrayList<>();
        when(manager.authorize(any(OAuth2AuthorizeRequest.class))).thenAnswer(call ->
                authorizedClient(call.getArgument(0), "observed-token", clock.instant(), clock.instant().plusSeconds(300)));
        var client = IdpServiceOAuth2Client.createConfigured(manager, new IdpClientCredentialsRequestEntityConverter(),
                clock, Duration.ofSeconds(60), registrations(registration()), authorizedClients,
                new TrustedIssuerRegistry(properties), properties, observations::add);
        clients.add(client);
        var request = request(REGISTRATION_ID, APP_ID, ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));
        client.authorize(request);
        client.authorize(request);
        clock.advance(Duration.ofSeconds(241));
        client.authorize(request);
        assertThat(observations.stream().filter(value -> value.getSignal().equals("token.cache.access"))
                .map(value -> value.getResult()).toList()).containsExactly("MISS", "HIT", "EXPIRED");
        assertThat(observations.stream().filter(value -> value.getSignal().equals("token.acquire.duration")).toList())
                .hasSize(2).allSatisfy(value -> {
                    assertThat(value.getResult()).isEqualTo("SUCCESS");
                    assertThat(value.getDuration().isNegative()).isFalse();
                });
        verify(manager, times(2)).authorize(any(OAuth2AuthorizeRequest.class));
        client.invalidate(request);
        when(manager.authorize(any(OAuth2AuthorizeRequest.class))).thenThrow(new IllegalStateException("endpoint unavailable"));
        assertThatThrownBy(() -> client.authorize(request)).isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class);
        assertThat(observations.getLast().getSignal()).isEqualTo("token.acquire.duration");
        assertThat(observations.getLast().getResult()).isEqualTo("FAILURE");
    }

    @Test
    void unavailableMetricsNeverLoseATokenOrHideAnAuthorizationFailure() {
        Instant now = Instant.parse("2026-10-10T00:00:00Z");
        var manager = mock(OAuth2AuthorizedClientManager.class);
        var authorizedClients = mock(OAuth2AuthorizedClientService.class);
        var properties = serviceProperties();
        when(manager.authorize(any(OAuth2AuthorizeRequest.class))).thenAnswer(call ->
                authorizedClient(call.getArgument(0), "token-stays-private", now, now.plusSeconds(300)));
        var client = IdpServiceOAuth2Client.createConfigured(manager, new IdpClientCredentialsRequestEntityConverter(),
                Clock.fixed(now, ZoneOffset.UTC), Duration.ofSeconds(60), registrations(registration()), authorizedClients,
                new TrustedIssuerRegistry(properties), properties, observation -> { throw new IllegalStateException("metrics down"); });
        clients.add(client);
        var request = request(REGISTRATION_ID, APP_ID, ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));
        assertThat(client.authorize(request).getTokenValue()).isEqualTo("token-stays-private");
        assertThat(client.authorize(request).getTokenValue()).isEqualTo("token-stays-private");
        client.invalidate(request);
        when(manager.authorize(any(OAuth2AuthorizeRequest.class))).thenThrow(new org.springframework.security.oauth2.core.OAuth2AuthorizationException(
                new org.springframework.security.oauth2.core.OAuth2Error("invalid_client")));
        assertThatThrownBy(() -> client.authorize(request)).isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class)
                .hasMessageContaining("invalid_client").hasMessageNotContaining("token-stays-private");
    }

    @Test
    void boundedAcquisitionLimitsUninterruptibleWorkAndDoesNotInheritRequestState() throws Exception {
        Instant now = Instant.parse("2026-10-10T00:00:00Z");
        var manager = mock(OAuth2AuthorizedClientManager.class);
        var authorizedClients = mock(OAuth2AuthorizedClientService.class);
        var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
        var inherited = new InheritableThreadLocal<String>(); inherited.set("request-private-sentinel");
        var observed = new AtomicReference<String>(); var virtual = new java.util.concurrent.atomic.AtomicBoolean();
        when(manager.authorize(any(OAuth2AuthorizeRequest.class))).thenAnswer(call -> {
            virtual.set(Thread.currentThread().isVirtual()); observed.set(inherited.get()); entered.countDown();
            while (release.getCount() != 0) {
                try { release.await(); } catch (InterruptedException ignored) { }
            }
            return authorizedClient(call.getArgument(0), "fixture-service-token", now, now.plusSeconds(300));
        });
        var client = newClient(manager, authorizedClients, Clock.fixed(now, ZoneOffset.UTC), Duration.ofSeconds(60),
                serviceProperties(), registrations(registration()));
        var request = request(REGISTRATION_ID, APP_ID, ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));
        try {
            for (int index = 0; index < 8; index++) {
                assertThatThrownBy(() -> client.authorizeBounded(request, ISSUER, Duration.ofMillis(80)))
                        .isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class)
                        .hasMessageContaining("authorization_timeout").hasNoCause();
                int active = index + 1;
                org.awaitility.Awaitility.await().atMost(Duration.ofSeconds(2)).untilAsserted(() ->
                        assertThat(client.boundedInFlight()).isEqualTo(active));
            }
            assertThat(entered.await(2, TimeUnit.SECONDS)).isTrue();
            assertThat(virtual).isTrue(); assertThat(observed.get()).isNull();
            assertThatThrownBy(() -> client.authorizeBounded(request, ISSUER, Duration.ofMillis(80)))
                    .isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class)
                    .hasMessageContaining("authorization_capacity").hasNoCause();
        } finally { release.countDown(); inherited.remove(); }
        org.awaitility.Awaitility.await().atMost(Duration.ofSeconds(5)).untilAsserted(() ->
                assertThat(client.authorizeBounded(request, ISSUER, Duration.ofSeconds(1)).getTokenValue()).isEqualTo("fixture-service-token"));
        verify(manager, times(1)).authorize(any(OAuth2AuthorizeRequest.class));
    }

    @Test
    void boundedIssuerMismatchAndInvalidationFailureExposeNoUnderlyingDetails() {
        Instant now = Instant.parse("2026-10-10T00:00:00Z");
        var manager = mock(OAuth2AuthorizedClientManager.class);
        var authorizedClients = mock(OAuth2AuthorizedClientService.class);
        var client = newClient(manager, authorizedClients, Clock.fixed(now, ZoneOffset.UTC), Duration.ofSeconds(60),
                serviceProperties(), registrations(registration()));
        var request = request(REGISTRATION_ID, APP_ID, ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));
        assertThatThrownBy(() -> client.authorizeBounded(request, "https://other.example", Duration.ofSeconds(1)))
                .isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class).hasNoCause();
        verify(manager, never()).authorize(any(OAuth2AuthorizeRequest.class));
        org.mockito.Mockito.doThrow(new IllegalStateException("private-detail-sentinel")).when(authorizedClients)
                .removeAuthorizedClient(any(), any());
        assertThatThrownBy(() -> client.invalidateBounded(request, ISSUER, Duration.ofSeconds(1)))
                .isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class).hasNoCause()
                .hasMessageNotContaining("private-detail-sentinel");
    }

    @Test
    void interruptedBoundedCallerKeepsItsInterruptAndReceivesASafeFailure() throws Exception {
        var manager = mock(OAuth2AuthorizedClientManager.class);
        var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
        when(manager.authorize(any(OAuth2AuthorizeRequest.class))).thenAnswer(call -> {
            entered.countDown();
            while (release.getCount() != 0) {
                try { release.await(); } catch (InterruptedException ignored) { }
            }
            throw new IllegalStateException("private-detail-sentinel");
        });
        var client = newClient(manager, mock(OAuth2AuthorizedClientService.class), Clock.systemUTC(), Duration.ofSeconds(60),
                serviceProperties(), registrations(registration()));
        var request = request(REGISTRATION_ID, APP_ID, ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));
        var error = new AtomicReference<Throwable>(); var interrupted = new java.util.concurrent.atomic.AtomicBoolean();
        Thread caller = Thread.ofPlatform().daemon().start(() -> {
            try { client.authorizeBounded(request, ISSUER, Duration.ofSeconds(5)); }
            catch (RuntimeException failure) { error.set(failure); interrupted.set(Thread.currentThread().isInterrupted()); }
        });
        try {
            assertThat(entered.await(2, TimeUnit.SECONDS)).isTrue(); caller.interrupt(); caller.join(2000);
            assertThat(caller.isAlive()).isFalse(); assertThat(interrupted).isTrue();
            assertThat(error.get()).isInstanceOf(IdpServiceOAuth2Client.IdpServiceAuthorizationException.class)
                    .hasMessageContaining("authorization_interrupted").hasNoCause().hasMessageNotContaining("private-detail-sentinel");
        } finally { release.countDown(); }
    }

    private static IdpServiceTokenRequest request(
            String registrationId,
            String appId,
            ServiceTokenContext context,
            String tenantId,
            Set<String> scopes
    ) {
        return request(registrationId, appId, RESOURCE, context, tenantId, scopes);
    }

    private static IdpServiceTokenRequest request(
            String registrationId,
            String appId,
            URI audience,
            ServiceTokenContext context,
            String tenantId,
            Set<String> scopes
    ) {
        return new IdpServiceTokenRequest(
                registrationId,
                appId,
                audience,
                context,
                tenantId,
                scopes
        );
    }

    private static ClientRegistration registration() {
        return registration(REGISTRATION_ID, ISSUER, CLIENT_ID);
    }

    private static ClientRegistration registration(String registrationId) {
        if (REGISTRATION_ID.equals(registrationId)) {
            return registration();
        }
        if (TENANT_REGISTRATION_A.equals(registrationId)) {
            return registration(registrationId, TENANT_ISSUER_A, "orders-key-a");
        }
        if (TENANT_REGISTRATION_B.equals(registrationId)) {
            return registration(registrationId, TENANT_ISSUER_B, "orders-key-b");
        }
        if ("untrusted".equals(registrationId)) {
            return registration(registrationId, "https://evil.example", "evil-key");
        }
        throw new IllegalArgumentException("test registration is unknown");
    }

    private static ClientRegistration registration(
            String registrationId,
            String issuer,
            String clientId) {
        return ClientRegistration.withRegistrationId(registrationId)
                .clientId(clientId)
                .clientSecret("orders-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .scope("orders:read", "orders:write")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .issuerUri(issuer)
                .tokenUri(issuer + "/oauth2/token")
                .build();
    }

    private IdpServiceOAuth2Client newClient(
            OAuth2AuthorizedClientManager manager,
            OAuth2AuthorizedClientService authorizedClients,
            Clock clock,
            Duration renewalSkew,
            IdpStarterProperties properties,
            ClientRegistrationRepository registrations) {
        IdpServiceOAuth2Client client = IdpServiceOAuth2Client.createConfigured(
                manager,
                new IdpClientCredentialsRequestEntityConverter(),
                clock,
                renewalSkew,
                registrations,
                authorizedClients,
                new TrustedIssuerRegistry(properties),
                properties);
        clients.add(client);
        return client;
    }

    private static ClientRegistrationRepository registrations(
            ClientRegistration... registrations) {
        Map<String, ClientRegistration> values = new LinkedHashMap<>();
        Arrays.stream(registrations).forEach(registration ->
                values.put(registration.getRegistrationId(), registration));
        return values::get;
    }

    private static IdpStarterProperties serviceProperties() {
        IdpStarterProperties properties = new IdpStarterProperties();
        properties.setIssuer(ISSUER);
        properties.setJwkSetUri(ISSUER + "/oauth2/jwks");
        properties.setResourceServerId("orders-resource");
        properties.setResourceUri(RESOURCE);
        properties.getServiceClient().setAppId(APP_ID);
        properties.getServiceClient().setRegistrationId(REGISTRATION_ID);
        properties.getServiceClient().getCredentialVersions()
                .put(REGISTRATION_ID, 7L);
        return properties;
    }

    private static IdpTransportBindingRegistry tokenBindings(long version) {
        return new IdpTransportBindingRegistry(List.of(new IdpTransportBindingVO("identity-token", version,
                URI.create(ISSUER), URI.create(ISSUER + "/oauth2/token"), RESOURCE, REGISTRATION_ID,
                IdpTransportBindingVO.Operation.TOKEN, "POST", "/oauth2/token", "permission-prod",
                "tianquan-shoubing-http", 18080, IdpTransportBindingVO.Transport.HTTP)));
    }

    private static IdpStarterProperties multiIssuerProperties(
            String issuerA,
            String issuerB) {
        IdpStarterProperties properties = new IdpStarterProperties();
        properties.setResourceServerId("orders-resource");
        properties.setResourceUri(RESOURCE);
        properties.getRevocation().setPrimaryEndpoint("rediss://redis.example:6379");
        properties.getRevocation().setEpoch("epoch-1");
        Map<String, TrustedIssuerSettings> issuers = new LinkedHashMap<>();
        issuers.put("tenant-1001-a", trustedIssuer(issuerA, "tenant:1001:a"));
        issuers.put("tenant-1001-b", trustedIssuer(issuerB, "tenant:1001:b"));
        properties.setTrustedIssuers(issuers);
        properties.getServiceClient().setAppId(APP_ID);
        properties.getServiceClient().setRegistrationId("orders-tenant-a");
        return properties;
    }

    private static TrustedIssuerSettings trustedIssuer(String issuer, String realmKey) {
        TrustedIssuerSettings settings = new TrustedIssuerSettings();
        settings.setIssuer(issuer);
        settings.setJwksUri(issuer + "/.well-known/jwks.json");
        settings.setRealmKey(realmKey);
        settings.setRealmType("TENANT");
        settings.setTenantId("1001");
        settings.setStatus("ACTIVE");
        settings.setTrustVersion(1L);
        return settings;
    }

    private static ServiceAuthorizationKey key(IdpServiceTokenRequest request) {
        return ServiceAuthorizationKey.from(request, ISSUER, CLIENT_ID, 7L);
    }

    private static OAuth2AuthorizedClient authorizedClient(
            OAuth2AuthorizeRequest request,
            String value,
            Instant issuedAt,
            Instant expiresAt) {
        return authorizedClient(request, registration(request.getClientRegistrationId()),
                value, issuedAt, expiresAt);
    }

    private static OAuth2AuthorizedClient authorizedClient(
            OAuth2AuthorizeRequest request,
            ClientRegistration registration,
            String value,
            Instant issuedAt,
            Instant expiresAt) {
        @SuppressWarnings("unchecked")
        Set<String> scopes = request.getAttribute("egon.tianquan-shoubing.scopes");
        OAuth2AccessToken token = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                value,
                issuedAt,
                expiresAt,
                scopes
        );
        return new OAuth2AuthorizedClient(
                registration,
                request.getPrincipal().getName(),
                token
        );
    }

    private static OAuth2AccessToken accessToken(String value, Instant issuedAt) {
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                value,
                issuedAt,
                issuedAt.plusSeconds(300),
                Set.of("orders:read", "orders:write"));
    }

    private static final class MutableClock extends Clock {

        private final AtomicReference<Instant> current;
        private final ZoneId zone;

        private MutableClock(Instant current) {
            this(current, ZoneOffset.UTC);
        }

        private MutableClock(Instant current, ZoneId zone) {
            this.current = new AtomicReference<>(current);
            this.zone = zone;
        }

        private void advance(Duration duration) {
            current.updateAndGet(value -> value.plus(duration));
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return new MutableClock(instant(), zone);
        }

        @Override
        public Instant instant() {
            return current.get();
        }
    }

}
