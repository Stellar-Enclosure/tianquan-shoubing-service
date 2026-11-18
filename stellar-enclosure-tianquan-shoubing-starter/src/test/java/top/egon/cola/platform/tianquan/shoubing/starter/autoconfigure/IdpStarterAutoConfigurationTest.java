package top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import io.grpc.ServerInterceptor;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicInteger;
import jakarta.validation.Validator;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import top.egon.cola.component.rpc.consumer.generic.RpcGenericInvocation;
import top.egon.cola.component.rpc.consumer.interceptor.RpcClientInvocation;
import top.egon.cola.component.rpc.consumer.reference.RpcServiceTargetVO;
import top.egon.cola.component.rpc.context.identity.RpcProcessIdentity;
import top.egon.cola.component.rpc.provider.server.RpcAdmissionIdentityResolver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.redisson.api.RedissonClient;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.webclient.autoconfigure.WebClientAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.web.reactive.function.client.WebClient;
import top.egon.cola.component.rpc.consumer.interceptor.RpcClientInterceptorFactory;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpClientCredentialsRequestEntityConverter;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingRegistry;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingVO;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingVO.Operation;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingVO.Transport;
import top.egon.cola.platform.tianquan.shoubing.starter.client.ServiceTokenWebClientConfiguration;
import top.egon.cola.platform.tianquan.shoubing.starter.security.CurrentIdentity;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpBearerAuthenticationFilter;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpJwtVerifier;
import top.egon.cola.platform.tianquan.shoubing.starter.security.ServiceScopeAuthorization;
import top.egon.cola.platform.tianquan.shoubing.starter.security.UserAccessTokenVerifier;
import top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcBearerServerInterceptor;
import top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcClientCredentialInterceptorFactory;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityOAuthClientStateReader;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityResourceServerStateReader;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static top.egon.cola.platform.tianquan.shoubing.starter.state.AuthorityTestFixture.settings;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClient;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClientResolver;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityProperties;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verify;
import static org.mockito.ArgumentMatchers.any;

class IdpStarterAutoConfigurationTest {

    @Test
    void explicitlyConfiguredAuditFailsClosedWhenHostDependenciesAreMissing() {
        new ApplicationContextRunner()
                .withUserConfiguration(IdpStarterAutoConfiguration.OAuthAuditConfiguration.class)
                .withPropertyValues(
                        "egon.cola.platform.tianquan.shoubing.audit.spool-directory=/tmp/owned-audit-fixture",
                        "egon.cola.platform.tianquan.shoubing.audit.hmac-key-file=/tmp/owned-audit-fixture/key")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasStackTraceContaining("tokenUsageAuditComponent")
                            .hasStackTraceContaining("IdentityAuthorityClientResolver");
                });
    }

    private final ApplicationContextRunner contextRunner =
            new ApplicationContextRunner()
                    .withConfiguration(AutoConfigurations.of(
                            IdpStarterAutoConfiguration.class, IdpSecurityObservationAutoConfiguration.class))
                    .withBean("jacksonObjectMapper", ObjectMapper.class, ObjectMapper::new)
                    .withBean("defaultValidator", Validator.class, LocalValidatorFactoryBean::new)
                    .withBean("registry", io.micrometer.core.instrument.MeterRegistry.class, io.micrometer.core.instrument.simple.SimpleMeterRegistry::new)
                    .withBean("identityAuthorityClientResolver", IdentityAuthorityClientResolver.class, () -> issuer -> top.egon.cola.platform.tianquan.shoubing.starter.state.AuthorityTestFixture.confirmingAuditClient())
                    .withPropertyValues(settings())
                    .withPropertyValues(
                            "egon.cola.platform.tianquan.shoubing.enabled=true",
                            "egon.cola.platform.tianquan.shoubing.issuer=https://tianquan-shoubing.local",
                            "egon.cola.platform.tianquan.shoubing.jwk-set-uri=https://tianquan-shoubing.local/oauth2/jwks",
                            "egon.cola.platform.tianquan.shoubing.resource-server-id=resource-tianquan-jianshen-prod",
                            "egon.cola.platform.tianquan.shoubing.resource-uri=https://api.example/prod/permission/tianquan-jianshen");

    @Test
    void configuredProjectionCannotFallBackToCanonicalHttpsWhenItsFileIsMissing(@TempDir Path directory) {
        contextRunner.withPropertyValues(
                        "egon.cola.platform.tianquan.shoubing.projection.jwks-file=" + directory.resolve("missing.json"))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasStackTraceContaining("IDP_PROJECTED_JWKS_UNAVAILABLE");
                });
    }

    @Test
    void productionProjectionRejectsUnknownSettingsAndMissingTrustRoot() {
        contextRunner.withPropertyValues("egon.cola.platform.tianquan.shoubing.projection.required=true")
                .run(context -> assertThat(context.getStartupFailure())
                        .hasStackTraceContaining("IDP_PROJECTED_JWKS_REQUIRED"));
        contextRunner.withPropertyValues("egon.cola.platform.tianquan.shoubing.projection.unrecognized=true")
                .run(context -> assertThat(context.getStartupFailure())
                        .hasStackTraceContaining("projection.unrecognized"));
    }

    @Test
    void sharedProjectionReaderFollowsKubernetesSymlinksOnlyInsideTheMount(@TempDir Path directory) throws Exception {
        Path mount = Files.createDirectory(directory.resolve("mounted"));
        Path version = Files.createDirectory(mount.resolve("..generation1"));
        Files.writeString(version.resolve("credentials.json"), "{}");
        Files.createSymbolicLink(mount.resolve("..data"), version.getFileName());
        Path projectedFile = Files.createSymbolicLink(mount.resolve("credentials.json"),
                Path.of("..data", "credentials.json"));
        assertThat(IdpProjectedFileComponent.read(projectedFile, 32)).isEqualTo(new byte[]{'{', '}'});
        assertThatThrownBy(() -> IdpProjectedFileComponent.read(projectedFile, 1))
                .isInstanceOf(IOException.class).hasMessage("IDP_PROJECTION_FILE_UNAVAILABLE");
        Path outside = Files.writeString(directory.resolve("outside.json"), "{}");
        Files.delete(mount.resolve("..data"));
        Files.createSymbolicLink(mount.resolve("..data"), outside.getParent());
        Files.move(outside, directory.resolve("credentials.json"));
        assertThatThrownBy(() -> IdpProjectedFileComponent.read(projectedFile, 32))
                .isInstanceOf(IOException.class).hasMessage("IDP_PROJECTION_FILE_UNAVAILABLE");
    }

    @Test
    void managedJwtDecoderUsesOnlyTheProjectedKeysAtThePublicIssuerIdentity(@TempDir Path directory) throws Exception {
        String issuer = "https://idp.example/tenants/1001";
        String jwks = issuer + "/.well-known/jwks.json";
        Instant now = Instant.now();
        RSAKey key = new RSAKeyGenerator(2048).algorithm(JWSAlgorithm.RS256).keyID("projection-key").generate();
        Path file = Files.writeString(directory.resolve("jwks.json"), """
                {"issuers":[{"issuer":"%s","jwksUri":"%s","trustVersion":1,
                  "validUntil":"%s","keys":[%s]}]}
                """.formatted(issuer, jwks, now.plusSeconds(300), key.toPublicJWK().toJSONString()));
        SignedJWT token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("at+jwt")).keyID(key.getKeyID()).build(),
                JWTClaimsSet.parse(Map.of("iss", issuer, "sub", "projected-client", "iat", now.getEpochSecond(),
                        "exp", now.plusSeconds(60L).getEpochSecond(), "jti", "projection-fixture")));
        token.sign(new RSASSASigner(key));

        contextRunner.withPropertyValues(
                        "egon.cola.platform.tianquan.shoubing.issuer=" + issuer,
                        "egon.cola.platform.tianquan.shoubing.jwk-set-uri=" + jwks,
                        "egon.cola.platform.tianquan.shoubing.projection.required=true",
                        "egon.cola.platform.tianquan.shoubing.projection.jwks-file=" + file)
                .run(context -> {
                    assertThat(context).hasNotFailed().hasBean("idpProjectedJwksTrustStore");
                    assertThat(context.getBean("idpJwtDecoder", JwtDecoder.class).decode(token.serialize()).getSubject())
                            .isEqualTo("projected-client");
                });
    }

    @Test
    void projectionOwnsActualServiceRegistrationAndDoesNotSelectThePublicEndpoint(@TempDir Path directory) throws Exception {
        String issuer = "https://idp.example/tenants/1001";
        URI endpoint = URI.create(issuer + "/oauth2/token");
        URI resource = URI.create("https://api.example/prod/permission/tianquan-jianshen");
        Path credentials = Files.writeString(directory.resolve("credentials.json"), """
                {"registrations":[{"registrationId":"orders","issuer":"%s","tokenUri":"%s",
                   "clientId":"orders-managed","clientSecret":"fixture-credential","credentialVersion":6}]}
                """.formatted(issuer, endpoint));
        IdpTransportBindingVO managed = new IdpTransportBindingVO("orders-token", 2L, URI.create(issuer), endpoint,
                resource, "orders", Operation.TOKEN, "POST", endpoint.getPath(), "identity", "issuer", 8080, Transport.HTTP);
        contextRunner.withBean("idpTransportBindingRegistry", IdpTransportBindingRegistry.class,
                        () -> new IdpTransportBindingRegistry(List.of(managed)))
                .withPropertyValues(
                        "egon.cola.platform.tianquan.shoubing.service-client.app-id=orders-app",
                        "egon.cola.platform.tianquan.shoubing.service-client.registration-id=orders",
                        "egon.cola.platform.tianquan.shoubing.projection.service-credentials-file=" + credentials)
                .run(context -> {
                    assertThat(context).hasNotFailed().hasBean("idpProjectedClientRuntime");
                    assertThat(context).doesNotHaveBean("idpOAuth2AuthorizedClientManager");
                    var client = context.getBean(IdpServiceOAuth2Client.class);
                    var request = new IdpServiceTokenRequest(
                            "orders", "orders-app", resource, ServiceTokenContext.TENANT, "1001", Set.of("orders:read"));
                    var authorization = client.authorizationKey(request);
                    assertThat(authorization.credentialVersion()).isEqualTo(6L);
                    assertThat(authorization.bindingId()).isEqualTo("orders-token");
                    assertThat(authorization.issuer()).isEqualTo(issuer);
                });
    }

    @Test
    void customNamedHostEndpointPolicyReplacesTheDefaultAndStillCreatesTheBearerFilter() {
        var policy = new top.egon.cola.platform.tianquan.shoubing.starter.security.IdpEndpointAuthenticationPolicy(
                List.of(), List.of("/internal/**"));
        contextRunner.withBean("customHostEndpointPolicy",
                        top.egon.cola.platform.tianquan.shoubing.starter.security.IdpEndpointAuthenticationPolicy.class,
                        () -> policy)
                .run(context -> {
                    assertThat(context).hasNotFailed().doesNotHaveBean("idpEndpointAuthenticationPolicy")
                            .hasSingleBean(IdpBearerAuthenticationFilter.class);
                    assertThat(context.getBean(top.egon.cola.platform.tianquan.shoubing.starter.security.IdpEndpointAuthenticationPolicy.class))
                            .isSameAs(policy);
                });
    }

    @Test
    void configuredRpcAndOldOverloadsUseNamedDependenciesWithoutAServiceClientForProviders() throws Exception {
        IdpRpcClientCredentialInterceptorFactory.class.getConstructor();
        IdpRpcBearerServerInterceptor.class.getConstructor(UserAccessTokenVerifier.class);
        var compatibility = new IdpStarterAutoConfiguration();
        assertThat(compatibility.idpRpcClientCredentialInterceptorFactory()).isNotNull();
        assertThat(compatibility.idpRpcBearerServerInterceptor(mock(UserAccessTokenVerifier.class))).isNotNull();
        contextRunner
                .withPropertyValues(providerSettings()).run(context -> {
                    assertThat(context).hasNotFailed().doesNotHaveBean(IdpServiceOAuth2Client.class);
                    assertThat(context).hasBean("idpRpcAdmissionIdentityResolver")
                            .hasSingleBean(RpcAdmissionIdentityResolver.class);
                    var interceptor = context.getBean("idpRpcBearerServerInterceptor", IdpRpcBearerServerInterceptor.class);
                    @SuppressWarnings("unchecked") ServerCall<String, String> call = mock(ServerCall.class);
                    var method = MethodDescriptor.<String, String>newBuilder().setType(MethodDescriptor.MethodType.UNARY)
                            .setFullMethodName("example.Inventory/Read").setRequestMarshaller(mock(MethodDescriptor.Marshaller.class))
                            .setResponseMarshaller(mock(MethodDescriptor.Marshaller.class)).build();
                    when(call.getMethodDescriptor()).thenReturn(method);
                    @SuppressWarnings("unchecked") ServerCallHandler<String, String> next = mock(ServerCallHandler.class);
                    interceptor.interceptCall(call, new Metadata(), next);
                    verifyNoInteractions(next);
                    verify(call).close(org.mockito.ArgumentMatchers.argThat(status -> status.getCode() == Status.Code.UNAUTHENTICATED), any());
                });
    }

    @Test
    void configuredConsumerRejectsWrongApplicationOrEnvironmentBeforeTokenAcquisition() {
        var client = mock(IdpServiceOAuth2Client.class);
        contextRunner
                .withBean("idpServiceOAuth2Client", IdpServiceOAuth2Client.class, () -> client)
                .withPropertyValues(consumerSettings()).run(context -> {
                    assertThat(context).hasNotFailed();
                    var factory = context.getBean("idpRpcClientCredentialInterceptorFactory", IdpRpcClientCredentialInterceptorFactory.class);
                    String method = "example.Inventory/Read";
                    var generic = new RpcGenericInvocation("inventory-native", "example.Inventory", "internal", "v1", method,
                            new byte[]{1}, 1000);
                    var target = new RpcServiceTargetVO("inventory-native", 2L, "workloads", "inventory-rpc", 9090, Set.of(method));
                    for (RpcProcessIdentity process : List.of(new RpcProcessIdentity("wrong-app", "test", "orders", 1, "test"),
                            new RpcProcessIdentity("orders", "wrong-env", "test", 1, "test"))) {
                        assertThatThrownBy(() -> factory.create(RpcClientInvocation.generic(generic, process, "call-1", target)))
                                .isInstanceOf(IllegalStateException.class);
                    }
                    verifyNoInteractions(client);
                });
    }

    @Test
    void enabledServiceConsumerNeedsItsActualOAuthClientAndValidatedBindings() {
        contextRunner
                .withPropertyValues(consumerSettings()).run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasStackTraceContaining("SERVICE RPC requires idpServiceOAuth2Client");
                });
        contextRunner
                .withBean("idpServiceOAuth2Client", IdpServiceOAuth2Client.class, () -> mock(IdpServiceOAuth2Client.class))
                .withPropertyValues(consumerSettings()).withPropertyValues("egon.cola.platform.tianquan.shoubing.rpc.consumer.bindings.inventory.scopes[0]=*")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void rpcUnknownKeysFailStrictBindingWithoutChangingObservationBinding() {
        contextRunner
                .withBean("idpServiceOAuth2Client", IdpServiceOAuth2Client.class, () -> mock(IdpServiceOAuth2Client.class))
                .withPropertyValues(consumerSettings())
                .withPropertyValues("egon.cola.platform.tianquan.shoubing.rpc.consumer.bindings.inventory.unknown-authority=grant")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasStackTraceContaining("unknown-authority");
                });
    }

    private String[] consumerSettings() {
        String prefix = "egon.cola.platform.tianquan.shoubing.rpc.consumer.bindings.inventory.";
        return new String[]{"egon.cola.platform.tianquan.shoubing.rpc.enabled=true", "egon.cola.platform.tianquan.shoubing.rpc.consumer.enabled=true",
                prefix + "service-name=example.Inventory", prefix + "group=internal", prefix + "version=v1", prefix + "full-method-name=example.Inventory/Read",
                prefix + "process-identity.applicationName=orders", prefix + "process-identity.env=test", prefix + "mode=SERVICE",
                prefix + "registration-id=inventory-client", prefix + "app-id=orders-app", prefix + "resource-uri=https://api.example/inventory",
                prefix + "scope-context=PLATFORM", prefix + "scopes[0]=inventory:read",
                prefix + "transport-binding-id=inventory-native", prefix + "transport-binding-version=2"};
    }

    private String[] providerSettings() {
        String prefix = "egon.cola.platform.tianquan.shoubing.rpc.provider.methods[example.Inventory/Read].";
        return new String[]{"egon.cola.platform.tianquan.shoubing.rpc.enabled=true", "egon.cola.platform.tianquan.shoubing.rpc.provider.enabled=true",
                prefix + "required=true", prefix + "principal-kind=SERVICE", prefix + "scope-context=TENANT", prefix + "required-scopes[0]=inventory:read",
                prefix + "expected-resource-uri=https://api.example/inventory"};
    }

    @Test
    void registersServiceTokenConfigurationAfterItsBeanDependencies() throws IOException {
        String resource = "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports";
        try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
            assertThat(input).isNotNull();
            String imports = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            String autoConfiguration = ServiceTokenWebClientConfiguration.class.getName();
            assertThat(imports.lines().filter(autoConfiguration::equals).count())
                    .isEqualTo(1L);
        }
        AutoConfigureAfter order = ServiceTokenWebClientConfiguration.class
                .getAnnotation(AutoConfigureAfter.class);
        assertThat(order.value()).contains(
                IdpStarterAutoConfiguration.class,
                WebClientAutoConfiguration.class);
    }

    @Test
    void formalAuditConstructorRequiresTheAuthorityPortAndHasNoRedisAdapter() throws Exception {
        var type = top.egon.cola.platform.tianquan.shoubing.starter.audit.TokenUsageAuditComponent.class;
        type.getConstructor(IdentityAuthorityClientResolver.class, java.time.Clock.class, Validator.class,
                top.egon.cola.platform.tianquan.shoubing.core.observability.IdpSecurityMetricsRecorder.class);
        assertThat(java.util.Arrays.stream(type.getConstructors()).flatMap(constructor -> java.util.Arrays.stream(constructor.getParameterTypes())))
                .noneMatch(RedissonClient.class::equals);
        contextRunner.run(context -> assertThat(context).hasNotFailed().doesNotHaveBean("idpAuditRedissonClient")
                .doesNotHaveBean("idpAuditSpoolLease"));
    }

    @Test
    void providesIdentityOnlyFilterBeforeRbac3Filter() {
        contextRunner.run(context -> {
            assertThat(context).doesNotHaveBean(IdentityResourceServerStateReader.class);
            assertThat(context).doesNotHaveBean(IdentityOAuthClientStateReader.class);
            assertThat(context).hasSingleBean(IdpJwtVerifier.class);
            assertThat(context).hasSingleBean(CurrentIdentity.class);
            assertThat(context).hasSingleBean(IdpBearerAuthenticationFilter.class);
            assertThat(context).hasSingleBean(ServiceScopeAuthorization.class);
            assertThat(context).hasSingleBean(
                    IdpRpcClientCredentialInterceptorFactory.class
            );
            assertThat(context).hasSingleBean(
                    IdpRpcBearerServerInterceptor.class
            );
            assertThat(context).doesNotHaveBean("idpRpcAdmissionIdentityResolver");
            assertThat(context.getBeansOfType(
                    RpcClientInterceptorFactory.class
            ).values()).anyMatch(
                    IdpRpcClientCredentialInterceptorFactory.class::isInstance
            );
            assertThat(context.getBeansOfType(
                    ServerInterceptor.class
            ).values()).anyMatch(
                    IdpRpcBearerServerInterceptor.class::isInstance
            );
            FilterRegistrationBean<?> registration = context.getBean(
                    "idpBearerFilterRegistration",
                    FilterRegistrationBean.class);
            assertThat(registration.getOrder()).isEqualTo(-102);
        });
    }

    @Test
    void honorsRpcSecurityAdapterOverrides() {
        IdpRpcClientCredentialInterceptorFactory client =
                new IdpRpcClientCredentialInterceptorFactory();
        IdpRpcBearerServerInterceptor server =
                new IdpRpcBearerServerInterceptor(
                        mock(UserAccessTokenVerifier.class)
                );

        contextRunner
                .withBean(
                        IdpRpcClientCredentialInterceptorFactory.class,
                        () -> client
                )
                .withBean(
                        IdpRpcBearerServerInterceptor.class,
                        () -> server
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(
                            IdpRpcClientCredentialInterceptorFactory.class
                    );
                    assertThat(context).hasSingleBean(
                            IdpRpcBearerServerInterceptor.class
                    );
                    assertThat(context.getBean(
                            IdpRpcClientCredentialInterceptorFactory.class
                    )).isSameAs(client);
                    assertThat(context.getBean(
                            IdpRpcBearerServerInterceptor.class
                    )).isSameAs(server);
                });
    }

    @Test
    void remainsDisabledByDefault() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        IdpStarterAutoConfiguration.class, IdpSecurityObservationAutoConfiguration.class))
                .run(context -> {
                    assertThat(context).doesNotHaveBean(IdpJwtVerifier.class);
                    assertThat(context).doesNotHaveBean(
                            IdpRpcClientCredentialInterceptorFactory.class
                    );
                    assertThat(context).doesNotHaveBean(
                            IdpRpcBearerServerInterceptor.class
                    );
                });
    }

    @Test
    void localAuthorityAdapterDoesNotNeedAnHttpServiceClient() {
        contextRunner.run(context -> assertThat(context).hasNotFailed().hasSingleBean(IdpJwtVerifier.class)
                .doesNotHaveBean(IdpServiceOAuth2Client.class));
    }

    @Test
    void bindsOneNamedDeploymentRegistryAndRejectsUnknownTransportFields() {
        String prefix = "egon.cola.platform.tianquan.shoubing.transport.bindings.orders-token.";
        var configured = contextRunner.withPropertyValues(
                prefix + "version=2", prefix + "canonical-issuer=https://identity.example/tenant",
                prefix + "canonical-endpoint=https://identity.example/oauth2/token",
                prefix + "resource=https://orders.example", prefix + "registration-id=orders",
                prefix + "operation=TOKEN", prefix + "method=POST", prefix + "path=/oauth2/token",
                prefix + "namespace=identity", prefix + "service=token", prefix + "port=18080",
                prefix + "transport=HTTP");
        configured.run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(IdpTransportBindingRegistry.class);
            var registry = context.getBean("idpTransportBindingRegistry", IdpTransportBindingRegistry.class);
            assertThat(registry.select(URI.create("https://identity.example/tenant"),
                    URI.create("https://identity.example/oauth2/token"), URI.create("https://orders.example"),
                    "orders", Operation.TOKEN, "POST")).hasValueSatisfying(binding -> {
                        assertThat(binding.physicalUri().toString())
                                .isEqualTo("http://token.identity.svc.cluster.local:18080/oauth2/token");
                        assertThat(binding.version()).isEqualTo(2L);
                    });
        });
        configured.withPropertyValues(prefix + "untrusted-target=http://arbitrary.invalid")
                .run(context -> assertThat(context).hasFailed().getFailure().hasStackTraceContaining("untrusted-target"));
    }

    @Test
    void actualTokenManagerPreservesBasicAndFormAndRejectsRedirectAndOversizeResponse() throws IOException {
        var fixture = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        var payload = new AtomicReference<String>();
        var auth = new AtomicReference<String>();
        var calls = new AtomicInteger();
        var redirects = new AtomicInteger();
        fixture.createContext("/elsewhere", exchange -> {
            redirects.incrementAndGet();
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        fixture.createContext("/oauth2/token", exchange -> {
            try (exchange) {
                auth.set(exchange.getRequestHeaders().getFirst("Authorization"));
                payload.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                int request = calls.incrementAndGet();
                if (request == 2) {
                    exchange.getResponseHeaders().set("Location", "/elsewhere");
                    exchange.sendResponseHeaders(302, -1);
                    return;
                }
                if (request == 4) {
                    byte[] invalidScope = "{\"error\":\"invalid_scope\",\"error_description\":\"fixture-private-error\"}"
                            .getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(400, invalidScope.length);
                    exchange.getResponseBody().write(invalidScope);
                    return;
                }
                byte[] bytes = request == 1
                        ? "{\"access_token\":\"fixture-token\",\"token_type\":\"Bearer\",\"expires_in\":300}"
                                .getBytes(StandardCharsets.UTF_8)
                        : new byte[64 * 1024 + 1];
                exchange.sendResponseHeaders(200, bytes.length);
                exchange.getResponseBody().write(bytes);
            }
        });
        fixture.start();
        try {
            URI loopback = URI.create("http://127.0.0.1:" + fixture.getAddress().getPort() + "/oauth2/token");
            URI canonicalIssuer = URI.create("https://identity.example.invalid");
            URI canonicalEndpoint = canonicalIssuer.resolve("/oauth2/token");
            URI resource = URI.create("https://orders.example");
            var registration = ClientRegistration.withRegistrationId("local-orders")
                    .clientId("fixture-client").clientSecret("fixture-secret")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .issuerUri(canonicalIssuer.toASCIIString()).tokenUri(canonicalEndpoint.toASCIIString()).build();
            var registrations = new InMemoryClientRegistrationRepository(registration);
            var properties = new IdpStarterProperties();
            properties.getServiceClient().setAppId("orders");
            properties.getServiceClient().setRegistrationId("local-orders");
            properties.getServiceClient().setCredentialVersions(java.util.Map.of("local-orders", 1L));
            var binding = new IdpTransportBindingVO("test-token", 1L, canonicalIssuer,
                    canonicalEndpoint, resource, "local-orders", Operation.TOKEN, "POST",
                    "/oauth2/token", "identity", "token", 18080, Transport.HTTP);
            // Only the test fixture substitutes the listener. The real converter must select the exact Service first.
            var converter = new IdpClientCredentialsRequestEntityConverter(
                    new IdpTransportBindingRegistry(List.of(binding))) {
                @Override
                public RequestEntity<?> convert(OAuth2ClientCredentialsGrantRequest grant) {
                    var request = super.convert(grant);
                    assertThat(request.getUrl()).isEqualTo(binding.physicalUri());
                    return new RequestEntity<>(request.getBody(), request.getHeaders(), request.getMethod(), loopback);
                }
            };
            var manager = new IdpStarterAutoConfiguration().idpOAuth2AuthorizedClientManager(
                    registrations, new InMemoryOAuth2AuthorizedClientService(registrations),
                    converter, properties, new IdentityAuthorityProperties());

            converter.bind(resource, ServiceTokenContext.TENANT, "41", java.util.Set.of("orders:read"));
            try {
                assertThat(manager.authorize(OAuth2AuthorizeRequest.withClientRegistrationId("local-orders")
                        .principal("valid-principal").build()).getAccessToken().getTokenValue()).isEqualTo("fixture-token");
                assertThat(auth.get()).startsWith("Basic ");
                assertThat(payload.get()).contains("grant_type=client_credentials",
                        "resource=https%3A%2F%2Forders.example", "tenant_id=41", "scope=orders%3Aread");
                assertThatThrownBy(() -> manager.authorize(OAuth2AuthorizeRequest.withClientRegistrationId("local-orders")
                        .principal("redirect-principal").build())).isInstanceOf(OAuth2AuthorizationException.class);
                assertThatThrownBy(() -> manager.authorize(OAuth2AuthorizeRequest.withClientRegistrationId("local-orders")
                        .principal("oversize-principal").build())).isInstanceOf(OAuth2AuthorizationException.class);
                assertThatThrownBy(() -> manager.authorize(OAuth2AuthorizeRequest.withClientRegistrationId("local-orders")
                        .principal("invalid-scope-principal").build()))
                        .isInstanceOfSatisfying(OAuth2AuthorizationException.class, failure -> {
                            assertThat(failure.getError().getErrorCode()).isEqualTo("invalid_scope");
                            assertThat(failure.getError().getDescription()).isNull();
                        });
            } finally {
                converter.clear();
            }
            assertThat(calls).hasValue(4);
            assertThat(redirects).hasValue(0);
        } finally {
            fixture.stop(0);
        }
    }

    @Test
    void providesServiceClientWhenRegistrationIsConfigured() {
        ClientRegistration registration = ClientRegistration
                .withRegistrationId("egon-tianquan-shoubing")
                .clientId("orders-key")
                .clientSecret("orders-secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenUri("https://tianquan-shoubing.local/oauth2/token")
                .issuerUri("https://tianquan-shoubing.local")
                .build();
        var serviceClientRunner = new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        IdpStarterAutoConfiguration.class,
                        IdpSecurityObservationAutoConfiguration.class,
                        ServiceTokenWebClientConfiguration.class))
                .withBean("jacksonObjectMapper", ObjectMapper.class, ObjectMapper::new)
                .withBean("defaultValidator", Validator.class, LocalValidatorFactoryBean::new)
                .withBean("registry", io.micrometer.core.instrument.MeterRegistry.class, io.micrometer.core.instrument.simple.SimpleMeterRegistry::new)
                .withBean("identityAuthorityClientResolver", IdentityAuthorityClientResolver.class, () -> issuer -> top.egon.cola.platform.tianquan.shoubing.starter.state.AuthorityTestFixture.confirmingAuditClient())
                .withPropertyValues(settings())
                .withBean(ClientRegistrationRepository.class,
                        () -> new InMemoryClientRegistrationRepository(
                                registration))
                .withBean(WebClient.Builder.class, WebClient::builder)
                .withPropertyValues(
                        "egon.cola.platform.tianquan.shoubing.enabled=true",
                        "egon.cola.platform.tianquan.shoubing.issuer=https://tianquan-shoubing.local",
                        "egon.cola.platform.tianquan.shoubing.jwk-set-uri=https://tianquan-shoubing.local/oauth2/jwks",
                        "egon.cola.platform.tianquan.shoubing.resource-server-id=rs-tianquan-shoubing-prod",
                        "egon.cola.platform.tianquan.shoubing.resource-uri=https://api.example/tianquan-shoubing",
                        "egon.cola.platform.tianquan.shoubing.service-client.app-id=orders-app",
                        "egon.cola.platform.tianquan.shoubing.service-client.registration-id=egon-tianquan-shoubing",
                        "egon.cola.platform.tianquan.shoubing.service-client.credential-versions.egon-tianquan-shoubing=8");
        serviceClientRunner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(OAuth2AuthorizedClientManager.class);
            assertThat(context).hasSingleBean(IdpServiceOAuth2Client.class);
            assertThat(context).hasBean("serviceTokenWebClient");
            assertThat(context.getBean("idpStarterProperties", IdpStarterProperties.class)
                    .getServiceClient().getCredentialVersions()).containsEntry("egon-tianquan-shoubing", 8L);
        });
        var bootService = new org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService(
                new InMemoryClientRegistrationRepository(registration));
        serviceClientRunner.withBean("authorizedClientService",
                        org.springframework.security.oauth2.client.OAuth2AuthorizedClientService.class, () -> bootService)
                .run(context -> {
                    assertThat(context).hasNotFailed().hasSingleBean(IdpServiceOAuth2Client.class);
                    assertThat(context).doesNotHaveBean("idpOAuth2AuthorizedClientService");
                    assertThat(context.getBean(org.springframework.security.oauth2.client.OAuth2AuthorizedClientService.class))
                            .isSameAs(bootService);
                });
    }

    @Test
    void rejectsLegacyPrivateKeyAndAdmissionProperties() {
        contextRunner.withPropertyValues("egon.cola.platform.tianquan.shoubing.admission.private-key-path=/run/secrets/controlled.pem")
                .run(context -> assertThat(context).hasFailed().getFailure().hasStackTraceContaining("migration required")
                        .hasStackTraceContaining("admission.private-key-path").hasMessageNotContaining("/run/secrets/controlled.pem"));
    }

    @Test
    void decoderAcceptsAccessTokenTypeValidatedByIdpVerifier()
            throws Exception {
        RSAKey key = new RSAKeyGenerator(2048)
                .keyID("tianquan-shoubing-local")
                .algorithm(JWSAlgorithm.RS256)
                .generate();
        byte[] jwkSet = ("{\"keys\":["
                + key.toPublicJWK().toJSONString()
                + "]}").getBytes(StandardCharsets.UTF_8);
        HttpServer server = HttpServer.create(
                new InetSocketAddress("127.0.0.1", 0),
                0
        );
        server.createContext("/oauth2/jwks", exchange -> {
            exchange.getResponseHeaders().add(
                    "Content-Type",
                    "application/json"
            );
            exchange.sendResponseHeaders(200, jwkSet.length);
            exchange.getResponseBody().write(jwkSet);
            exchange.close();
        });
        server.start();
        try {
            String issuer = "http://127.0.0.1:" + server.getAddress().getPort();
            String resource = "https://api.example/local/permission/tianquan-jianshen";
            IdpStarterProperties properties = new IdpStarterProperties();
            properties.setEnabled(true);
            properties.setIssuer(issuer);
            properties.setJwkSetUri(issuer + "/oauth2/jwks");
            properties.setResourceServerId("permission-tianquan-jianshen-local");
            properties.setResourceUri(URI.create(resource));
            JwtDecoder decoder = new IdpStarterAutoConfiguration()
                    .idpJwtDecoder(properties);
            Instant now = Instant.now();
            SignedJWT token = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .type(new JOSEObjectType("at+jwt"))
                            .keyID("tianquan-shoubing-local")
                            .build(),
                    JWTClaimsSet.parse(java.util.Map.of("iss", issuer, "sub", "tianquan-shoubing-service",
                            "aud", List.of(resource), "iat", now.getEpochSecond(), "nbf", now.getEpochSecond(),
                            "exp", now.plusSeconds(60).getEpochSecond(), "jti", "token-1"))
            );
            token.sign(new RSASSASigner(key));

            assertThat(decoder.decode(token.serialize()).getSubject())
                    .isEqualTo("tianquan-shoubing-service");
        } finally {
            server.stop(0);
        }
    }

}
