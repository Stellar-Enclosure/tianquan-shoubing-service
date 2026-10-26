package top.egon.cola.platform.tianquan.shoubing.admin.support.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClient;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClientResolver;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuditReceipt;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditFingerprint;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpSecurityObservationAutoConfiguration;
import top.egon.cola.platform.tianquan.shoubing.starter.observability.IdpSecurityMetricsComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.observability.IdpSecurityObservationReceiverEnum;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.match.MockRestRequestMatchers;
import org.springframework.test.web.client.response.MockRestResponseCreators;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.web.client.RestTemplate;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditEvent;
import top.egon.cola.platform.tianquan.shoubing.core.observability.SecurityMetricObservationBO;
import top.egon.cola.platform.tianquan.shoubing.starter.audit.OAuthUsageObservationProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.audit.TokenUsageAuditComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TenantIssuerAuthenticationManagerComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TrustedIssuerRegistry;

/** Actual SDK emitters and host registry wiring, with controlled infrastructure and time. */
class TianquanSecurityMetricsContractTest {
    @Test
    @SuppressWarnings("unchecked")
    void scopeDenyOnceAndMetricsBeforeTheActualAdministrationPdp() throws Exception {
        var events = new java.util.ArrayList<Map<String, String>>();
        var authority = recordingAuthority(events);
        var converter = (top.egon.cola.platform.tianquan.shoubing.starter.security.domain.converter.TokenUsageAuditEventConverter)
                Class.forName("top.egon.cola.platform.tianquan.shoubing.starter.security.domain.converter.TokenUsageAuditEventConverterImpl").getConstructor().newInstance();
        var observer = new top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent(producer(authority, metrics), converter,
                new OAuthUsageObservationProperties(true, ISSUER, false, IdpSecurityObservationReceiverEnum.SHOUBING), metrics, Clock.fixed(NOW, ZoneOffset.UTC), validator, RESOURCE);
        var identity = new top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal("10001", "1001", "901", Set.of(RESOURCE.toASCIIString()),
                NOW, NOW.plusSeconds(300), top.egon.cola.platform.tianquan.shoubing.contract.AuthenticationContext.password());
        var snapshot = new top.egon.cola.platform.tianquan.jianshen.contract.authorization.SystemAuthorizationSnapshot("1001", "10001", "20001", "shoubing", 1, 2,
                java.util.List.of("50001"), null, null, Set.of("tianquan-shoubing:audit:read"), Set.of(), Map.of(), Map.of(), "sha256:scope", NOW, NOW.plusSeconds(300));
        var fine = org.mockito.Mockito.spy(new top.egon.cola.platform.tianquan.jianshen.starter.authorization.DefaultAuthorizationService(
                () -> new top.egon.cola.platform.tianquan.jianshen.starter.authorization.AuthorizationService.RuntimeAuthorizationContext(identity, snapshot, false),
                request -> top.egon.cola.platform.tianquan.jianshen.starter.authorization.AuthorizationService.OperationSodResult.allowed(),
                request -> top.egon.cola.platform.tianquan.jianshen.starter.authorization.AuthorizationService.FenceResult.allowed(NOW), Clock.fixed(NOW, ZoneOffset.UTC)));
        var beans = new org.springframework.beans.factory.support.DefaultListableBeanFactory(); beans.registerSingleton("authorizationService", fine);
        var policy = new top.egon.cola.platform.tianquan.jianshen.starter.autoconfigure.Rbac3StarterProperties();
        policy.getUserScopePolicy().setEnabled(true).setPermissionScopes(Map.of("tianquan-shoubing:audit:read", Set.of("tianquan-shoubing:audit:read")));
        var port = new IdpSecurityConfig().idpAdminAuthorizationPort(beans.getBeanProvider(top.egon.cola.platform.tianquan.jianshen.starter.authorization.AuthorizationService.class),
                policy, observer, metrics, validator);
        var proof = new top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO(ISSUER, RESOURCE, "a".repeat(64), "b".repeat(64), "c".repeat(64));
        var request = new org.springframework.mock.web.MockHttpServletRequest("GET", "/api/v1/tianquan-shoubing/audits");
        var response = new org.springframework.mock.web.MockHttpServletResponse();
        var authentication = new top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken(identity); authentication.setDetails(proof);
        org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(authentication);
        try {
            new top.egon.cola.platform.tianquan.shoubing.starter.security.IdpSecurityObservationFilter(observer,
                    new top.egon.cola.platform.tianquan.shoubing.starter.security.IdpEndpointAuthenticationPolicy()).doFilter(request, response, (incoming, outgoing) -> {
                        org.springframework.web.context.request.RequestContextHolder.setRequestAttributes(new org.springframework.web.context.request.ServletRequestAttributes(request));
                        assertThatThrownBy(() -> port.require(identity, "tianquan-shoubing:audit:read")).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
                        assertThat(top.egon.cola.platform.tianquan.shoubing.starter.security.IdpSecurityObservationFilter.beforeAuthorizationDenied(request)).isTrue();
                    });
        } finally { org.springframework.web.context.request.RequestContextHolder.resetRequestAttributes(); org.springframework.security.core.context.SecurityContextHolder.clearContext(); }
        assertThat(events).hasSize(1).allSatisfy(event -> assertThat(event).containsEntry("result", "DENIED"));
        org.mockito.Mockito.verify(fine, org.mockito.Mockito.never()).requirePermission(any());
        assertThat(registry.get("rbac.authorization").tags("receiver", RECEIVER, "result", "DENY").counter().count()).isEqualTo(1);
        doThrow(new IllegalStateException("controlled SQL unavailable")).when(authority).appendAudit(any());
        var failedRequest = new org.springframework.mock.web.MockHttpServletRequest("GET", "/scope-failure-fixture");
        org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(authentication);
        try {
            new top.egon.cola.platform.tianquan.shoubing.starter.security.IdpSecurityObservationFilter(observer,
                    new top.egon.cola.platform.tianquan.shoubing.starter.security.IdpEndpointAuthenticationPolicy())
                    .doFilter(failedRequest, new org.springframework.mock.web.MockHttpServletResponse(), (incoming, outgoing) -> {
                        org.springframework.web.context.request.RequestContextHolder.setRequestAttributes(new org.springframework.web.context.request.ServletRequestAttributes(failedRequest));
                        assertThatThrownBy(() -> port.require(identity, "tianquan-shoubing:audit:read")).isInstanceOfSatisfying(
                                top.egon.cola.platform.tianquan.jianshen.starter.authorization.AuthorizationService.RuntimeUnavailableException.class,
                                failure -> assertThat(failure.reasonCode()).isEqualTo("OAUTH_AUDIT_DELIVERY_UNAVAILABLE"));
                        assertThat(top.egon.cola.platform.tianquan.shoubing.starter.security.IdpSecurityObservationFilter.authorizationObservationContext(failedRequest).isFailed()).isTrue();
                        assertThat(top.egon.cola.platform.tianquan.shoubing.starter.security.IdpSecurityObservationFilter.beforeAuthorizationDenied(failedRequest)).isFalse();
                    });
        } finally { org.springframework.web.context.request.RequestContextHolder.resetRequestAttributes(); org.springframework.security.core.context.SecurityContextHolder.clearContext(); }

    }
    private static final String RECEIVER = "SHOUBING";
    private static final URI ISSUER = URI.create("https://idp.example/tenants/1001");
    private static final URI RESOURCE = URI.create("https://api.example/orders");
    private static final Instant NOW = Instant.parse("2026-10-10T00:00:00Z");
    @TempDir Path temporary;
    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    private final LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
    private IdpSecurityMetricsComponent metrics;

    @BeforeEach void prepare() { validator.afterPropertiesSet(); metrics = new IdpSecurityMetricsComponent(() -> registry, validator, new OAuthUsageObservationProperties(true, ISSUER, false, IdpSecurityObservationReceiverEnum.SHOUBING)); }

    @Test
    void realCryptoAndJwkCacheProduceTheHostMetersWithoutIdentityTags() throws Exception {
        var properties = new IdpStarterProperties();
        properties.setResourceServerId("orders-resource"); properties.setResourceUri(RESOURCE);
        properties.getRevocation().setPrimaryEndpoint("rediss://redis.example:6379"); properties.getRevocation().setEpoch("epoch-1");
        var trusted = new IdpStarterProperties.TrustedIssuerSettings();
        trusted.setIssuer(ISSUER.toASCIIString()); trusted.setJwksUri(ISSUER + "/.well-known/jwks.json");
        trusted.setRealmKey("tenant:1001"); trusted.setRealmType("TENANT"); trusted.setTenantId("1001"); trusted.setStatus("ACTIVE"); trusted.setTrustVersion(1);
        properties.setTrustedIssuers(Map.of("tenant-1001", trusted));
        var managers = new TenantIssuerAuthenticationManagerComponent(new TrustedIssuerRegistry(properties), properties,
                Clock.fixed(NOW, ZoneOffset.UTC), metrics);
        managers.initialize();
        var field = TenantIssuerAuthenticationManagerComponent.class.getDeclaredField("jwksRestOperations"); field.setAccessible(true);
        var server = MockRestServiceServer.bindTo((RestTemplate) field.get(managers)).build();
        var key = new RSAKeyGenerator(2048).keyID("key-1").algorithm(JWSAlgorithm.RS256).generate();
        server.expect(ExpectedCount.once(), MockRestRequestMatchers.requestTo(ISSUER + "/.well-known/jwks.json"))
                .andRespond(MockRestResponseCreators.withSuccess(new JWKSet(key.toPublicJWK()).toString(), MediaType.APPLICATION_JSON));
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", ISSUER.toASCIIString()); claims.put("sub", "subject-1001"); claims.put("aud", RESOURCE.toASCIIString());
        claims.put("iat", NOW.minusSeconds(1).getEpochSecond()); claims.put("nbf", NOW.minusSeconds(1).getEpochSecond());
        claims.put("exp", NOW.plusSeconds(300).getEpochSecond()); claims.put("jti", "901"); claims.put("tenant_id", "1001");
        claims.put("principal_type", "USER"); claims.put("scope_context", "TENANT");
        claims.put("authorization_id", "801"); claims.put("client_registration_id", "501");
        claims.put("security_version", Map.of("realm", 1L, "client", 2L, "subject", 3L));
        var token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("key-1").type(new JOSEObjectType("at+jwt")).build(), JWTClaimsSet.parse(claims));
        token.sign(new RSASSASigner(key));
        managers.authenticate(token.serialize()); managers.authenticate(token.serialize());
        assertThat(registry.find("jwt.verify.duration").tags("receiver", RECEIVER, "result", "SUCCESS").timer()).isNotNull();
        assertThat(registry.get("jwt.verify.duration").tags("receiver", RECEIVER, "result", "SUCCESS").timer().count()).isEqualTo(2);
        assertThat(registry.get("jwks.cache.access").tags("receiver", RECEIVER, "result", "MISS").counter().count()).isGreaterThan(0);
        assertThat(registry.getMeters()).allSatisfy(meter -> assertThat(meter.getId().getTags())
                .allSatisfy(tag -> assertThat(tag.getKey()).isIn("receiver", "result")));
        server.verify();
    }

    @Test
    void sqlConfirmedHandoffEmitsDeliveryAndReceiptAgeWithoutSpoolMeters() throws Exception {
        var authority = recordingAuthority(new java.util.ArrayList<>());
        var producer = producer(authority, metrics);
        var event = new TokenUsageAuditEvent("metric-event", 1, ISSUER, RESOURCE.toASCIIString(), null, null, null,
                "SUCCESS", "TOKEN_USE_VERIFIED", NOW.minusSeconds(5), null);
        assertThat(producer.appendStrict(event).outcome()).isEqualTo("STORED");
        assertThat(registry.get("oauth.audit.delivery").tags("receiver", RECEIVER, "result", "CONFIRMED").counter().count()).isEqualTo(1);
        assertThat(registry.get("receipt.age").tags("receiver", RECEIVER, "result", "CONFIRMED").timer().count()).isEqualTo(1);
        assertThat(registry.find("spool.bytes").gauge()).isNull();
        assertThat(Files.exists(temporary.resolve("spool"))).isFalse();
    }

    @Test
    void rejectsUnsupportedMetricSchemaRatherThanRegisteringAnArbitraryMeter() {
        assertThatThrownBy(() -> metrics.record(SecurityMetricObservationBO.builder().signal("caller.unbounded")
                .result("tenant-1001").duration(Duration.ofNanos(-1)).value(-1).build()))
                .isInstanceOf(jakarta.validation.ConstraintViolationException.class);
        assertThat(registry.getMeters()).isEmpty();
    }

    @Test
    void enabledHostRequiresARegistryAndUsesTheExistingPrimaryWithoutCreatingAnother() throws Exception {
        new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(IdpSecurityObservationAutoConfiguration.class))
                .withUserConfiguration(TianquanSecurityObservationConfiguration.class)
                .withPropertyValues("egon.cola.platform.tianquan.shoubing.usage-observation.enabled=true")
                .withBean("defaultValidator", jakarta.validation.Validator.class, () -> validator)
                .run(context -> assertThat(context).hasFailed());
        var secondary = new SimpleMeterRegistry();
        var props = new OAuthUsageObservationProperties(true, ISSUER, false).setReceiver(IdpSecurityObservationReceiverEnum.SHOUBING);
        var producer = producer(recordingAuthority(new java.util.ArrayList<>()), metrics);
        new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(IdpSecurityObservationAutoConfiguration.class))
                .withUserConfiguration(TianquanSecurityObservationConfiguration.class)
                .withPropertyValues("egon.cola.platform.tianquan.shoubing.usage-observation.enabled=true")
                .withPropertyValues(secureProperties())
                .withBean("identityAuthorityClientResolver", IdentityAuthorityClientResolver.class,
                        () -> issuer -> recordingAuthority(new java.util.ArrayList<>()))
                .withBean("trustedIssuerRegistry", TrustedIssuerRegistry.class, this::trustedRegistry)
                .withBean("primary", MeterRegistry.class, () -> registry, definition -> definition.setPrimary(true))
                .withBean("secondary", MeterRegistry.class, () -> secondary)
                .withBean("defaultValidator", jakarta.validation.Validator.class, () -> validator)
                .withBean("tokenUsageAuditComponent", TokenUsageAuditComponent.class, () -> producer)
                .withBean("oauthUsageObservationProperties", OAuthUsageObservationProperties.class, () -> props)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBeansOfType(MeterRegistry.class)).hasSize(2);
                    assertThat(context).hasSingleBean(TokenUsageAuditComponent.class);
                    @SuppressWarnings("unchecked") java.util.function.Supplier<MeterRegistry> selected =
                            (java.util.function.Supplier<MeterRegistry>) context.getBean("idpMeterRegistrySupplier");
                    assertThat(selected.get()).isSameAs(registry);
                });
    }

    @Test
    void fixedStrategyTableHandlesSqlAuthoritySignals() {
        for (String signal : java.util.List.of("jwt.verify.duration", "token.acquire.duration", "receipt.age")) {
            metrics.record(SecurityMetricObservationBO.builder().signal(signal)
                    .result(signal.equals("receipt.age") ? "CONFIRMED" : "SUCCESS").duration(Duration.ofMillis(1)).build());
        }
        for (String signal : java.util.List.of("jwks.cache.access", "token.cache.access")) {
            metrics.record(SecurityMetricObservationBO.builder().signal(signal).result("HIT").build());
        }
        metrics.record(SecurityMetricObservationBO.builder().signal("oauth.authentication").result("VALID").build());
        metrics.record(SecurityMetricObservationBO.builder().signal("rbac.authorization").result("ALLOW").build());
        metrics.record(SecurityMetricObservationBO.builder().signal("oauth.audit.delivery").result("CONFIRMED").build());
        assertThat(registry.getMeters()).hasSize(8).allSatisfy(meter ->
                assertThat(meter.getId().getTag("receiver")).isEqualTo(RECEIVER));
    }

    @Test
    void disabledHostDoesNotRequireDeploymentInputsOrCreateAMetricsRegistry() {
        new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(IdpSecurityObservationAutoConfiguration.class))
                .withUserConfiguration(TianquanSecurityObservationConfiguration.class)
                .withPropertyValues("egon.cola.platform.tianquan.shoubing.usage-observation.enabled=false")
                .run(context -> assertThat(context).hasNotFailed().doesNotHaveBean(MeterRegistry.class)
                        .doesNotHaveBean("idpSecurityMetricsRecorder"));
    }

    @Test
    void deadOrMissingSqlReceiptCannotCountAsConfirmedHandoff() throws Exception {
        var authority = recordingAuthority(new java.util.ArrayList<>());
        doAnswer(call -> receipt(call.getArgument(0), "DEAD")).when(authority).appendAudit(any());
        var producer = producer(authority, metrics);
        var event = new TokenUsageAuditEvent("dead-metric", 1, ISSUER, RESOURCE.toASCIIString(), null, null, null,
                "SUCCESS", "TOKEN_USE_VERIFIED", NOW, null);
        assertThatThrownBy(() -> producer.appendStrict(event)).hasMessage("OAUTH_AUDIT_DELIVERY_UNAVAILABLE");
        assertThat(registry.get("oauth.audit.delivery").tags("receiver", RECEIVER, "result", "FAILED").counter().count()).isEqualTo(1);
        assertThat(registry.find("receipt.age").timer()).isNull();
    }

    @Test
    void failedMetricRecordingNeverChangesTheSqlConfirmedHandoff() throws Exception {
        var producer = producer(recordingAuthority(new java.util.ArrayList<>()), sample -> { throw new IllegalStateException("metrics unavailable"); });
        var event = new TokenUsageAuditEvent("metric-failure", 1, ISSUER, RESOURCE.toASCIIString(), null, null, null,
                "SUCCESS", "TOKEN_USE_VERIFIED", NOW, null);
        assertThat(producer.appendStrict(event).outcome()).isEqualTo("STORED");
        assertThat(Files.exists(temporary.resolve("spool"))).isFalse();
    }

    @Test
    @SuppressWarnings("unchecked")
    void nativeUserInfoCompletesStrictUsageBeforeItsProtocolResponse() throws Exception {
        var context = new org.springframework.web.context.support.AnnotationConfigWebApplicationContext();
        context.setServletContext(new org.springframework.mock.web.MockServletContext());
        java.util.List<Map<String, String>> usage = new java.util.ArrayList<>();
        var authority = recordingAuthority(usage);
        doAnswer(call -> {
            var attrs = (org.springframework.web.context.request.ServletRequestAttributes)
                    org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();
            assertThat(attrs.getResponse().isCommitted()).isFalse();
            TokenUsageAuditEvent event = call.getArgument(0); usage.add(eventFields(event)); return receipt(event, "STORED");
        }).when(authority).appendAudit(any());
        var producer = producer(authority, metrics);
        var props = new OAuthUsageObservationProperties(true, URI.create("https://idp.example.test/tenants/1001"), false).setReceiver(IdpSecurityObservationReceiverEnum.SHOUBING);
        var receiver = new IdpStarterProperties(); receiver.setResourceUri(RESOURCE);
        var converter = (top.egon.cola.platform.tianquan.shoubing.starter.security.domain.converter.TokenUsageAuditEventConverter)
                Class.forName("top.egon.cola.platform.tianquan.shoubing.starter.security.domain.converter.TokenUsageAuditEventConverterImpl")
                .getConstructor().newInstance();
        context.addBeanFactoryPostProcessor(factory -> {
            factory.registerSingleton("tokenUsageAuditComponent", producer);
            factory.registerSingleton("oauthUsageObservationProperties", props);
            factory.registerSingleton("idpStarterProperties", receiver);
            factory.registerSingleton("tokenUsageAuditEventConverterImpl", converter);
            factory.registerSingleton("idpSecurityMetricsRecorder", metrics);
        });
        context.register(Class.forName("top.egon.cola.platform.tianquan.shoubing.admin.oauth.OAuthConsentRoundTripTest$NativeConfiguration"));
        context.refresh();
        Object fixture = context.getBean("fixture");
        try {
            Class<?> nativeTest = Class.forName("top.egon.cola.platform.tianquan.shoubing.admin.oauth.OAuthConsentRoundTripTest");
            var constructor = nativeTest.getDeclaredConstructor(); constructor.setAccessible(true);
            Object scenario = constructor.newInstance();
            for (String field : java.util.List.of("context", "fixture")) {
                var target = nativeTest.getDeclaredField(field); target.setAccessible(true);
                target.set(scenario, field.equals("context") ? context : fixture);
            }
            for (String method : java.util.List.of("prepareNativeFixture", "nativeLoginConsentCodeOidcUserinfoAndRefreshRoundTrip")) {
                var action = nativeTest.getDeclaredMethod(method); action.setAccessible(true);
                try { action.invoke(scenario); }
                catch (java.lang.reflect.InvocationTargetException failure) {
                    if (failure.getCause() instanceof Error error) { throw error; }
                    if (failure.getCause() instanceof Exception exception) { throw exception; }
                    throw failure;
                }
            }
            assertThat(usage).as("native UserInfo must use the real durable producer").hasSize(2);
            assertThat(usage.getFirst()).containsEntry("reasonCode", "TOKEN_USE_VERIFIED");
            assertThat(usage.getLast()).containsEntry("reasonCode", "AUTHENTICATION_FAILED")
                    .doesNotContainKeys("subjectRef", "clientRef", "tokenRef");
            assertThat(registry.get("jwt.verify.duration").tags("receiver", RECEIVER, "result", "SUCCESS").timer().count()).isEqualTo(1);
        } finally {
            context.close(); ((AutoCloseable) fixture).close();
            org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder.resetContext();
            org.springframework.security.core.context.SecurityContextHolder.clearContext();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void nativeUserInfoErrorsAreAnonymousAndStrictFailureNeverReturnsIdentity() throws Exception {
        java.util.List<Map<String, String>> usage = new java.util.ArrayList<>();
        var authority = recordingAuthority(usage);
        var producer = producer(authority, metrics);
        var context = nativeContext(producer);
        Object fixture = context.getBean("fixture");
        try {
            Object scenario = nativeScenario(context, fixture);
            var mvcField = scenario.getClass().getDeclaredField("mvc"); mvcField.setAccessible(true);
            var mvc = (org.springframework.test.web.servlet.MockMvc) mvcField.get(scenario);
            var missing = mvc.perform(nativeRequest(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                    .get("/tenants/1001/userinfo"))).andReturn();
            assertThat(missing.getResponse().getStatus()).isEqualTo(401);
            assertThat(missing.getResponse().getHeader("Location")).isNull();
            assertThat(usage).hasSize(1);
            invokeNative(scenario, "userInfoDependencyFailuresAreUnavailableAndNeverReturnIdentity");
            assertThat(usage).hasSize(4).allSatisfy(event -> assertThat(event)
                    .containsEntry("reasonCode", "AUTHENTICATION_FAILED").doesNotContainKeys("subjectRef", "clientRef", "tokenRef"));
            invokeNative(scenario, "prepareNativeFixture");
            invokeNative(scenario, "reducedRefreshScopeCannotRegainOpenidThroughMetadataReload");
            assertThat(usage).hasSize(5);
            invokeNative(scenario, "prepareNativeFixture");
            String access = mintNativeAccess(scenario);
            var malformed = mvc.perform(nativeRequest(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                    .get("/tenants/1001/userinfo")).header("Authorization", "Bearer malformed.jwt.value")).andReturn();
            assertThat(malformed.getResponse().getStatus()).isEqualTo(401);
            assertThat(usage).hasSize(6);
            String[] segments = access.split("\\.");
            byte[] signature = java.util.Base64.getUrlDecoder().decode(segments[2]); signature[0] ^= 1;
            String forged = segments[0] + "." + segments[1] + "." + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
            var badSignature = mvc.perform(nativeRequest(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                    .get("/tenants/1001/userinfo")).header("Authorization", "Bearer " + forged)).andReturn();
            assertThat(badSignature.getResponse().getStatus()).isEqualTo(401);
            assertThat(usage).hasSize(7);
            var tokensField = fixture.getClass().getDeclaredField("tokens"); tokensField.setAccessible(true);
            Map<String, top.egon.cola.platform.tianquan.shoubing.admin.token.domain.po.OAuthTokenPO> stored =
                    (Map<String, top.egon.cola.platform.tianquan.shoubing.admin.token.domain.po.OAuthTokenPO>) tokensField.get(fixture);
            stored.values().stream().filter(row -> row.getTokenType() == top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthTokenTypeEnum.ACCESS)
                    .forEach(row -> row.setRevokedAt(Instant.now()));
            var revoked = mvc.perform(nativeRequest(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                    .get("/tenants/1001/userinfo")).header("Authorization", "Bearer " + access)).andReturn();
            assertThat(revoked.getResponse().getStatus()).isEqualTo(401);
            assertThat(usage).hasSize(8);
            invokeNative(scenario, "prepareNativeFixture");
            access = mintNativeAccess(scenario);
            doThrow(new IllegalStateException("fixture SQL failure")).when(authority).appendAudit(any());
            var unavailable = mvc.perform(nativeRequest(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                    .get("/tenants/1001/userinfo")).header("Authorization", "Bearer " + access)).andReturn();
            assertThat(unavailable.getResponse().getStatus()).isEqualTo(503);
            assertThat(unavailable.getResponse().getHeader("Cache-Control")).isEqualTo("no-store");
            assertThat(unavailable.getResponse().getContentAsString()).contains("temporarily_unavailable")
                    .doesNotContain("sub", access, "fixture SQL failure");
            assertThat(usage).hasSize(8);
            assertThat(Files.exists(temporary.resolve("spool"))).isFalse();
        } finally {
            context.close(); ((AutoCloseable) fixture).close();
            org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder.resetContext();
            org.springframework.security.core.context.SecurityContextHolder.clearContext();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void nativeMetricOutageDoesNotChangeTheSuccessfulUserInfoResponse() throws Exception {
        var authority = recordingAuthority(new java.util.ArrayList<>());
        var context = nativeContext(producer(authority, metrics), sample -> { throw new IllegalStateException("metric outage fixture"); });
        Object fixture = context.getBean("fixture");
        try {
            Object scenario = nativeScenario(context, fixture);
            String access = mintNativeAccess(scenario);
            var field = scenario.getClass().getDeclaredField("mvc"); field.setAccessible(true);
            var mvc = (org.springframework.test.web.servlet.MockMvc) field.get(scenario);
            var response = mvc.perform(nativeRequest(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                    .get("/tenants/1001/userinfo")).header("Authorization", "Bearer " + access)).andReturn().getResponse();
            assertThat(response.getStatus()).isEqualTo(200);
            assertThat(response.getContentAsString()).contains("user-1001").doesNotContain("metric outage fixture", access);
        } finally { context.close(); ((AutoCloseable) fixture).close(); }
    }

    private org.springframework.web.context.support.AnnotationConfigWebApplicationContext nativeContext(TokenUsageAuditComponent producer) throws Exception {
        return nativeContext(producer, metrics);
    }

    private org.springframework.web.context.support.AnnotationConfigWebApplicationContext nativeContext(TokenUsageAuditComponent producer,
            top.egon.cola.platform.tianquan.shoubing.core.observability.IdpSecurityMetricsRecorder nativeMetrics) throws Exception {
        var context = new org.springframework.web.context.support.AnnotationConfigWebApplicationContext();
        context.setServletContext(new org.springframework.mock.web.MockServletContext());
        var props = new OAuthUsageObservationProperties(true, URI.create("https://idp.example.test/tenants/1001"), false).setReceiver(IdpSecurityObservationReceiverEnum.SHOUBING);
        var receiver = new IdpStarterProperties(); receiver.setResourceUri(RESOURCE);
        var converter = (top.egon.cola.platform.tianquan.shoubing.starter.security.domain.converter.TokenUsageAuditEventConverter)
                Class.forName("top.egon.cola.platform.tianquan.shoubing.starter.security.domain.converter.TokenUsageAuditEventConverterImpl").getConstructor().newInstance();
        context.addBeanFactoryPostProcessor(factory -> {
            factory.registerSingleton("tokenUsageAuditComponent", producer);
            factory.registerSingleton("oauthUsageObservationProperties", props);
            factory.registerSingleton("idpStarterProperties", receiver);
            factory.registerSingleton("tokenUsageAuditEventConverterImpl", converter);
            factory.registerSingleton("idpSecurityMetricsRecorder", nativeMetrics);
        });
        context.register(Class.forName("top.egon.cola.platform.tianquan.shoubing.admin.oauth.OAuthConsentRoundTripTest$NativeConfiguration"));
        context.refresh(); return context;
    }

    private Object nativeScenario(org.springframework.web.context.support.AnnotationConfigWebApplicationContext context, Object fixture) throws Exception {
        Class<?> type = Class.forName("top.egon.cola.platform.tianquan.shoubing.admin.oauth.OAuthConsentRoundTripTest");
        var constructor = type.getDeclaredConstructor(); constructor.setAccessible(true); Object scenario = constructor.newInstance();
        for (String field : java.util.List.of("context", "fixture")) {
            var target = type.getDeclaredField(field); target.setAccessible(true); target.set(scenario, field.equals("context") ? context : fixture);
        }
        invokeNative(scenario, "prepareNativeFixture"); return scenario;
    }

    private void invokeNative(Object scenario, String name) throws Exception {
        var action = scenario.getClass().getDeclaredMethod(name); action.setAccessible(true);
        try { action.invoke(scenario); }
        catch (java.lang.reflect.InvocationTargetException failure) {
            if (failure.getCause() instanceof Error error) { throw error; }
            if (failure.getCause() instanceof Exception exception) { throw exception; }
            throw failure;
        }
    }

    private String mintNativeAccess(Object scenario) throws Exception {
        var start = scenario.getClass().getDeclaredMethod("startThroughRealLogin", long.class); start.setAccessible(true);
        Object pending = start.invoke(scenario, 1001L);
        var csrf = scenario.getClass().getDeclaredMethod("consentCsrf", pending.getClass()); csrf.setAccessible(true);
        var approve = scenario.getClass().getDeclaredMethod("approve", pending.getClass(), String.class); approve.setAccessible(true);
        String code = (String) approve.invoke(scenario, pending, csrf.invoke(scenario, pending));
        var tokens = scenario.getClass().getDeclaredMethod("token", String.class, String.class); tokens.setAccessible(true);
        return ((com.fasterxml.jackson.databind.JsonNode) tokens.invoke(scenario, code, "V".repeat(64))).path("access_token").asText();
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder nativeRequest(
            org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request) {
        return request.secure(true).with(value -> { value.setScheme("https"); value.setServerName("idp.example.test"); value.setServerPort(443); return value; });
    }

    @Test
    void ownProfilesDeclareTheSameObservationAndDeliveryLeaves() throws Exception {
        var loader = new org.springframework.boot.env.YamlPropertySourceLoader();
        String prefix = "egon.cola.platform.tianquan.shoubing.";
        for (String profile : java.util.List.of("src/main/resources/application.yml", "src/main/resources/application-local.yml", "src/main/resources/application-oauth-migration.yml")) {
            var sources = loader.load(profile, new org.springframework.core.io.FileSystemResource(profile));
            var names = new java.util.HashSet<String>();
            for (var source : sources) { names.addAll(java.util.List.of(((org.springframework.core.env.EnumerablePropertySource<?>) source).getPropertyNames())); }
            assertThat(names).as(profile).contains(prefix + "usage-observation.enabled", prefix + "usage-observation.receiver", prefix + "usage-observation.fallback-issuer",
                    prefix + "usage-observation.allow-local-plaintext",
                    "egon.cola.component.rpc.tls.enabled", "egon.cola.component.rpc.tls.development-plaintext",
                    "egon.cola.component.tianshu.rpc.tls.enabled", "egon.cola.component.tianshu.rpc.tls.development-plaintext");
            var environment = new org.springframework.mock.env.MockEnvironment()
                    .withProperty("TIANQUAN_SHOUBING_OAUTH_ISSUER", ISSUER.toASCIIString());
            for (var source : sources) { environment.getPropertySources().addLast(source); }
            var binder = org.springframework.boot.context.properties.bind.Binder.get(environment);
            var usage = binder.bind(prefix + "usage-observation", OAuthUsageObservationProperties.class).orElseThrow(IllegalStateException::new);
            assertThat(validator.validate(usage)).isEmpty();
            assertThat(names).doesNotContain(prefix + "audit.spool-directory", prefix + "audit.hmac-key-file", prefix + "audit.stream");
            boolean offline = profile.contains("oauth-migration") || profile.contains("local-it");
            assertThat(usage.isEnabled()).isEqualTo(!offline);
            assertThat(usage.getReceiver()).isEqualTo(IdpSecurityObservationReceiverEnum.SHOUBING);
            assertThat(usage.isAllowLocalPlaintext()).isEqualTo(profile.endsWith("application-local.yml"));

        }
    }

    @Test
    void enabledHostRejectsPlaintextProductionInputs() throws Exception {
        var producer = producer(recordingAuthority(new java.util.ArrayList<>()), metrics);
        new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(IdpSecurityObservationAutoConfiguration.class))
                .withUserConfiguration(TianquanSecurityObservationConfiguration.class)
                .withPropertyValues("egon.cola.platform.tianquan.shoubing.usage-observation.enabled=true",
                        "egon.cola.platform.tianquan.shoubing.resource-uri=http://api.example/orders",
                        "egon.cola.platform.tianquan.shoubing.issuer=" + ISSUER,
                        "egon.cola.platform.tianquan.shoubing.jwk-set-uri=" + ISSUER + "/.well-known/jwks.json",
                        "egon.cola.platform.tianquan.shoubing.revocation.primary-endpoint=rediss://redis.example:6379",
                        "egon.cola.platform.tianquan.jianshen.authorization.endpoint=https://permission.example",
                        "egon.tianquan-shoubing.oauth.public-origin=https://idp.example",
                        "egon.cola.component.rpc.enabled=false", "egon.cola.component.tianshu.enabled=false")
                .withBean("primary", MeterRegistry.class, () -> registry)
                .withBean("defaultValidator", jakarta.validation.Validator.class, () -> validator)
                .withBean("tokenUsageAuditComponent", TokenUsageAuditComponent.class, () -> producer)
                .withBean("identityAuthorityClientResolver", IdentityAuthorityClientResolver.class,
                        () -> issuer -> recordingAuthority(new java.util.ArrayList<>()))
                .withBean("trustedIssuerRegistry", TrustedIssuerRegistry.class, this::trustedRegistry)
                .withBean("oauthUsageObservationProperties", OAuthUsageObservationProperties.class,
                        () -> new OAuthUsageObservationProperties(true, ISSUER, false).setReceiver(IdpSecurityObservationReceiverEnum.SHOUBING))
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void transportGuardAllowsOnlyTheExplicitLocalLoopbackException() throws Exception {
        secureHostRunner(false).run(context -> assertThat(context).hasNotFailed());
        for (String invalid : java.util.List.of(
                "egon.cola.component.rpc.enabled=true",
                "egon.cola.component.tianshu.enabled=true",
                "egon.cola.platform.tianquan.shoubing.issuer=http://idp.example/tenants/1001",
                "spring.security.oauth2.client.provider.unsafe.token-uri=http://remote.example/token")) {
            secureHostRunner(false).withPropertyValues(invalid).run(context -> assertThat(context).hasFailed());
        }
        String[] loopback = {
                "DEPLOYMENT_ENV=local", "egon.cola.platform.tianquan.shoubing.resource-uri=http://127.0.0.1/orders",
                "egon.cola.platform.tianquan.shoubing.revocation.primary-endpoint=redis://127.0.0.1:6379",
                "egon.cola.platform.tianquan.jianshen.authorization.endpoint=http://localhost:18130" };
        secureHostRunner(true).withPropertyValues(loopback).withInitializer(context -> context.getEnvironment().setActiveProfiles("local"))
                .run(context -> assertThat(context).hasNotFailed());
        secureHostRunner(true).withPropertyValues(loopback).run(context -> assertThat(context).hasFailed());
        secureHostRunner(true).withPropertyValues(loopback).withPropertyValues("DEPLOYMENT_ENV=prod")
                .withInitializer(context -> context.getEnvironment().setActiveProfiles("local"))
                .run(context -> assertThat(context).hasFailed());
        secureHostRunner(true).withPropertyValues(loopback).withPropertyValues("egon.cola.platform.tianquan.shoubing.resource-uri=http://remote.example/orders")
                .withInitializer(context -> context.getEnvironment().setActiveProfiles("local"))
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void independentHostsNeedNoExclusiveLocalAuditVolume() throws Exception {
        var runner = secureHostRunner(false);
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean("tianquanSecurityAuditReady", java.util.function.BooleanSupplier.class).getAsBoolean()).isTrue();
            assertThat(context.getBean("tianquanAuditReadiness", org.springframework.boot.health.contributor.HealthIndicator.class)
                    .health().getStatus()).isEqualTo(org.springframework.boot.health.contributor.Status.UP);
            runner.run(second -> assertThat(second).hasNotFailed().doesNotHaveBean("idpAuditSpoolLease"));
        });
        assertThat(Files.exists(temporary.resolve("spool"))).isFalse();
    }

    private String[] secureProperties() {
        return new String[] {
                "egon.cola.platform.tianquan.shoubing.usage-observation.enabled=true",
                "egon.cola.platform.tianquan.shoubing.issuer=" + ISSUER,
                "egon.cola.platform.tianquan.shoubing.jwk-set-uri=" + ISSUER + "/.well-known/jwks.json",
                "egon.cola.platform.tianquan.shoubing.resource-uri=" + RESOURCE,
                "egon.cola.platform.tianquan.shoubing.revocation.primary-endpoint=rediss://redis.example:6379",
                "egon.cola.platform.tianquan.jianshen.authorization.endpoint=https://permission.example",
                "egon.tianquan-shoubing.oauth.public-origin=https://idp.example",
                "egon.cola.component.rpc.enabled=false", "egon.cola.component.tianshu.enabled=false" };
    }

    private ApplicationContextRunner secureHostRunner(boolean allowLocal) throws Exception {
        var producer = producer(recordingAuthority(new java.util.ArrayList<>()), metrics);
        return new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(IdpSecurityObservationAutoConfiguration.class))
                .withUserConfiguration(TianquanSecurityObservationConfiguration.class)
                .withPropertyValues(secureProperties())
                .withBean("primary", MeterRegistry.class, () -> registry)
                .withBean("defaultValidator", jakarta.validation.Validator.class, () -> validator)
                .withBean("tokenUsageAuditComponent", TokenUsageAuditComponent.class, () -> producer)
                .withBean("identityAuthorityClientResolver", IdentityAuthorityClientResolver.class,
                        () -> issuer -> recordingAuthority(new java.util.ArrayList<>()))
                .withBean("trustedIssuerRegistry", TrustedIssuerRegistry.class, this::trustedRegistry)
                .withBean("oauthUsageObservationProperties", OAuthUsageObservationProperties.class,
                        () -> new OAuthUsageObservationProperties(true, ISSUER, allowLocal).setReceiver(IdpSecurityObservationReceiverEnum.SHOUBING));
    }

    private TokenUsageAuditComponent producer(IdentityAuthorityClient authority,
            top.egon.cola.platform.tianquan.shoubing.core.observability.IdpSecurityMetricsRecorder recorder) {
        return new TokenUsageAuditComponent(issuer -> authority, Clock.systemUTC(), validator, recorder);
    }

    private IdentityAuthorityClient recordingAuthority(java.util.List<Map<String, String>> events) {
        var authority = mock(IdentityAuthorityClient.class);
        doAnswer(call -> {
            TokenUsageAuditEvent event = call.getArgument(0); events.add(eventFields(event)); return receipt(event, "STORED");
        }).when(authority).appendAudit(any());
        return authority;
    }

    private IdentityAuditReceipt receipt(TokenUsageAuditEvent event, String outcome) {
        return new IdentityAuditReceipt(java.util.UUID.randomUUID().toString(), event.eventId(), TokenUsageAuditFingerprint.of(event),
                event.issuer().toASCIIString(), "controlled-resource", event.resource(), outcome, Instant.now());
    }

    private Map<String, String> eventFields(TokenUsageAuditEvent event) {
        Map<String, String> values = new LinkedHashMap<>(); values.put("eventId", event.eventId());
        values.put("issuer", event.issuer().toASCIIString()); values.put("resource", event.resource());
        values.put("result", event.result()); values.put("reasonCode", event.reasonCode());
        if (event.subjectRef() != null) { values.put("subjectRef", event.subjectRef()); }
        if (event.clientRef() != null) { values.put("clientRef", event.clientRef()); }
        if (event.tokenRef() != null) { values.put("tokenRef", event.tokenRef()); }
        if (event.traceId() != null) { values.put("traceId", event.traceId()); }
        return Map.copyOf(values);
    }

    private TrustedIssuerRegistry trustedRegistry() {
        var properties = new IdpStarterProperties(); var issuer = new IdpStarterProperties.TrustedIssuerSettings();
        issuer.setIssuer(ISSUER.toASCIIString()); issuer.setJwksUri(ISSUER + "/.well-known/jwks.json");
        issuer.setRealmKey("tenant:1001"); issuer.setRealmType("TENANT"); issuer.setTenantId("1001");
        issuer.setStatus("ACTIVE"); issuer.setTrustVersion(1); properties.setTrustedIssuers(Map.of("tenant", issuer));
        return new TrustedIssuerRegistry(properties);
    }
}
