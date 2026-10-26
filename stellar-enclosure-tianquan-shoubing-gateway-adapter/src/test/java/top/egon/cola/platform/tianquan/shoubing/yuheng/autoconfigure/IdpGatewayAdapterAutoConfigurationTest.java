package top.egon.cola.platform.tianquan.shoubing.yuheng.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import top.egon.cola.component.yuheng.core.security.*;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterAutoConfiguration;
import top.egon.cola.platform.tianquan.shoubing.starter.security.*;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClient;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClientResolver;
import top.egon.cola.platform.tianquan.shoubing.yuheng.security.*;

class IdpGatewayAdapterAutoConfigurationTest {
    private static final String PREFIX = "egon.cola.platform.tianquan.shoubing.yuheng.";
    private final IdpObservedVerificationComponent observer = mock(IdpObservedVerificationComponent.class);
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(IdpGatewayAdapterAutoConfiguration.class))
            .withBean("tenantIssuerAuthenticationManagerComponent", TenantIssuerAuthenticationManagerComponent.class, () -> {
                var manager = mock(TenantIssuerAuthenticationManagerComponent.class); when(manager.isConfigured()).thenReturn(true); return manager;
            })
            .withBean("trustedIssuerRegistry", TrustedIssuerRegistry.class, () -> {
                var registry = mock(TrustedIssuerRegistry.class);
                when(registry.activeIssuers()).thenReturn(java.util.List.of(new TrustedIssuerRegistry.TrustedIssuerVO(
                        java.net.URI.create("https://idp.example/tenants/1001"), java.net.URI.create("https://idp.example/tenants/1001/jwks"),
                        "tenant:1001", TrustedIssuerRegistry.RealmType.TENANT, "1001", TrustedIssuerRegistry.Status.ACTIVE, 1)));
                return registry;
            })
            .withBean("identityAuthorityClientResolver", IdentityAuthorityClientResolver.class, () -> issuer -> mock(IdentityAuthorityClient.class))
            .withBean("verifiedPrincipalConverter", VerifiedPrincipalConverter.class, () -> mock(VerifiedPrincipalConverter.class))
            .withBean("idpObservedVerificationComponent", IdpObservedVerificationComponent.class, () -> {
                when(observer.enabled()).thenReturn(true); return observer;
            })
            .withBean("idpSecurityMetricsRecorder", top.egon.cola.platform.tianquan.shoubing.core.observability.IdpSecurityMetricsRecorder.class, () -> sample -> { })
            .withBean("idpClock", Clock.class, Clock::systemUTC)
            .withBean("defaultValidator", jakarta.validation.Validator.class, org.springframework.validation.beanvalidation.LocalValidatorFactoryBean::new);

    @Test void runsAfterSharedAuthorityAndObservationConfiguration() {
        assertThat(IdpGatewayAdapterAutoConfiguration.class.getAnnotation(AutoConfiguration.class).after()).contains(IdpStarterAutoConfiguration.class);
    }
    @Test void staysDisabledByDefault() {
        runner.run(context -> assertThat(context).doesNotHaveBean(GatewayCredentialExtractor.class).doesNotHaveBean(GatewayIdentityMapper.class));
    }
    @Test void boundRoutesAssembleWithoutRedisAndKeepMandatoryScopeAuthorization() {
        runner.withPropertyValues(settings()).run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(GatewayCredentialExtractor.class).hasSingleBean(GatewayAuthenticationProvider.class)
                    .hasSingleBean(GatewayIdentityMapper.class).hasSingleBean(GatewayAuthorizationProvider.class)
                    .doesNotHaveBean("idpGatewayRedissonClient").doesNotHaveBean("idpAuditRedissonClient")
                    .doesNotHaveBean("idpGatewayResourceServerStateReader").doesNotHaveBean("idpGatewayOAuthClientStateReader")
                    .doesNotHaveBean("idpGatewayJwtDecoder");
            assertThat(context.getBean(GatewayAuthorizationProvider.class).mandatory()).isTrue();
            assertThat(context.getBean(GatewayAuthenticationProvider.class).requiredAuthorizationProviderIds())
                    .containsExactly(IdpOAuthScopeAuthorizationProvider.PROVIDER_ID);
            assertThat(context).doesNotHaveBean(IdpRefreshClient.class).doesNotHaveBean(IdpRefreshTokenStatusClient.class)
                    .doesNotHaveBean(IdpUserOnlineStateProvider.class);
        });
    }
    @Test void missingBindingsAndRetiredRedisConfigurationFailClosed() {
        runner.withPropertyValues(PREFIX + "enabled=true").run(context -> assertThat(context).hasFailed());
        runner.withPropertyValues(settings()).withPropertyValues(PREFIX + "runtime.redis-enabled=false")
                .run(context -> assertThat(context).hasFailed().getFailure().hasStackTraceContaining("SQL authority migration required"));
    }
    @Test void disabledAuditCannotCreateAFormalGatewayVerifier() {
        runner.withPropertyValues(settings()).withBean("idpObservedVerificationComponent", IdpObservedVerificationComponent.class,
                        () -> mock(IdpObservedVerificationComponent.class))
                .withAllowBeanDefinitionOverriding(true).run(context -> assertThat(context).hasFailed());
    }
    @Test void everyKnownGatewayTargetRequiresItsOwnBoundAuthorityIdentity() {
        var resolver = mock(IdentityAuthorityClientResolver.class);
        when(resolver.forIssuer(any())).thenThrow(new AssertionError("issuer-only fallback is forbidden"));
        when(resolver.forResource(any(), org.mockito.ArgumentMatchers.eq(java.net.URI.create("https://api.example/orders"))))
                .thenReturn(mock(IdentityAuthorityClient.class));
        runner.withPropertyValues(settings()).withAllowBeanDefinitionOverriding(true)
                .withBean("identityAuthorityClientResolver", IdentityAuthorityClientResolver.class, () -> resolver)
                .run(context -> assertThat(context).hasNotFailed());
        runner.withPropertyValues(settings()).withPropertyValues(PREFIX + "route-resources.other.resource-uri=https://api.example/other")
                .withAllowBeanDefinitionOverriding(true)
                .withBean("identityAuthorityClientResolver", IdentityAuthorityClientResolver.class, () -> resolver)
                .run(context -> assertThat(context).hasFailed().getFailure().hasStackTraceContaining("GATEWAY_AUTHORITY_BINDING_REQUIRED"));
        verify(resolver, never()).forIssuer(any());
    }

    private String[] settings() {
        return new String[]{PREFIX + "enabled=true", PREFIX + "route-resources.orders.resource-uri=https://api.example/orders",
                PREFIX + "route-resources.orders.biz-code=commerce", PREFIX + "route-resources.orders.app-code=orders",
                PREFIX + "route-resources.orders.environment=test"};
    }
}
