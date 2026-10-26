package top.egon.cola.platform.tianquan.shoubing.yuheng.autoconfigure;

import java.time.Clock;
import java.util.List;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import top.egon.cola.platform.tianquan.shoubing.core.observability.IdpSecurityMetricsRecorder;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpSecurityObservationAutoConfiguration;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterAutoConfiguration;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TenantIssuerAuthenticationManagerComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedPrincipalConverter;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TrustedIssuerRegistry;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClientResolver;
import top.egon.cola.platform.tianquan.shoubing.yuheng.security.GatewayResourceServerResolver;
import top.egon.cola.platform.tianquan.shoubing.yuheng.security.IdpGatewayJwtVerifier;
import top.egon.cola.platform.tianquan.shoubing.yuheng.security.IdpIdentityAuthenticationProvider;
import top.egon.cola.platform.tianquan.shoubing.yuheng.security.IdpOAuthScopeAuthorizationProvider;
import top.egon.cola.platform.tianquan.shoubing.yuheng.security.IdpReservedHeaderSanitizer;
import top.egon.cola.platform.tianquan.shoubing.yuheng.security.IdpTrustedIdentityMapper;
import top.egon.cola.platform.tianquan.shoubing.yuheng.security.IdpUserCookieCredentialExtractor;
import top.egon.cola.platform.tianquan.shoubing.yuheng.security.IdpUserCredentialRecoveryProvider;

/** Adapts the shared SQL-backed verification and confirmed audit pipeline to the Gateway security SPI. */
@AutoConfiguration(value = "idpGatewayAdapterAutoConfiguration", after = {IdpStarterAutoConfiguration.class, IdpSecurityObservationAutoConfiguration.class})
@EnableConfigurationProperties(IdpGatewayAdapterProperties.class)
@ConditionalOnProperty(prefix = "egon.cola.platform.tianquan.shoubing.yuheng", name = "enabled", havingValue = "true")
public class IdpGatewayAdapterAutoConfiguration {
    @Bean
    public Object idpGatewayLegacyConfigurationMigrationGuard(Environment environment) {
        String prefix = "egon.cola.platform.tianquan.shoubing.yuheng.";
        var retired = List.of("issuer", "jwk-set-uri", "platform-audience", "resource-state-key-prefix", "resource-scope-key-prefix",
                "resource-uri-key-prefix", "client-state-key-prefix", "runtime.redis-enabled", "runtime.redis-address",
                "runtime.password-file", "runtime.database", "runtime.timeout").stream().map(prefix::concat)
                .filter(environment::containsProperty).toList();
        if (!retired.isEmpty()) { throw new IllegalStateException("Gateway SQL authority migration required: " + String.join(", ", retired)); }
        return new Object();
    }

    @Bean
    @ConditionalOnMissingBean
    public IdpReservedHeaderSanitizer idpReservedHeaderSanitizer() { return new IdpReservedHeaderSanitizer(); }

    @Bean
    @ConditionalOnMissingBean
    public IdpUserCookieCredentialExtractor idpUserCookieCredentialExtractor(
            IdpReservedHeaderSanitizer sanitizer, IdpGatewayAdapterProperties properties) {
        properties.validate();
        return IdpUserCookieCredentialExtractor.createConfigured(sanitizer);
    }

    @Bean
    @ConditionalOnMissingBean
    public GatewayResourceServerResolver gatewayResourceServerResolver(IdpGatewayAdapterProperties properties) {
        properties.validate();
        return new GatewayResourceServerResolver(properties.getRouteResources());
    }

    @Bean("idpGatewayJwtVerifier")
    @ConditionalOnMissingBean
    public IdpGatewayJwtVerifier idpGatewayJwtVerifier(GatewayResourceServerResolver resources,
            @Qualifier("tenantIssuerAuthenticationManagerComponent") TenantIssuerAuthenticationManagerComponent issuerManager,
            IdentityAuthorityClientResolver authority,
            @Qualifier("trustedIssuerRegistry") TrustedIssuerRegistry trustedIssuers,
            @Qualifier("verifiedPrincipalConverter") VerifiedPrincipalConverter converter,
            @Qualifier("idpClock") Clock clock,
            @Qualifier("idpObservedVerificationComponent") IdpObservedVerificationComponent observations) {
        for (var issuer : trustedIssuers.activeIssuers()) {
            for (var resource : resources.targetResources()) {
                java.util.Objects.requireNonNull(authority.forResource(issuer.issuer(), resource), "GATEWAY_AUTHORITY_BINDING_REQUIRED");
            }
        }
        return IdpGatewayJwtVerifier.createConfigured(resources, clock, issuerManager, authority, converter, observations);
    }

    @Bean("idpUserCredentialRecoveryProvider")
    @ConditionalOnMissingBean
    public IdpUserCredentialRecoveryProvider idpUserCredentialRecoveryProvider(
            IdpReservedHeaderSanitizer sanitizer, IdpGatewayAdapterProperties properties) {
        properties.validate();
        return IdpUserCredentialRecoveryProvider.createConfigured(sanitizer,
                properties.getRefreshTokenCookieName(), properties.getAccessTokenCookieName());
    }

    @Bean(name = "idpIdentityAuthenticationProvider")
    @ConditionalOnMissingBean
    public IdpIdentityAuthenticationProvider idpIdentityAuthenticationProvider(
            @Qualifier("idpGatewayJwtVerifier") IdpGatewayJwtVerifier verifier,
            @Qualifier("defaultValidator") jakarta.validation.Validator validator) {
        return IdpIdentityAuthenticationProvider.createConfigured(verifier, validator);
    }

    @Bean(name = "idpOAuthScopeAuthorizationProvider")
    @ConditionalOnMissingBean(name = "idpOAuthScopeAuthorizationProvider")
    IdpOAuthScopeAuthorizationProvider idpOAuthScopeAuthorizationProvider(
            @Qualifier("idpObservedVerificationComponent") IdpObservedVerificationComponent observations,
            @Qualifier("idpSecurityMetricsRecorder") IdpSecurityMetricsRecorder metrics,
            @Qualifier("defaultValidator") jakarta.validation.Validator validator) {
        return new IdpOAuthScopeAuthorizationProvider(observations, metrics, validator);
    }

    @Bean(name = "idpTrustedIdentityMapper")
    @ConditionalOnMissingBean
    public IdpTrustedIdentityMapper idpTrustedIdentityMapper() { return new IdpTrustedIdentityMapper(); }
}
