package top.egon.cola.platform.tianquan.shoubing.admin.support.security;

import io.micrometer.core.instrument.MeterRegistry;
import jakarta.validation.Validator;
import lombok.extern.slf4j.Slf4j;
import java.util.function.Supplier;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import top.egon.cola.component.common.core.validation.ValidationUtils;
import top.egon.cola.platform.tianquan.shoubing.starter.audit.OAuthUsageObservationProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.audit.TokenUsageAuditComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingConverter;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingRegistry;

/** Composes host transport and durable-audit checks with the existing security runtime. */
@Slf4j
@Configuration(value = "tianquanSecurityObservationConfiguration", proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "egon.cola.platform.tianquan.shoubing.usage-observation", name = "enabled", havingValue = "true")
public class TianquanSecurityObservationConfiguration {
    /** Separate from the port factory to avoid a producer-to-recorder initialization cycle. */
    @Bean(name = "tianquanSecurityObservationStartupCheck")
    Object tianquanSecurityObservationStartupCheck(@Qualifier("tokenUsageAuditComponent") TokenUsageAuditComponent producer,
            @Qualifier("oauthUsageObservationProperties") OAuthUsageObservationProperties properties,
            @Qualifier("defaultValidator") Validator validator,
            @Qualifier("idpMeterRegistrySupplier") Supplier<MeterRegistry> registries,
            @Qualifier("environment") org.springframework.core.env.Environment environment,
            @Qualifier("idpTransportBindingRegistry") ObjectProvider<IdpTransportBindingRegistry> transportBindings,
            @Qualifier("tianquanSecurityAuditReady") java.util.function.BooleanSupplier auditReady) {
        var schema = new ValidationUtils(validator);
        schema.validate(properties);
        registries.get();
        java.util.Objects.requireNonNull(producer, "producer");
        validateTransport(environment, properties);
        validatePhysicalBindings(environment, transportBindings, schema);
        if (!auditReady.getAsBoolean()) { throw new IllegalStateException("OAUTH_AUDIT_NOT_READY"); }
        return new Object();
    }

    /** Contributes to the existing Actuator readiness group without replacing other indicators. */
    @Bean(name = "tianquanAuditReadiness")
    org.springframework.boot.health.contributor.HealthIndicator tianquanAuditReadiness(
            @Qualifier("tianquanSecurityAuditReady") java.util.function.BooleanSupplier ready) {
        return () -> ready.getAsBoolean() ? org.springframework.boot.health.contributor.Health.up().build()
                : org.springframework.boot.health.contributor.Health.down().withDetail("failedCheck", "oauthAudit").build();
    }

    private void validateTransport(org.springframework.core.env.Environment environment, OAuthUsageObservationProperties usage) {
        var binder = org.springframework.boot.context.properties.bind.Binder.get(environment);
        var idp = binder.bind("egon.cola.platform.tianquan.shoubing", top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties.class)
                .orElseGet(top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties::new);
        boolean local = java.util.Arrays.asList(environment.getActiveProfiles()).contains("local")
                && java.util.Set.of("local", "dev").contains(environment.getProperty("DEPLOYMENT_ENV",
                        environment.getProperty("egon.cola.component.tianshu.env", ""))) && usage.isAllowLocalPlaintext();
        if (idp.getTrustedIssuers().isEmpty()) {
            secureEndpoint(idp.getIssuer(), "https", false);
            secureEndpoint(idp.getJwkSetUri(), "https", local);
        } else {
            for (var entry : idp.getTrustedIssuers().values()) {
                secureEndpoint(entry.getIssuer(), "https", false);
                secureEndpoint(entry.getJwksUri(), "https", false);
            }
        }
        secureEndpoint(idp.getResourceUri() == null ? null : idp.getResourceUri().toASCIIString(), "https", local);
        boolean trustedFallback = idp.getTrustedIssuers().isEmpty()
                ? usage.getFallbackIssuer().toASCIIString().equals(idp.getIssuer())
                : idp.getTrustedIssuers().values().stream().anyMatch(entry -> usage.getFallbackIssuer().toASCIIString().equals(entry.getIssuer())
                        && "ACTIVE".equals(entry.getStatus()));
        if (!trustedFallback) { throw new IllegalStateException("OAUTH_OBSERVATION_FALLBACK_UNTRUSTED"); }
        secureEndpoint(environment.getProperty("egon.cola.platform.tianquan.jianshen.authorization.endpoint"), "https", local);
        secureEndpoint(environment.getProperty("egon.tianquan-shoubing.oauth.public-origin"), "https", local);
        var clients = binder.bind("spring.security.oauth2.client", org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties.class)
                .orElseGet(org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties::new);
        for (var provider : clients.getProvider().values()) {
            if (provider.getIssuerUri() != null) { secureEndpoint(provider.getIssuerUri(), "https", false); }
            for (String endpoint : new String[] { provider.getTokenUri(), provider.getJwkSetUri(), provider.getAuthorizationUri(), provider.getUserInfoUri() }) {
                if (endpoint != null) { secureEndpoint(endpoint, "https", local); }
            }
        }
        // Native RPC validates its h2c contract; the ConfigData SDK validates its own fixed HTTP binding.
        // Neither transport inherits the retired application's TLS/certificate readiness requirement.
    }

    private void validatePhysicalBindings(org.springframework.core.env.Environment environment,
            ObjectProvider<IdpTransportBindingRegistry> registries, ValidationUtils schema) {
        var properties = org.springframework.boot.context.properties.bind.Binder.get(environment)
                .bind("egon.cola.platform.tianquan.shoubing.transport", IdpTransportBindingProperties.class)
                .orElseGet(IdpTransportBindingProperties::new);
        schema.validate(properties);
        if (properties.getBindings().isEmpty()) { return; }
        var registry = registries.getIfAvailable();
        if (registry == null) { throw new IllegalStateException("OAUTH_OBSERVATION_TRANSPORT_REGISTRY_REQUIRED"); }
        for (var entry : properties.getBindings().entrySet()) {
            var configured = entry.getValue();
            if (configured.getBindingId() != null && !entry.getKey().equals(configured.getBindingId())) {
                throw new IllegalStateException("OAUTH_OBSERVATION_TRANSPORT_BINDING_MISMATCH");
            }
            var expected = IdpTransportBindingConverter.INSTANCE.toTarget(configured.toBuilder().bindingId(entry.getKey()).build());
            var actual = registry.require(expected.bindingId(), expected.version(), expected.canonicalIssuer(),
                    expected.canonicalEndpoint(), expected.resource(), expected.registrationId(), expected.operation(), expected.method());
            // require checks the canonical tuple; equality also checks the namespace, Service, port and physical protocol.
            if (!expected.equals(actual)) { throw new IllegalStateException("OAUTH_OBSERVATION_TRANSPORT_BINDING_MISMATCH"); }
        }
    }

    private void secureEndpoint(String value, String scheme, boolean local) {
        if (value == null || value.isBlank()) { throw new IllegalStateException("OAUTH_OBSERVATION_ENDPOINT_REQUIRED"); }
        java.net.URI uri = java.net.URI.create(value);
        boolean plaintext = local && uri.getHost() != null && java.util.Set.of("localhost", "127.0.0.1", "[::1]").contains(uri.getHost())
                && ("https".equals(scheme) && "http".equals(uri.getScheme()) || "rediss".equals(scheme) && "redis".equals(uri.getScheme()));
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null
                || !scheme.equals(uri.getScheme()) && !plaintext) { throw new IllegalStateException("OAUTH_OBSERVATION_TLS_REQUIRED"); }
    }
}
