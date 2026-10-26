package top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure;

import io.micrometer.core.instrument.MeterRegistry;
import jakarta.validation.Validator;
import java.util.Objects;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import top.egon.cola.component.common.core.validation.ValidationUtils;
import top.egon.cola.platform.tianquan.shoubing.core.observability.IdpSecurityMetricsRecorder;
import top.egon.cola.platform.tianquan.shoubing.starter.audit.OAuthUsageObservationProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.audit.TokenUsageAuditComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TrustedIssuerRegistry;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClientResolver;
import top.egon.cola.platform.tianquan.shoubing.starter.observability.IdpSecurityMetricsComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.observability.IdpSecurityObservationReadinessComponent;

/** Reuses host metrics and validates SQL authority routing without creating local audit storage. */
@Slf4j
@AutoConfiguration("idpSecurityObservationAutoConfiguration")
@AutoConfigureBefore(IdpStarterAutoConfiguration.class)
public class IdpSecurityObservationAutoConfiguration {
    /** Keeps optional Micrometer types out of contexts where observation is disabled. */
    @Configuration(value = "idpObservationMetricsConfiguration", proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "egon.cola.platform.tianquan.shoubing.usage-observation", name = "enabled", havingValue = "true")
    @ConditionalOnClass(name = "io.micrometer.core.instrument.MeterRegistry")
    static class MetricsConfiguration {
        @Bean(name = "idpMeterRegistrySupplier")
        @ConditionalOnMissingBean(name = "idpMeterRegistrySupplier")
        Supplier<MeterRegistry> idpMeterRegistrySupplier(ObjectProvider<MeterRegistry> registries) {
            registries.getObject();
            return registries::getObject;
        }

        @Bean(name = "idpSecurityMetricsRecorder")
        @ConditionalOnMissingBean(IdpSecurityMetricsRecorder.class)
        IdpSecurityMetricsRecorder idpSecurityMetricsRecorder(
                @Qualifier("idpMeterRegistrySupplier") Supplier<MeterRegistry> registries,
                @Qualifier("defaultValidator") Validator validator,
                @Qualifier("oauthUsageObservationProperties") OAuthUsageObservationProperties usage) {
            new ValidationUtils(validator).validate(usage);
            return new IdpSecurityMetricsComponent(registries, validator, usage);
        }
    }

    @Configuration(value = "idpObservationReadinessConfiguration", proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "egon.cola.platform.tianquan.shoubing.usage-observation", name = "enabled", havingValue = "true")
    static class ReadinessConfiguration {
        @Bean(name = "idpSecurityObservationReadinessComponent")
        IdpSecurityObservationReadinessComponent idpSecurityObservationReadinessComponent(
                IdentityAuthorityClientResolver authority,
                @Qualifier("trustedIssuerRegistry") TrustedIssuerRegistry issuers,
                @Qualifier("oauthUsageObservationProperties") OAuthUsageObservationProperties usage,
                @Qualifier("idpMeterRegistrySupplier") Supplier<?> registry,
                @Qualifier("idpSecurityMetricsRecorder") IdpSecurityMetricsRecorder metrics) {
            registry.get();
            Objects.requireNonNull(metrics, "metrics");
            return new IdpSecurityObservationReadinessComponent(authority, issuers, usage);
        }

        @Bean(name = {"idpSecurityAuditReady", "tianquanSecurityAuditReady"})
        BooleanSupplier idpSecurityAuditReady(
                @Qualifier("idpSecurityObservationReadinessComponent") IdpSecurityObservationReadinessComponent readiness,
                @Qualifier("tokenUsageAuditComponent") TokenUsageAuditComponent producer) {
            Objects.requireNonNull(producer, "producer");
            BooleanSupplier ready = readiness.readiness();
            if (!ready.getAsBoolean()) { throw new IllegalStateException("OAUTH_AUDIT_NOT_READY"); }
            return ready;
        }
    }
}
