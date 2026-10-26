package top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static top.egon.cola.platform.tianquan.shoubing.starter.state.AuthorityTestFixture.settings;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import top.egon.cola.platform.tianquan.shoubing.core.observability.IdpSecurityMetricsRecorder;
import top.egon.cola.platform.tianquan.shoubing.starter.audit.TokenUsageAuditComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClient;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClientResolver;

class IdpSecurityObservationAutoConfigurationTest {
    private static final String PREFIX = "egon.cola.platform.tianquan.shoubing.";
    private final LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    private final IdentityAuthorityClient client = mock(IdentityAuthorityClient.class);
    private final IdentityAuthorityClientResolver resolver = issuer -> client;

    @BeforeEach void prepare() { validator.afterPropertiesSet(); }
    @AfterEach void close() { validator.close(); registry.close(); }

    @Test void authorityAndHostMetricsAssembleWithoutRedisOrFiles() {
        runner().withBean("registry", MeterRegistry.class, () -> registry).run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(TokenUsageAuditComponent.class)
                    .hasSingleBean(IdpSecurityMetricsRecorder.class).doesNotHaveBean("idpAuditRedissonClient")
                    .doesNotHaveBean("idpAuditSpoolLease").doesNotHaveBean("identityResourceServerStateReader")
                    .doesNotHaveBean("identityOAuthClientStateReader").doesNotHaveBean("reactiveOAuthRevocationReader");
            assertThat(context.getBean("idpSecurityAuditReady", BooleanSupplier.class).getAsBoolean()).isTrue();
            assertThat(context.getBean("idpSecurityAuditReady")).isSameAs(context.getBean("tianquanSecurityAuditReady"));
            assertThat(context.getBean(IdentityAuthorityClientResolver.class)).isSameAs(resolver);
            verifyNoInteractions(client);
        });
    }

    @Test void enabledObservationRequiresUniqueMetricsAndTrustedFallbackIssuer() {
        runner().run(context -> assertThat(context).hasFailed());
        var second = new SimpleMeterRegistry();
        try {
            runner().withBean("first", MeterRegistry.class, () -> registry).withBean("second", MeterRegistry.class, () -> second)
                    .run(context -> assertThat(context).hasFailed());
        } finally { second.close(); }
        runner().withBean("registry", MeterRegistry.class, () -> registry)
                .withPropertyValues(PREFIX + "usage-observation.fallback-issuer=https://other.example")
                .run(context -> assertThat(context).hasFailed());
        runner().withBean("registry", MeterRegistry.class, () -> registry)
                .withPropertyValues(PREFIX + "usage-observation.receiver=")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test void missingAuthorityDoesNotFallBackToRedisOrFilesystem() {
        new ApplicationContextRunner().withConfiguration(configurations()).withPropertyValues(settings())
                .withBean("jacksonObjectMapper", ObjectMapper.class, () -> new ObjectMapper().findAndRegisterModules())
                .withBean("defaultValidator", jakarta.validation.Validator.class, () -> validator)
                .withBean("registry", MeterRegistry.class, () -> registry)
                .withBean("unrelatedRedis", org.redisson.api.RedissonClient.class, () -> mock(org.redisson.api.RedissonClient.class))
                .run(context -> assertThat(context).hasFailed());
    }

    @Test void auditCannotBeDisabledOnTheFormalVerifierPath() {
        runner().withPropertyValues(PREFIX + "usage-observation.enabled=false")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test void configuredReadinessDoesNotPretendToProveRemoteDatabaseHealth() {
        runner().withBean("registry", MeterRegistry.class, () -> registry).run(context -> {
            assertThat(context).hasNotFailed();
            var observer = context.getBean(top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent.class);
            when(client.appendAudit(any())).thenThrow(new IllegalStateException("controlled SQL failure"));
            assertThat(context.getBean("idpSecurityAuditReady", BooleanSupplier.class).getAsBoolean()).isTrue();
            assertThat(observer.authenticationFailure()).isFalse();
            doAnswer(call -> top.egon.cola.platform.tianquan.shoubing.starter.state.AuthorityTestFixture.receipt(call.getArgument(0))).when(client).appendAudit(any());
            assertThat(observer.authenticationFailure()).isTrue();
        });
    }

    @Test void retiredSpoolConfigurationFailsWithMigrationDiagnostic() {
        runner().withBean("registry", MeterRegistry.class, () -> registry)
                .withPropertyValues(PREFIX + "audit.spool-directory=/must/not/be/touched")
                .run(context -> assertThat(context).hasFailed().getFailure().hasStackTraceContaining("migration required"));
    }

    @Test void disabledStarterDoesNotNeedOptionalMetricsAndEnabledObservationDoes() {
        new ApplicationContextRunner().withClassLoader(new FilteredClassLoader("io.micrometer.core"))
                .withConfiguration(AutoConfigurations.of(IdpSecurityObservationAutoConfiguration.class))
                .run(context -> assertThat(context).hasNotFailed().doesNotHaveBean("idpSecurityMetricsRecorder"));
        runner().withClassLoader(new FilteredClassLoader("io.micrometer.core"))
                .run(context -> assertThat(context).hasFailed());
    }

    @Test void servletObservationFilterIsNotInstantiatedInReactiveHost() {
        new ReactiveWebApplicationContextRunner().withConfiguration(configurations()).withPropertyValues(settings())
                .withBean("jacksonObjectMapper", ObjectMapper.class, () -> new ObjectMapper().findAndRegisterModules())
                .withBean("defaultValidator", jakarta.validation.Validator.class, () -> validator)
                .withBean("identityAuthorityClientResolver", IdentityAuthorityClientResolver.class, () -> resolver)
                .withBean("registry", MeterRegistry.class, () -> registry)
                .run(context -> assertThat(context).hasNotFailed().hasBean("idpObservedVerificationComponent")
                        .doesNotHaveBean("idpSecurityObservationFilter").doesNotHaveBean("idpSecurityObservationFilterRegistration"));
        new WebApplicationContextRunner().withConfiguration(configurations()).withPropertyValues(settings())
                .withBean("jacksonObjectMapper", ObjectMapper.class, () -> new ObjectMapper().findAndRegisterModules())
                .withBean("defaultValidator", jakarta.validation.Validator.class, () -> validator)
                .withBean("identityAuthorityClientResolver", IdentityAuthorityClientResolver.class, () -> resolver)
                .withBean("registry", MeterRegistry.class, () -> registry)
                .run(context -> assertThat(context).hasNotFailed().hasBean("idpSecurityObservationFilter")
                        .hasBean("idpSecurityObservationFilterRegistration"));
    }

    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner().withConfiguration(configurations()).withPropertyValues(settings())
                .withBean("jacksonObjectMapper", ObjectMapper.class, () -> new ObjectMapper().findAndRegisterModules())
                .withBean("defaultValidator", jakarta.validation.Validator.class, () -> validator)
                .withBean("identityAuthorityClientResolver", IdentityAuthorityClientResolver.class, () -> resolver);
    }

    private AutoConfigurations configurations() {
        return AutoConfigurations.of(IdpSecurityObservationAutoConfiguration.class, IdpStarterAutoConfiguration.class);
    }
}
