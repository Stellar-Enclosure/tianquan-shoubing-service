package top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.bind.BindHandler;
import org.springframework.boot.context.properties.bind.handler.NoUnboundElementsBindHandler;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.RestClientClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTypeValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpClientCredentialsRequestEntityConverter;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.security.CurrentIdentity;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpBearerAuthenticationFilter;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpEndpointAuthenticationPolicy;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpJwtVerifier;
import top.egon.cola.platform.tianquan.shoubing.starter.security.OAuthRevocationReader;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TenantIssuerAuthenticationManagerComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TrustedIssuerRegistry;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedPrincipalConverter;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedTenantContextFilter;
import top.egon.cola.platform.tianquan.shoubing.starter.security.ServiceAccessTokenVerifier;
import top.egon.cola.platform.tianquan.shoubing.starter.security.UserAccessTokenVerifier;
import top.egon.cola.platform.tianquan.shoubing.starter.security.RetryingJwtDecoder;
import top.egon.cola.platform.tianquan.shoubing.starter.security.ServiceScopeAuthorization;
import top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcBearerServerInterceptor;
import top.egon.cola.platform.tianquan.shoubing.starter.security.rpc.IdpRpcClientCredentialInterceptorFactory;
import top.egon.cola.platform.tianquan.shoubing.core.observability.IdpSecurityMetricsRecorder;
import top.egon.cola.platform.tianquan.shoubing.starter.audit.OAuthUsageObservationProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpSecurityObservationFilter;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.converter.TokenUsageAuditEventConverter;
import top.egon.cola.platform.tianquan.shoubing.starter.audit.TokenUsageAuditComponent;

import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClientResolver;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.state.ConfiguredIdentityAuthorityClients;
import top.egon.cola.platform.tianquan.shoubing.starter.security.impl.DatabaseOAuthRevocationReader;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

/**
 * 为普通 Servlet 资源服务器装配统一 Tianquan-Shoubing 身份验证能力。
 * 本配置创建 Spring OAuth2 Client SERVICE facade、JWT 解码器、用户实时状态读取器、身份验证器与
 * Bearer 过滤器；它不签发 OAuth Access Token，也不执行接口权限判断。
 *
 * <p>Auto-configures unified Tianquan-Shoubing identity verification for regular Servlet resource servers.
 * It creates the OAuth2 Client facade, JWT decoder, service-state readers, identity
 * verifier, and Bearer filter. It neither issues OAuth access tokens nor makes endpoint
 * authorization decisions.</p>
 */
@AutoConfiguration
@AutoConfigureAfter(OAuth2ClientAutoConfiguration.class)
@EnableConfigurationProperties
@Import({
        IdpStarterAutoConfiguration.OAuthAuditConfiguration.class,
        IdpStarterAutoConfiguration.VerifiedPrincipalConverterConfiguration.class
})
@ConditionalOnProperty(
        prefix = "egon.cola.platform.tianquan.shoubing",
        name = "enabled",
        havingValue = "true")
public class IdpStarterAutoConfiguration {

    /** Retains the SDK mapper qualifier with Boot 4's Jackson 2 compatibility module. */
    @Bean
    public static BeanFactoryPostProcessor idpJacksonObjectMapperAlias() {
        return beanFactory -> {
            if (beanFactory.containsBean("jackson2ObjectMapper") && !beanFactory.containsBean("jacksonObjectMapper")) {
                beanFactory.registerAlias("jackson2ObjectMapper", "jacksonObjectMapper");
            }
        };
    }

    @Configuration(proxyBeanMethods = false)
    @ComponentScan(basePackageClasses = VerifiedPrincipalConverter.class)
    public static class VerifiedPrincipalConverterConfiguration {
    }

    @Configuration(proxyBeanMethods = false)
    public static class OAuthAuditConfiguration {
        @Bean(name = "tokenUsageAuditComponent")
        @ConditionalOnMissingBean(TokenUsageAuditComponent.class)
        public TokenUsageAuditComponent tokenUsageAuditComponent(
                IdentityAuthorityClientResolver authority,
                @Qualifier("idpClock") Clock clock,
                @Qualifier("defaultValidator") jakarta.validation.Validator validator,
                @Qualifier("idpSecurityMetricsRecorder") ObjectProvider<IdpSecurityMetricsRecorder> metrics) {
            return new TokenUsageAuditComponent(authority, clock, validator,
                    metrics.getIfAvailable(() -> IdpSecurityMetricsRecorder.NOOP));
        }
    }

    @Bean(name = "oauthUsageObservationProperties")
    OAuthUsageObservationProperties oauthUsageObservationProperties() {
        return new OAuthUsageObservationProperties();
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "egon.cola.platform.tianquan.shoubing.usage-observation", name = "enabled", havingValue = "true")
    public static class UsageObservationConfiguration {
        @Bean(name = "idpObservedVerificationComponent")
        IdpObservedVerificationComponent idpObservedVerificationComponent(
                @Qualifier("tokenUsageAuditComponent") TokenUsageAuditComponent producer,
                @Qualifier("tokenUsageAuditEventConverterImpl") TokenUsageAuditEventConverter converter,
                @Qualifier("oauthUsageObservationProperties") OAuthUsageObservationProperties properties,
                @Qualifier("idpSecurityMetricsRecorder") IdpSecurityMetricsRecorder metrics,
                @Qualifier("idpClock") Clock clock,
                @Qualifier("defaultValidator") jakarta.validation.Validator validator,
                @Qualifier("idpStarterProperties") IdpStarterProperties receiver,
                @Qualifier("idpSecurityAuditReady") java.util.function.BooleanSupplier ready) {
            return new IdpObservedVerificationComponent(producer, converter, properties, metrics, clock, validator, receiver.getResourceUri(), ready);
        }

        @Bean(name = "idpSecurityObservationFilter")
        @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
        IdpSecurityObservationFilter idpSecurityObservationFilter(
                @Qualifier("idpObservedVerificationComponent") IdpObservedVerificationComponent observations,
                IdpEndpointAuthenticationPolicy endpointPolicy) {
            return new IdpSecurityObservationFilter(observations, endpointPolicy);
        }

        @Bean(name = "idpSecurityObservationFilterRegistration")
        @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
        org.springframework.boot.web.servlet.FilterRegistrationBean<IdpSecurityObservationFilter> idpSecurityObservationFilterRegistration(
                @Qualifier("idpSecurityObservationFilter") IdpSecurityObservationFilter filter) {
            var registration = new org.springframework.boot.web.servlet.FilterRegistrationBean<>(filter);
            registration.setEnabled(false);
            return registration;
        }
    }

    /**
     * 创建 Tianquan-Shoubing Starter 自动配置实例。
     *
     * <p>Creates the Tianquan-Shoubing Starter auto-configuration instance.</p>
     */
    public IdpStarterAutoConfiguration() {
    }

    /** Exposes the request-bound verified USER identity accessor. */
    @Bean(name = "currentIdentity")
    @ConditionalOnMissingBean
    public CurrentIdentity currentIdentity() {
        return new CurrentIdentity();
    }

    @Bean(name = "idpStarterProperties")
    @ConfigurationProperties("egon.cola.platform.tianquan.shoubing")
    @ConditionalOnMissingBean(name = "idpStarterProperties")
    public IdpStarterProperties idpStarterProperties() {
        return new IdpStarterProperties();
    }

    @Bean(name = "idpClock")
    @ConditionalOnMissingBean(name = "idpClock")
    public Clock idpClock() {
        return Clock.systemUTC();
    }

    @Bean(name = "trustedIssuerRegistry")
    @ConditionalOnMissingBean(name = "trustedIssuerRegistry")
    public TrustedIssuerRegistry trustedIssuerRegistry(@Qualifier("idpStarterProperties") IdpStarterProperties properties) {
        return new TrustedIssuerRegistry(properties);
    }

    @Bean(name = "verifiedPrincipalConverter")
    @Primary
    @ConditionalOnBean(name = "verifiedPrincipalConverterImpl")
    @ConditionalOnMissingBean(name = "verifiedPrincipalConverter")
    public VerifiedPrincipalConverter verifiedPrincipalConverter(
            @Qualifier("verifiedPrincipalConverterImpl") VerifiedPrincipalConverter generatedConverter) {
        return generatedConverter;
    }

    @Bean(name = "tenantIssuerAuthenticationManagerComponent")
    @ConditionalOnMissingBean(name = "tenantIssuerAuthenticationManagerComponent")
    public TenantIssuerAuthenticationManagerComponent tenantIssuerAuthenticationManagerComponent(
            @Qualifier("trustedIssuerRegistry") TrustedIssuerRegistry trustedIssuerRegistry,
            @Qualifier("idpStarterProperties") IdpStarterProperties properties,
            @Qualifier("idpClock") Clock idpClock,
            @Qualifier("idpSecurityMetricsRecorder") ObjectProvider<IdpSecurityMetricsRecorder> metrics) {
        TenantIssuerAuthenticationManagerComponent component =
                new TenantIssuerAuthenticationManagerComponent(
                        trustedIssuerRegistry, properties, idpClock, metrics.getIfAvailable(() -> IdpSecurityMetricsRecorder.NOOP));
        component.initialize();
        return component;
    }

    @Bean(name = "identityAuthorityProperties")
    @ConfigurationProperties("egon.cola.platform.tianquan.shoubing.authority")
    public IdentityAuthorityProperties identityAuthorityProperties() {
        return new IdentityAuthorityProperties();
    }

    /** Local database owners provide this port directly; other hosts use one finite SERVICE binding per issuer. */
    @Bean(name = "identityAuthorityClientResolver")
    @ConditionalOnMissingBean(IdentityAuthorityClientResolver.class)
    public IdentityAuthorityClientResolver identityAuthorityClientResolver(
            @Qualifier("identityAuthorityProperties") IdentityAuthorityProperties authority,
            @Qualifier("idpStarterProperties") IdpStarterProperties properties,
            @Qualifier("trustedIssuerRegistry") TrustedIssuerRegistry issuers,
            @Qualifier("idpServiceOAuth2Client") IdpServiceOAuth2Client serviceClient,
            @Qualifier("jacksonObjectMapper") ObjectMapper mapper) {
        return new ConfiguredIdentityAuthorityClients(authority, properties, issuers, serviceClient, mapper);
    }

    @Bean(name = "oauthRevocationReader")
    @ConditionalOnMissingBean(OAuthRevocationReader.class)
    public OAuthRevocationReader oauthRevocationReader(IdentityAuthorityClientResolver authority,
            @Qualifier("idpStarterProperties") IdpStarterProperties properties) {
        return new DatabaseOAuthRevocationReader(authority, properties.getResourceUri());
    }

    @Bean(name = "verifiedTenantContextFilter")
    @ConditionalOnMissingBean(name = "verifiedTenantContextFilter")
    public VerifiedTenantContextFilter verifiedTenantContextFilter() {
        return new VerifiedTenantContextFilter();
    }

    /** Creates the request converter used by the standard client-credentials provider. */
    @Bean(name = "idpClientCredentialsRequestEntityConverter")
    @ConditionalOnBean(ClientRegistrationRepository.class)
    @ConditionalOnMissingBean
    public IdpClientCredentialsRequestEntityConverter
            idpClientCredentialsRequestEntityConverter() {
        return new IdpClientCredentialsRequestEntityConverter();
    }

    /** Provides the default in-memory authorized-client store for service tokens. */
    @Bean(name = "idpOAuth2AuthorizedClientService")
    @ConditionalOnBean(ClientRegistrationRepository.class)
    @ConditionalOnMissingBean
    public OAuth2AuthorizedClientService idpOAuth2AuthorizedClientService(
            ClientRegistrationRepository registrations
    ) {
        return new InMemoryOAuth2AuthorizedClientService(registrations);
    }

    /**
     * Configures Spring's client-credentials provider with the Tianquan-Shoubing extension converter.
     */
    @Bean(name = "idpOAuth2AuthorizedClientManager")
    @ConditionalOnBean({
            ClientRegistrationRepository.class,
            OAuth2AuthorizedClientService.class
    })
    @ConditionalOnMissingBean(OAuth2AuthorizedClientManager.class)
    @ConditionalOnProperty(
            prefix = "egon.cola.platform.tianquan.shoubing.service-client",
            name = {"app-id", "registration-id"}
    )
    public OAuth2AuthorizedClientManager idpOAuth2AuthorizedClientManager(
            ClientRegistrationRepository registrations,
            OAuth2AuthorizedClientService authorizedClients,
            IdpClientCredentialsRequestEntityConverter converter,
            @Qualifier("idpStarterProperties") IdpStarterProperties properties,
            @Qualifier("identityAuthorityProperties") IdentityAuthorityProperties authorityProperties
    ) {
        properties.getServiceClient().validate();
        RestClientClientCredentialsTokenResponseClient responseClient =
                new RestClientClientCredentialsTokenResponseClient();
        responseClient.setRestClient(top.egon.cola.platform.tianquan.shoubing.starter.state.HttpIdentityAuthorityClient
                .boundedTransport(authorityProperties.getTimeout()).mutate().configureMessageConverters(converters -> {
                    converters.addCustomConverter(new org.springframework.http.converter.FormHttpMessageConverter());
                    converters.addCustomConverter(new org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter());
                }).defaultStatusHandler(new org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler()).build());
        responseClient.setHeadersConverter(converter::convertHeaders);
        responseClient.setParametersConverter(converter::convertParameters);
        ClientCredentialsOAuth2AuthorizedClientProvider provider =
                new ClientCredentialsOAuth2AuthorizedClientProvider();
        provider.setClockSkew(
                properties.getServiceClient().getRenewalSkew()
        );
        provider.setAccessTokenResponseClient(responseClient);
        AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                        registrations,
                        authorizedClients
                );
        manager.setAuthorizedClientProvider(provider);
        return manager;
    }

    /** Creates the one recommended SERVICE-token API for biz services. */
    @Bean(name = "idpServiceOAuth2Client")
    @ConditionalOnBean({
            OAuth2AuthorizedClientManager.class,
            ClientRegistrationRepository.class,
            OAuth2AuthorizedClientService.class
    })
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
            prefix = "egon.cola.platform.tianquan.shoubing.service-client",
            name = {"app-id", "registration-id"}
    )
    public IdpServiceOAuth2Client idpServiceOAuth2Client(
            @Qualifier("idpOAuth2AuthorizedClientManager") OAuth2AuthorizedClientManager manager,
            @Qualifier("idpClientCredentialsRequestEntityConverter") IdpClientCredentialsRequestEntityConverter converter,
            @Qualifier("clientRegistrationRepository") ClientRegistrationRepository registrations,
            OAuth2AuthorizedClientService authorizedClients,
            @Qualifier("trustedIssuerRegistry") TrustedIssuerRegistry trustedIssuerRegistry,
            @Qualifier("idpStarterProperties") IdpStarterProperties properties,
            @Qualifier("idpClock") Clock idpClock,
            @Qualifier("idpSecurityMetricsRecorder") ObjectProvider<IdpSecurityMetricsRecorder> metrics
    ) {
        properties.getServiceClient().validate();
        return IdpServiceOAuth2Client.createConfigured(
                manager,
                converter,
                idpClock,
                properties.getServiceClient().getRenewalSkew(),
                registrations,
                authorizedClients,
                trustedIssuerRegistry,
                properties,
                metrics.getIfAvailable(() -> IdpSecurityMetricsRecorder.NOOP)
        );
    }

    /** Fails explicitly when retired private-key/Admission settings remain configured. */
    @Bean
    @ConditionalOnProperty(
            prefix = "egon.cola.platform.tianquan.shoubing",
            name = "enabled",
            havingValue = "true"
    )
    public Object idpLegacyConfigurationMigrationGuard(
            Environment environment
    ) {
        List<String> retired = List.of(
                "egon.cola.platform.tianquan.shoubing.admission.private-key-path",
                "egon.cola.platform.tianquan.shoubing.admission.management-client-id",
                "egon.cola.platform.tianquan.shoubing.admission.rpc-target",
                "egon.tianquan-shoubing.tianquan-jianshen.service-token.private-key-file",
                "egon.tianquan-shoubing.tianquan-jianshen.service-token.key-id",
                "egon.tianquan-shoubing.oauth.client-assertion-key-prefix",
                "egon.cola.platform.tianquan.shoubing.resource-state-key-prefix",
                "egon.cola.platform.tianquan.shoubing.oauth-client-state-key-prefix",
                "egon.cola.platform.tianquan.shoubing.audit.spool-directory",
                "egon.cola.platform.tianquan.shoubing.audit.hmac-key-file",
                "egon.cola.platform.tianquan.shoubing.audit.stream",
                "egon.cola.platform.tianquan.shoubing.revocation.key-prefix",
                "egon.cola.platform.tianquan.shoubing.revocation.mode",
                "egon.cola.platform.tianquan.shoubing.revocation.primary-endpoint",
                "egon.cola.platform.tianquan.shoubing.revocation.epoch",
                "egon.cola.platform.tianquan.shoubing.migration.legacy-issuer",
                "egon.cola.platform.tianquan.shoubing.migration.legacy-tenant-allowlist-key",
                "egon.cola.platform.tianquan.shoubing.migration.legacy-enabled"
        );
        List<String> configured = retired.stream()
                .filter(environment::containsProperty)
                .toList();
        if (!configured.isEmpty()) {
            throw new IllegalStateException(
                    "Tianquan-Shoubing OAuth2 Client migration required; retired properties configured: "
                            + String.join(", ", configured)
            );
        }
        return new Object();
    }

    /**
     * 创建支持 JWK 刷新的 Tianquan-Shoubing JWT 解码器。
     *
     * <p>Creates the Tianquan-Shoubing JWT decoder with one-time JWK refresh support.</p>
     *
     * @param properties Tianquan-Shoubing Starter 配置；Tianquan-Shoubing Starter settings
     * @return 名为 {@code idpJwtDecoder} 的 JWT 解码器；the JWT decoder named
     *         {@code idpJwtDecoder}
     */
    @Bean(name = "idpJwtDecoder")
    @ConditionalOnProperty(
            prefix = "egon.cola.platform.tianquan.shoubing",
            name = {"issuer", "jwk-set-uri"})
    @ConditionalOnMissingBean(name = "idpJwtDecoder")
    public JwtDecoder idpJwtDecoder(@Qualifier("idpStarterProperties") IdpStarterProperties properties) {
        properties.validate();
        return new RetryingJwtDecoder(() -> decoder(properties));
    }

    /** Every protected decision requires the current SQL authority state and a confirmed durable audit event. */
    @Bean(name = "idpJwtVerifier")
    @ConditionalOnMissingBean
    public IdpJwtVerifier idpJwtVerifier(
            @Qualifier("idpStarterProperties") IdpStarterProperties properties,
            @Qualifier("tenantIssuerAuthenticationManagerComponent") TenantIssuerAuthenticationManagerComponent manager,
            @Qualifier("oauthRevocationReader") OAuthRevocationReader revocations,
            @Qualifier("verifiedPrincipalConverter") VerifiedPrincipalConverter converter,
            @Qualifier("idpClock") Clock clock,
            @Qualifier("idpObservedVerificationComponent") IdpObservedVerificationComponent observations) {
        properties.validateJwtVerification();
        return IdpJwtVerifier.createDatabaseConfigured(properties.getResourceUri(), clock, manager,
                revocations, converter, observations);
    }

    /**
     * Exposes the stateless USER-token verifier to internal subject-token adapters.
     */
    @Bean
    @ConditionalOnBean(IdpJwtVerifier.class)
    @ConditionalOnMissingBean
    public UserAccessTokenVerifier userAccessTokenVerifier(IdpJwtVerifier verifier) {
        return new UserAccessTokenVerifier(verifier);
    }

    /**
     * Creates the trusted local RPC credential selector, retaining USER relay when disabled.
     *
     * @return trusted RPC USER credential relay
     */
    @Bean(name = "idpRpcClientCredentialInterceptorFactory")
    @ConditionalOnBean(UserAccessTokenVerifier.class)
    @ConditionalOnMissingBean
    public IdpRpcClientCredentialInterceptorFactory
            idpRpcClientCredentialInterceptorFactory(
                    @Qualifier("idpStarterProperties") IdpStarterProperties properties,
                    @Qualifier("idpServiceOAuth2Client") ObjectProvider<IdpServiceOAuth2Client> clients,
                    @Qualifier("defaultValidator") ObjectProvider<jakarta.validation.Validator> validators,
                    Environment environment) {
        validateRpcBindings(properties, validators.getIfAvailable(), environment);
        return IdpRpcClientCredentialInterceptorFactory.createConfigured(clients.getIfAvailable(), properties, validators.getIfAvailable());
    }

    /** Preserves the former direct factory call for USER-only consumers. */
    public IdpRpcClientCredentialInterceptorFactory idpRpcClientCredentialInterceptorFactory() {
        return new IdpRpcClientCredentialInterceptorFactory();
    }

    /**
     * Creates the RPC provider policy chain with the existing single-pass JWT verifier.
     *
     * @param verifier shared USER access-token verifier
     * @return RPC USER Bearer server interceptor
     */
    @Bean(name = "idpRpcBearerServerInterceptor")
    @ConditionalOnBean(UserAccessTokenVerifier.class)
    @ConditionalOnMissingBean
    public IdpRpcBearerServerInterceptor idpRpcBearerServerInterceptor(
            @Qualifier("userAccessTokenVerifier") UserAccessTokenVerifier verifier,
            @Qualifier("idpJwtVerifier") IdpJwtVerifier combinedVerifier,
            @Qualifier("idpStarterProperties") IdpStarterProperties properties,
            @Qualifier("idpObservedVerificationComponent") ObjectProvider<IdpObservedVerificationComponent> observations,
            @Qualifier("defaultValidator") ObjectProvider<jakarta.validation.Validator> validators,
            Environment environment
    ) {
        validateRpcBindings(properties, validators.getIfAvailable(), environment);
        return IdpRpcBearerServerInterceptor.createConfigured(verifier, combinedVerifier, properties, observations.getIfAvailable(), validators.getIfAvailable());
    }

    /** Preserves the former direct factory call for optional USER-only providers. */
    public IdpRpcBearerServerInterceptor idpRpcBearerServerInterceptor(UserAccessTokenVerifier verifier) {
        return new IdpRpcBearerServerInterceptor(verifier);
    }

    private void validateRpcBindings(IdpStarterProperties properties, jakarta.validation.Validator validator, Environment environment) {
        // Limit strict binding to RPC: unrelated opt-in observation configuration owns its own keys.
        Binder.get(environment).bind("egon.cola.platform.tianquan.shoubing.rpc", Bindable.ofInstance(properties.getRpc()),
                new NoUnboundElementsBindHandler(BindHandler.DEFAULT));
        if (properties.getRpc().isEnabled()) {
            new top.egon.cola.component.common.core.validation.ValidationUtils(
                    java.util.Objects.requireNonNull(validator, "defaultValidator")).validate(properties.getRpc());
        }
    }

    /**
     * Exposes the explicit SERVICE-token verifier used by SERVICE-only endpoint policies.
     */
    @Bean
    @ConditionalOnBean(IdpJwtVerifier.class)
    @ConditionalOnMissingBean
    public ServiceAccessTokenVerifier serviceAccessTokenVerifier(IdpJwtVerifier verifier) {
        return new ServiceAccessTokenVerifier(verifier);
    }

    /**
     * Provides a fail-closed-capable default endpoint policy for resource applications.
     */
    @Bean
    @ConditionalOnMissingBean
    public IdpEndpointAuthenticationPolicy idpEndpointAuthenticationPolicy() {
        return new IdpEndpointAuthenticationPolicy();
    }

    /**
     * 创建只读取 Tianquan-Shoubing SERVICE Token Scope 的本地授权判断器。
     *
     * <p>Creates the local authorization evaluator that reads only scopes from Tianquan-Shoubing SERVICE
     * tokens.</p>
     *
     * @return SERVICE Scope 判断器；SERVICE scope evaluator
     */
    @Bean
    @ConditionalOnMissingBean
    public ServiceScopeAuthorization serviceScopeAuthorization() {
        return new ServiceScopeAuthorization();
    }

    /**
     * 创建把已验证身份写入 Spring Security 上下文的 Bearer 过滤器。
     *
     * <p>Creates the Bearer filter that stores a verified identity in the Spring Security
     * context.</p>
     *
     * @param userAccessTokenVerifier USER access-token verifier
     * @param serviceAccessTokenVerifier SERVICE access-token verifier
     * @param endpointAuthenticationPolicy endpoint credential policy
     * @param objectMapper 认证失败响应的 JSON 序列化器；JSON mapper for authentication failures
     * @return Tianquan-Shoubing Bearer 身份过滤器；Tianquan-Shoubing Bearer identity filter
     */
    @Bean
    @ConditionalOnBean(IdpJwtVerifier.class)
    @ConditionalOnMissingBean
    public IdpBearerAuthenticationFilter idpBearerAuthenticationFilter(
            @Qualifier("userAccessTokenVerifier") UserAccessTokenVerifier userAccessTokenVerifier,
            @Qualifier("serviceAccessTokenVerifier") ServiceAccessTokenVerifier serviceAccessTokenVerifier,
            IdpEndpointAuthenticationPolicy endpointAuthenticationPolicy,
            @Qualifier("jacksonObjectMapper") ObjectMapper objectMapper,
            @Qualifier("verifiedTenantContextFilter") VerifiedTenantContextFilter verifiedTenantContextFilter,
            @Qualifier("idpJwtVerifier") IdpJwtVerifier combinedVerifier
    ) {
        return IdpBearerAuthenticationFilter.create(
                userAccessTokenVerifier,
                serviceAccessTokenVerifier,
                endpointAuthenticationPolicy,
                objectMapper,
                verifiedTenantContextFilter,
                combinedVerifier);
    }

    /**
     * 注册 Tianquan-Shoubing Bearer 过滤器并设置其 Servlet 执行顺序。
     * 是否启用注册由 {@code registerFilter} 配置控制。
     *
     * <p>Registers the Tianquan-Shoubing Bearer filter and assigns its Servlet ordering. Registration can be
     * disabled through the {@code registerFilter} setting.</p>
     *
     * @param filter Tianquan-Shoubing Bearer 身份过滤器；Tianquan-Shoubing Bearer identity filter
     * @param properties Tianquan-Shoubing Starter 配置；Tianquan-Shoubing Starter settings
     * @return Servlet 过滤器注册对象；Servlet filter registration
     */
    @Bean
    @ConditionalOnBean(IdpBearerAuthenticationFilter.class)
    @ConditionalOnMissingBean(name = "idpBearerFilterRegistration")
    public FilterRegistrationBean<IdpBearerAuthenticationFilter>
            idpBearerFilterRegistration(
                    IdpBearerAuthenticationFilter filter,
                    @Qualifier("idpStarterProperties") IdpStarterProperties properties) {
        FilterRegistrationBean<IdpBearerAuthenticationFilter> registration =
                new FilterRegistrationBean<>(filter);
        registration.setName("idpBearerAuthenticationFilter");
        registration.setOrder(-102);
        registration.setEnabled(properties.isRegisterFilter());
        return registration;
    }

    /**
     * 根据 JWK Set 地址构造 Nimbus 解码器，并校验签发方和时间窗口。
     *
     * <p>Builds a Nimbus decoder from the JWK Set endpoint and validates issuer and time claims.
     * USER and SERVICE verifiers apply their own exact audience policy after decoding.</p>
     *
     * @param properties 已完成校验的 Tianquan-Shoubing Starter 配置；validated Tianquan-Shoubing Starter settings
     * @return 配置完成的 JWT 解码器；configured JWT decoder
     */
    private JwtDecoder decoder(@Qualifier("idpStarterProperties") IdpStarterProperties properties) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(
                        properties.getJwkSetUri().trim())
                .validateType(false)
                .build();
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(JwtValidators.createDefaultWithValidators(
                new JwtIssuerValidator(properties.getIssuer().trim()),
                new JwtTypeValidator("at+jwt")));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validators));
        return decoder;
    }

}
