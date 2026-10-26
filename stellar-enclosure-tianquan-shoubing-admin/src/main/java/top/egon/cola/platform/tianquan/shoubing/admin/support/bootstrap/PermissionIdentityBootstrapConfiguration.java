package top.egon.cola.platform.tianquan.shoubing.admin.support.bootstrap;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import top.egon.cola.component.common.core.validation.ValidationUtils;
import top.egon.cola.component.common.mybatis.ddl.EgonColaPostgreDdlRunner;
import top.egon.cola.component.common.mybatis.routing.EgonColaRoutingProfileBO;
import top.egon.cola.component.common.mybatis.routing.EgonColaTwoLevelRouteStrategy;
import top.egon.cola.component.common.mybatis.routing.EgonColaWriteTargetResolver;
import top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties;
import top.egon.cola.component.common.mybatis.sharding.bootstrap.EgonColaShardingTopologyValidator;
import top.egon.cola.component.common.mybatis.sharding.resolver.EgonColaShardingWriteTargetResolver;
import top.egon.cola.component.outbox.autoconfigure.OutboxMpStorageProperties;
import top.egon.cola.component.outbox.migration.OutboxManagedDdlInitializer;

/** Explicitly registered non-web context: no application scan, runner, dispatcher, or scheduled jobs. */
@EnableTransactionManagement(proxyTargetClass = true)
@org.springframework.boot.context.properties.EnableConfigurationProperties(top.egon.cola.component.outbox.autoconfigure.TransactionalOutboxProperties.class)
@org.springframework.boot.autoconfigure.ImportAutoConfiguration({
        org.springframework.boot.validation.autoconfigure.ValidationAutoConfiguration.class,
        top.egon.cola.component.common.id.autoconfigure.IdGeneratorAutoConfiguration.class,
        top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusAutoConfiguration.class,
        com.baomidou.mybatisplus.autoconfigure.MybatisPlusAutoConfiguration.class,
        top.egon.cola.component.outbox.autoconfigure.OutboxMybatisPlusAutoConfiguration.class,
        top.egon.cola.component.outbox.autoconfigure.OutboxStateMachineAutoConfiguration.class})
@ComponentScan(basePackages = {
        "top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.impl",
        "top.egon.cola.platform.tianquan.shoubing.admin.token.repository.impl",
        "top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.impl",
        "top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.impl",
        "top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter",
        "top.egon.cola.platform.tianquan.shoubing.admin.token.domain.converter",
        "top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.converter",
        "top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.converter"})
@MapperScan(basePackages = "top.egon.cola.platform.tianquan.shoubing.admin", annotationClass = org.apache.ibatis.annotations.Mapper.class)
@Import({top.egon.cola.platform.tianquan.shoubing.admin.identity.repo.IdentityDirectoryContext.class,
        top.egon.cola.platform.tianquan.shoubing.admin.identity.repository.IdentityUserRepository.class,
        top.egon.cola.platform.tianquan.shoubing.admin.identity.domain.converter.IdentityUserConverterImpl.class,
        top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.TenantIssuerServiceImpl.class,
        top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthManagementRealmResolver.class,
        top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthClientServiceImpl.class,
        top.egon.cola.platform.tianquan.shoubing.admin.resource.service.impl.ResourceServerServiceImpl.class,
        top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.TokenRevocationServiceImpl.class,
        top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthSecurityProjectionComponent.class,
        top.egon.cola.platform.tianquan.shoubing.admin.support.outbox.service.IdentityOutboxPublisher.class,
        top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthPayloadCipherComponent.class,
        top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthKeyCipherComponent.class})
class PermissionIdentityBootstrapConfiguration {
    @Bean({"idpClock", "egonColaMybatisPlusClock"}) @Primary
    Clock clock() { return Clock.systemUTC(); }

    @Bean({"jacksonObjectMapper", "outboxStateMachineObjectMapper"})
    ObjectMapper mapper() { return PermissionIdentityBootstrapCli.mapper(); }

    @Bean("idpSecureRandom")
    java.security.SecureRandom random() { return new java.security.SecureRandom(); }

    @Bean("oauthPublicOrigin")
    URI publicOrigin(PermissionIdentityBootstrapCommand.Connection input) { return input.publicOrigin(); }

    @Bean("oauthKeyEncryptionProperties")
    top.egon.cola.platform.tianquan.shoubing.admin.token.config.OAuthKeyEncryptionProperties encryption(
            PermissionIdentityBootstrapCommand.Connection input) {
        return top.egon.cola.platform.tianquan.shoubing.admin.token.config.OAuthKeyEncryptionProperties.builder()
                .keyId(input.keyId()).keyFile(PermissionBootstrapFiles.path(input.keyFile())).build();
    }

    @Bean("egonColaShardingTopologyValidator")
    EgonColaShardingTopologyValidator topologyValidator(@Qualifier("egonColaValidationUtils") ValidationUtils validation) {
        return new EgonColaShardingTopologyValidator(validation);
    }

    @Bean("egon.cola.component.mybatis-plus.sharding-top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties")
    EgonColaShardingProperties sharding(PermissionIdentityBootstrapCommand.Connection input) {
        return EgonColaShardingProperties.builder().mode(EgonColaShardingProperties.ModeEnum.SHARDING)
                .configStyle(EgonColaShardingProperties.ConfigStyleEnum.NATIVE).nativeRulesResource("classpath:oauth-sharding-native.yml")
                .dataSources(List.of(new EgonColaShardingProperties.PhysicalDataSourceProperties("oauth_primary", "oauth_primary",
                        EgonColaShardingProperties.DataSourceRoleEnum.PRIMARY, "org.postgresql.Driver", input.jdbcUrl(), input.username(), ""))).build();
    }

    @Bean("permissionBootstrapTopology")
    EgonColaShardingTopologyValidator.TopologyBO topology(EgonColaShardingTopologyValidator validator,
            EgonColaShardingProperties properties) throws java.io.IOException {
        try (var yaml = new ClassPathResource("oauth-sharding-native.yml").getInputStream()) {
            return validator.validate(properties, yaml.readAllBytes());
        }
    }

    @Bean("egonColaShardingRouteFingerprint")
    String fingerprint(EgonColaShardingTopologyValidator.TopologyBO topology) { return topology.fingerprint(); }

    @Bean("egonColaRoutingProfiles")
    Map<String, EgonColaRoutingProfileBO> profiles(EgonColaShardingTopologyValidator.TopologyBO topology) { return topology.profiles(); }

    @Bean("egonColaWriteTargetResolver")
    EgonColaWriteTargetResolver writeTargetResolver(@Qualifier("egonColaRoutingProfiles") Map<String, EgonColaRoutingProfileBO> profiles,
            EgonColaTwoLevelRouteStrategy strategy, @Qualifier("egonColaValidationUtils") ValidationUtils validation,
            EgonColaShardingTopologyValidator.TopologyBO topology) {
        return new EgonColaShardingWriteTargetResolver(profiles, strategy, validation, topology.fingerprint());
    }

    @Bean("outboxManagedDdlInitializer")
    OutboxManagedDdlInitializer outboxDdl(EgonColaPostgreDdlRunner runner, EgonColaShardingTopologyValidator topology,
            @Qualifier("egonColaValidationUtils") ValidationUtils validation, EgonColaShardingProperties properties,
            @Qualifier("outboxStateMachineObjectMapper") ObjectMapper mapper) {
        return new OutboxManagedDdlInitializer(runner, topology, validation, properties,
                OutboxMpStorageProperties.builder().autoInitializeDdl(false).build(), mapper);
    }

    @Bean("dataSource") @Primary
    DataSource dataSource(@Qualifier("permissionBootstrapPhysicalDataSource") DataSource physical,
            EgonColaShardingTopologyValidator.TopologyBO topology, OutboxManagedDdlInitializer initializer) throws Exception {
        new top.egon.cola.platform.tianquan.shoubing.admin.oauth.config.OAuthStateSchemaValidator().validate(physical);
        return new top.egon.cola.component.outbox.migration.OutboxLogicalDataSourceFactory(initializer)
                .create(Map.of("oauth_primary", physical), topology.yaml());
    }

    @Bean("transactionManager") @Primary
    org.springframework.jdbc.datasource.DataSourceTransactionManager transactions(@Qualifier("dataSource") DataSource source) {
        return new org.springframework.jdbc.datasource.DataSourceTransactionManager(source);
    }

    @Bean("resourceServerEventAdapter")
    top.egon.cola.platform.tianquan.shoubing.admin.resource.support.outbox.TransactionalOutboxResourceServerEventAdapter resourceEvents(
            top.egon.cola.component.outbox.api.TransactionalOutbox outbox, @Qualifier("idpClock") Clock clock) {
        return new top.egon.cola.platform.tianquan.shoubing.admin.resource.support.outbox.TransactionalOutboxResourceServerEventAdapter(outbox, clock);
    }

    private record ProducerDestination(String channel, java.util.Set<String> destinations)
            implements top.egon.cola.component.outbox.delivery.DeliveryHandler {
        @Override public void validateDestination(String destination) {
            if (!destinations.contains(destination)) { throw new IllegalArgumentException("PERMISSION_BOOTSTRAP_DESTINATION_INVALID"); }
        }
        @Override public top.egon.cola.component.outbox.delivery.DeliveryResult deliver(
                top.egon.cola.component.outbox.delivery.DeliveryContext context) {
            throw new IllegalStateException("PERMISSION_BOOTSTRAP_DELIVERY_NOT_ENABLED");
        }
    }
        @Bean("outboxInfrastructure")
        top.egon.cola.component.outbox.autoconfigure.OutboxInfrastructure outboxInfrastructure(
                org.springframework.beans.factory.config.ConfigurableListableBeanFactory beans,
                top.egon.cola.component.outbox.autoconfigure.TransactionalOutboxProperties properties,
                @Qualifier("egonColaValidationUtils") ValidationUtils validation) {
            new top.egon.cola.component.outbox.autoconfigure.OutboxConfigurationValidator(validation).validate(properties);
            return new top.egon.cola.component.outbox.autoconfigure.OutboxInfrastructureResolver().resolve(beans, properties);
        }

        @Bean("outboxMessageValidator")
        top.egon.cola.component.outbox.validation.OutboxMessageValidator outboxMessageValidator(
                @Qualifier("jacksonObjectMapper") ObjectMapper mapper,
                top.egon.cola.component.outbox.autoconfigure.TransactionalOutboxProperties properties,
                @Qualifier("egonColaValidationUtils") ValidationUtils validation) {
            return new top.egon.cola.component.outbox.validation.OutboxMessageValidator(mapper,
                    Math.toIntExact(properties.getPayload().getMaxBytes().toBytes()), properties.getPayload().getMaxHeaderCount(),
                    Math.toIntExact(properties.getPayload().getMaxHeaderBytes().toBytes()), validation);
        }

        @Bean("outboxMetrics")
        top.egon.cola.component.outbox.observability.OutboxMetrics outboxMetrics() {
            return new top.egon.cola.component.outbox.observability.NoopOutboxMetrics();
        }

        @Bean("deliveryHandlerRegistry")
        top.egon.cola.component.outbox.delivery.DeliveryHandlerRegistry deliveryHandlerRegistry() {
            return new top.egon.cola.component.outbox.delivery.DeliveryHandlerRegistry(List.of(
                    new ProducerDestination("oauth-audit", java.util.Set.of("oauth.audit.identity.v1")),
                    new ProducerDestination(top.egon.cola.platform.tianquan.shoubing.core.audit.OAuthSecurityChangedEvent.OUTBOX_CHANNEL,
                            java.util.Set.of(top.egon.cola.platform.tianquan.shoubing.core.audit.OAuthSecurityChangedEvent.OUTBOX_DESTINATION)),
                    new ProducerDestination(top.egon.cola.platform.tianquan.shoubing.admin.resource.support.outbox.TransactionalOutboxResourceServerEventAdapter.PROJECTION_CHANNEL,
                            java.util.Set.of(top.egon.cola.platform.tianquan.shoubing.admin.resource.support.outbox.TransactionalOutboxResourceServerEventAdapter.RESOURCE_PROJECTION_DESTINATION,
                                    top.egon.cola.platform.tianquan.shoubing.admin.resource.support.outbox.TransactionalOutboxResourceServerEventAdapter.SERVICE_GRANT_PROJECTION_DESTINATION)),
                    new ProducerDestination(top.egon.cola.platform.tianquan.shoubing.admin.resource.support.outbox.TransactionalOutboxResourceServerEventAdapter.CHANNEL,
                            java.util.Set.of(top.egon.cola.platform.tianquan.shoubing.admin.resource.support.outbox.TransactionalOutboxResourceServerEventAdapter.DISABLED_DESTINATION))));
        }

        @Bean("transactionalOutbox")
        top.egon.cola.component.outbox.api.TransactionalOutbox transactionalOutbox(
                @Qualifier("outboxMessageValidator") top.egon.cola.component.outbox.validation.OutboxMessageValidator validator,
                @Qualifier("outboxInfrastructure") top.egon.cola.component.outbox.autoconfigure.OutboxInfrastructure infrastructure,
                @Qualifier("outboxStore") top.egon.cola.component.outbox.store.OutboxStore store,
                @Qualifier("deliveryHandlerRegistry") top.egon.cola.component.outbox.delivery.DeliveryHandlerRegistry handlers,
                @Qualifier("outboxMetrics") top.egon.cola.component.outbox.observability.OutboxMetrics metrics,
                @Qualifier("jacksonObjectMapper") ObjectMapper mapper,
                org.springframework.context.ApplicationEventPublisher events,
                top.egon.cola.component.outbox.autoconfigure.TransactionalOutboxProperties properties) {
            return new top.egon.cola.component.outbox.transaction.DefaultTransactionalOutbox(validator,
                    new top.egon.cola.component.outbox.serialization.JacksonOutboxMessageSerializer(mapper),
                    new top.egon.cola.component.outbox.api.UuidOutboxIdGenerator(), mapper,
                    new top.egon.cola.component.outbox.transaction.OutboxTransactionGuard(infrastructure.dataSource()),
                    store, handlers, new top.egon.cola.component.outbox.transaction.OutboxAfterCommitBuffer(events, metrics),
                    metrics, properties);
        }

        @Bean(name = "outboxSchemaValidator", initMethod = "validate")
        top.egon.cola.component.outbox.store.OutboxSchemaValidator outboxSchemaValidator(
                @Qualifier("outboxStore") top.egon.cola.component.outbox.store.OutboxStore store,
                @Qualifier("egonColaValidationUtils") ValidationUtils validation) {
            return new top.egon.cola.component.outbox.store.OutboxSchemaValidator(store, validation);
        }


}
