package top.egon.cola.platform.tianquan.shoubing.admin.oauth.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import top.egon.cola.component.common.mybatis.sharding.bootstrap.EgonColaShardingDataSourceBootstrapper.LogicalDataSourceFactory;
import top.egon.cola.component.outbox.migration.OutboxLogicalDataSourceFactory;
import top.egon.cola.component.outbox.migration.OutboxManagedDdlInitializer;

import java.time.Clock;
import java.util.Map;
import javax.sql.DataSource;
import org.mybatis.spring.annotation.MapperScan;
import top.egon.cola.platform.tianquan.shoubing.admin.IdpAdminApplication;

@Configuration(proxyBeanMethods = false)
@MapperScan(basePackageClasses = IdpAdminApplication.class, annotationClass = org.apache.ibatis.annotations.Mapper.class)
public class OAuthPersistenceConfiguration {

    @Bean("egonColaMybatisPlusClock")
    public Clock egonColaMybatisPlusClock(@Qualifier("idpClock") Clock idpClock) {
        return idpClock;
    }

    @Bean("egonColaShardingLogicalDataSourceFactory")
    public LogicalDataSourceFactory egonColaShardingLogicalDataSourceFactory(
            OAuthManagedDdlComponent oauthManagedDdlComponent,
            @Qualifier("outboxManagedDdlInitializer") OutboxManagedDdlInitializer outboxDdlInitializer) {
        return new OutboxLogicalDataSourceFactory(outboxDdlInitializer) {
            @Override
            public DataSource create(Map<String, DataSource> physical, byte[] yaml) throws Exception {
                oauthManagedDdlComponent.initialize(physical, yaml);
                return super.create(physical, yaml);
            }
        };
    }

    @Bean("transactionManager")
    @Primary
    public DataSourceTransactionManager transactionManager(@Qualifier("dataSource") DataSource dataSource) {
        return new DataSourceTransactionManager(dataSource);
    }

    @Bean("oauthOutboxIdentity")
    public top.egon.cola.platform.tianquan.shoubing.admin.support.outbox.OAuthOutboxIdentity oauthOutboxIdentity(
            @Qualifier("outboxInfrastructure") top.egon.cola.component.outbox.autoconfigure.OutboxInfrastructure infrastructure,
            @Qualifier("egon.cola.component.mybatis-plus.sharding-top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties")
            top.egon.cola.component.common.mybatis.sharding.EgonColaShardingProperties sharding,
            @Qualifier("egonColaRoutingProfiles") Map<String, top.egon.cola.component.common.mybatis.routing.EgonColaRoutingProfileBO> profiles,
            top.egon.cola.platform.tianquan.shoubing.admin.identity.repo.IdentityDirectoryContext directory) {
        new top.egon.cola.component.outbox.persistence.OutboxShardRouting(infrastructure.dataSource(), sharding, profiles);
        var identities = new top.egon.cola.platform.tianquan.shoubing.admin.support.outbox.OAuthOutboxIdentity(profiles, directory.directoryPartitionId());
        int directorySlot = identities.forPlatform("oauth_identity_user").slot();
        for (String table : java.util.List.of("oauth_identity_credential", "oauth_identity_membership", "oauth_realm",
                "oauth_security_state", "oauth_audit", "oauth_subject_tenant_history", "oauth_subject_revocation_task",
                "oauth_password_change_receipt", "oauth_subject_delivery_receipt", "oauth_resource_fence")) {
            if (identities.forPlatform(table).slot() != directorySlot) {
                throw new IllegalStateException("OAUTH_DIRECTORY_SHARD_MISMATCH: " + table);
            }
        }
        return identities;
    }
}
