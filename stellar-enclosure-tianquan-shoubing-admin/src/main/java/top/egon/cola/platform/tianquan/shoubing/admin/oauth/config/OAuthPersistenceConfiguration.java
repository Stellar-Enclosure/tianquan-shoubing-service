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
}
