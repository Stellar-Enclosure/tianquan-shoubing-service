package top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.sql.DataSource;
import org.apache.ibatis.builder.xml.XMLMapperBuilder;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.plugin.Invocation;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.RowBounds;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.Test;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.SqlSessionTemplate;
import org.mybatis.spring.transaction.SpringManagedTransactionFactory;
import org.slf4j.MDC;
import org.springframework.context.annotation.CommonAnnotationBeanPostProcessor;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties;
import top.egon.cola.component.common.mybatis.interceptor.EgonColaLocalWriteGuardInnerInterceptor;
import top.egon.cola.component.common.mybatis.interceptor.EgonColaOriginalSqlGuardInterceptor;
import top.egon.cola.component.common.mybatis.interceptor.EgonColaTenantIdGuardInnerInterceptor;
import top.egon.cola.component.common.mybatis.routing.EgonColaPhysicalTargetBO;
import top.egon.cola.component.common.mybatis.routing.EgonColaRouteResult;
import top.egon.cola.component.common.mybatis.routing.EgonColaTwoLevelRouteStrategy;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.OAuthRealmMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

class OAuthRecoveryFenceSqlTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");

    @Test void primaryConditionRejectsMissingClientsAndHiddenSecurityHistory() throws Exception {
        var source = new JdbcDataSource();
        source.setURL("jdbc:h2:mem:" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1");
        var jdbc = new JdbcTemplate(source);
        jdbc.execute("CREATE SCHEMA tianquan_oauth");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_realm (id BIGINT, tenant_id BIGINT, realm_key VARCHAR, version BIGINT, deleted_at TIMESTAMP, update_user_id VARCHAR, update_time TIMESTAMP WITH TIME ZONE)");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_client (id BIGINT, tenant_id BIGINT, version BIGINT, deleted_at TIMESTAMP)");
        for (String table : List.of("oauth_authorization", "oauth_authentication", "oauth_revocation")) {
            jdbc.execute("CREATE TABLE tianquan_oauth." + table + " (tenant_id BIGINT, deleted_at TIMESTAMP)");
        }
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_security_state (tenant_id BIGINT, generation BIGINT, revision BIGINT, target_type VARCHAR, deleted_at TIMESTAMP)");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_realm (id,tenant_id,realm_key,version) VALUES (1,101,'tenant:101',3)");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_client (id,tenant_id,version) VALUES (7,101,1),(8,101,2)");
        var factory = new SqlSessionFactoryBean(); factory.setDataSource(source);
        factory.setMapperLocations(new ClassPathResource("mapper/oauth/OAuthRealmMapper.xml"));
        var mapper = new SqlSessionTemplate(factory.getObject()).getMapper(OAuthRealmMapper.class);
        var first = OAuthClientBO.builder().id(7L).version(1L).build();
        var second = OAuthClientBO.builder().id(8L).version(2L).build();
        assertThat(mapper.fenceRecovery(101L, 1L, "tenant:101", 3L, List.of(first), 1, true, NOW, "worker")).isZero();
        jdbc.update("INSERT INTO tianquan_oauth.oauth_authentication (tenant_id) VALUES (101)");
        assertThat(mapper.fenceRecovery(101L, 1L, "tenant:101", 3L, List.of(first, second), 2, true, NOW, "worker")).isZero();
        jdbc.update("DELETE FROM tianquan_oauth.oauth_authentication");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_security_state (tenant_id,generation,revision,target_type) VALUES (101,1,1,'SUBJECT')");
        assertThat(mapper.fenceRecovery(101L, 1L, "tenant:101", 3L, List.of(first, second), 2, true, NOW, "worker")).isZero();
        jdbc.update("DELETE FROM tianquan_oauth.oauth_security_state");
        assertThat(mapper.fenceRecovery(101L, 1L, "tenant:101", 3L, List.of(first, second), 2, true, NOW, "worker")).isEqualTo(1);
        assertThat(mapper.fenceRecovery(101L, 1L, "tenant:101", 3L, List.of(first, second), 2, true, NOW, "worker")).isZero();
    }

    @Test void recoveryFencePassesSqlAndSameGroupGuards() throws Exception {
        var config = new Configuration();
        String resource = "mapper/oauth/OAuthRealmMapper.xml";
        try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
            new XMLMapperBuilder(input, config, resource, config.getSqlFragments()).parse();
        }
        config.setEnvironment(new Environment("test", new SpringManagedTransactionFactory(), mock(DataSource.class)));
        var properties = new EgonColaMybatisPlusProperties();
        var tenantGuard = new EgonColaTenantIdGuardInnerInterceptor(() -> "worker", properties);
        new CommonAnnotationBeanPostProcessor().postProcessBeforeInitialization(tenantGuard, "sqlGuard");
        var routeGuard = new EgonColaLocalWriteGuardInnerInterceptor(query -> new EgonColaRouteResult(List.of(
                new EgonColaPhysicalTargetBO("primary", "tianquan_oauth", query.logicalTable())), "a".repeat(64)),
                tenantGuard, mock(EgonColaTwoLevelRouteStrategy.class), Map.of());
        var params = Map.<String, Object>of("tenantId", 101L, "id", 1L, "realmKey", "tenant:101", "expectedVersion", 3L,
                "clients", List.of(OAuthClientBO.builder().id(7L).version(1L).build()), "clientCount", 1,
                "initializing", true, "now", NOW, "actor", "worker");
        var statement = config.getMappedStatement(OAuthRealmMapper.class.getName() + ".fenceRecovery");
        assertThat(statement.getBoundSql(params).getSql().toLowerCase()).doesNotContain("for update", "for share");
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
        assertThat(parser.parse(statement.getBoundSql(params).getSql(), false)).isNotNull();
        MDC.put("tenantId", "101"); MDC.put("userId", "worker");
        try {
            Executor executor = mock(Executor.class);
            var invocation = new Invocation(executor, Executor.class.getMethod("update", MappedStatement.class, Object.class),
                    new Object[]{statement, params});
            assertThatCode(() -> new EgonColaOriginalSqlGuardInterceptor(properties).intercept(invocation)).doesNotThrowAnyException();
            var handler = config.newStatementHandler(executor, statement, params, RowBounds.DEFAULT, null, statement.getBoundSql(params));
            assertThatCode(() -> routeGuard.beforePrepare(handler, null, null)).doesNotThrowAnyException();
        } finally { MDC.remove("tenantId"); MDC.remove("userId"); }
    }
}
