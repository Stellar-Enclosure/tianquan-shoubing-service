package top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.time.Instant;
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
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.OAuthClientMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

class OAuthClientGrantFenceSqlTest {
    private final OAuthClientBO client = OAuthClientBO.builder().id(44L).version(3L).clientId("web").build();

    @Test void absentGrantMustBeProvedAgainstTheCurrentPrimaryClient() throws Exception {
        var source = new JdbcDataSource();
        source.setURL("jdbc:h2:mem:" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1");
        var jdbc = new JdbcTemplate(source); jdbc.execute("CREATE SCHEMA tianquan_oauth");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_client (id BIGINT, tenant_id BIGINT, client_id VARCHAR, version BIGINT, deleted_at TIMESTAMP, update_user_id VARCHAR, update_time TIMESTAMP WITH TIME ZONE)");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_grant (tenant_id BIGINT, client_pk BIGINT, resource_server_id VARCHAR, grant_type VARCHAR, deleted_at TIMESTAMP)");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_client (id,tenant_id,client_id,version) VALUES (44,1001,'web',3)");
        var factory = new SqlSessionFactoryBean(); factory.setDataSource(source);
        factory.setMapperLocations(new ClassPathResource("mapper/oauth/OAuthClientMapper.xml"));
        var mapper = new SqlSessionTemplate(factory.getObject()).getMapper(OAuthClientMapper.class);
        var now = Instant.parse("2026-10-28T00:00:00Z");
        assertThat(mapper.fenceGrantAbsent(1001L, client, "orders", "USER_DELEGATION", now, "worker")).isEqualTo(1);
        jdbc.update("UPDATE tianquan_oauth.oauth_client SET version = 3");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_grant VALUES (1001,44,'orders','USER_DELEGATION',NULL)");
        assertThat(mapper.fenceGrantAbsent(1001L, client, "orders", "USER_DELEGATION", now, "worker")).isZero();
        assertThat(mapper.fenceGrantAbsent(1001L, client, "other", "USER_DELEGATION", now, "worker")).isEqualTo(1);
        jdbc.update("UPDATE tianquan_oauth.oauth_client SET version = 3");
        assertThat(mapper.fenceGrantAbsent(1002L, client, "orders", "USER_DELEGATION", now, "worker")).isZero();
        jdbc.update("UPDATE tianquan_oauth.oauth_grant SET deleted_at = CURRENT_TIMESTAMP");
        assertThat(mapper.fenceGrantAbsent(1001L, client, "orders", "USER_DELEGATION", now, "worker")).isEqualTo(1);
        assertThat(mapper.fenceGrantAbsent(1001L, client, "orders", "USER_DELEGATION", now, "worker")).isZero();
    }

    @Test void absenceProofIsTenantScopedAndRejectsCrossPrimaryRouting() throws Exception {
        var configuration = new Configuration(); String resource = "mapper/oauth/OAuthClientMapper.xml";
        try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
            new XMLMapperBuilder(input, configuration, resource, configuration.getSqlFragments()).parse();
        }
        configuration.setEnvironment(new Environment("test", new SpringManagedTransactionFactory(), mock(DataSource.class)));
        var properties = new EgonColaMybatisPlusProperties();
        var tenantGuard = new EgonColaTenantIdGuardInnerInterceptor(() -> "worker", properties);
        new CommonAnnotationBeanPostProcessor().postProcessBeforeInitialization(tenantGuard, "sqlGuard");
        var guard = new EgonColaLocalWriteGuardInnerInterceptor(query -> new EgonColaRouteResult(List.of(
                new EgonColaPhysicalTargetBO("primary", "tianquan_oauth", query.logicalTable())), "a".repeat(64)),
                tenantGuard, mock(EgonColaTwoLevelRouteStrategy.class), Map.of());
        var cross = new EgonColaLocalWriteGuardInnerInterceptor(query -> new EgonColaRouteResult(List.of(
                new EgonColaPhysicalTargetBO(query.logicalTable().equals("oauth_client") ? "a" : "b",
                        "tianquan_oauth", query.logicalTable())), "a".repeat(64)),
                tenantGuard, mock(EgonColaTwoLevelRouteStrategy.class), Map.of());
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
        var params = Map.<String, Object>of("tenantId", 1001L, "client", client,
                "resourceServerId", "orders", "grantType", "USER_DELEGATION",
                "now", Instant.parse("2026-10-28T00:00:00Z"), "actor", "worker");
        MDC.put("tenantId", "1001"); MDC.put("userId", "worker");
        try {
            Executor executor = mock(Executor.class);
            var update = configuration.getMappedStatement(OAuthClientMapper.class.getName() + ".fenceGrantAbsent");
            assertThat(parser.parse(update.getBoundSql(params).getSql(), false)).isNotNull();
            var invocation = new Invocation(executor, Executor.class.getMethod("update", MappedStatement.class, Object.class), new Object[]{update, params});
            assertThatCode(() -> new EgonColaOriginalSqlGuardInterceptor(properties).intercept(invocation)).doesNotThrowAnyException();
            var statement = configuration.newStatementHandler(executor, update, params, RowBounds.DEFAULT, null, update.getBoundSql(params));
            assertThatCode(() -> guard.beforePrepare(statement, null, null)).doesNotThrowAnyException();
            var crossStatement = configuration.newStatementHandler(executor, update, params, RowBounds.DEFAULT, null, update.getBoundSql(params));
            assertThatThrownBy(() -> cross.beforePrepare(crossStatement, null, null)).hasMessageContaining("LOCAL_WRITE_TARGET_MISMATCH");
        } finally { MDC.remove("tenantId"); MDC.remove("userId"); }
    }
}
