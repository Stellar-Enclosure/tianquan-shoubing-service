package top.egon.cola.platform.tianquan.shoubing.admin.resource.repository;

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
import top.egon.cola.platform.tianquan.shoubing.admin.resource.dao.OAuthResourceFenceMapper;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

class OAuthResourceFenceSqlTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");
    @Test void staleFenceOrResourceVersionCannotAcquireThePrimaryGuard() throws Exception {
        var source = new JdbcDataSource(); source.setURL("jdbc:h2:mem:" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1");
        var jdbc = new JdbcTemplate(source); jdbc.execute("CREATE SCHEMA tianquan_oauth");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_resource_fence (id BIGINT, tenant_id BIGINT, version BIGINT, deleted_at TIMESTAMP, update_user_id VARCHAR, update_time TIMESTAMP WITH TIME ZONE)");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_resource (id BIGINT, tenant_id BIGINT, version BIGINT, resource_server_id VARCHAR, deleted_at TIMESTAMP)");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_resource_fence (id,tenant_id,version) VALUES (11,1,5)");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_resource (id,tenant_id,version,resource_server_id) VALUES (11,1,3,'orders')");
        var factory = new SqlSessionFactoryBean(); factory.setDataSource(source);
        factory.setMapperLocations(new ClassPathResource("mapper/resource/OAuthResourceFenceMapper.xml"));
        var mapper = new SqlSessionTemplate(factory.getObject()).getMapper(OAuthResourceFenceMapper.class);
        assertThat(mapper.selectVersion(1L, 11L)).isEqualTo(5L);
        assertThat(mapper.fenceObserved(1L, 11L, 4L, 3L, "orders", NOW, "worker")).isZero();
        assertThat(mapper.fenceObserved(1L, 11L, 5L, 2L, "orders", NOW, "worker")).isZero();
        assertThat(mapper.fenceObserved(1L, 11L, 5L, 3L, "orders", NOW, "worker")).isEqualTo(1);
        assertThat(mapper.fenceObserved(1L, 11L, 5L, 3L, "orders", NOW, "worker")).isZero();
    }

    @Test void fenceIsVersionedAndCannotRouteAcrossPrimaryGroups() throws Exception {
        var configuration = new Configuration(); String resource = "mapper/resource/OAuthResourceFenceMapper.xml";
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
                new EgonColaPhysicalTargetBO(query.logicalTable().equals("oauth_resource_fence") ? "a" : "b",
                        "tianquan_oauth", query.logicalTable())), "a".repeat(64)),
                tenantGuard, mock(EgonColaTwoLevelRouteStrategy.class), Map.of());
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
        var params = Map.<String, Object>of("tenantId", 1L, "id", 11L, "expectedVersion", 5L,
                "resourceVersion", 3L, "resourceServerId", "orders", "now", NOW, "actor", "worker");
        MDC.put("tenantId", "1"); MDC.put("userId", "worker");
        try {
            Executor executor = mock(Executor.class);
            var read = configuration.getMappedStatement(OAuthResourceFenceMapper.class.getName() + ".selectVersion");
            assertThat(read.getBoundSql(params).getSql().toLowerCase()).doesNotContain("for update", "for share");
            assertThatCode(() -> tenantGuard.beforeQuery(executor, read, params, RowBounds.DEFAULT, null, read.getBoundSql(params))).doesNotThrowAnyException();
            var update = configuration.getMappedStatement(OAuthResourceFenceMapper.class.getName() + ".fenceObserved");
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
