package top.egon.cola.platform.tianquan.shoubing.admin.token.repository;

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
import top.egon.cola.platform.tianquan.shoubing.admin.token.dao.OAuthSecurityStateMapper;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

class OAuthAuthorizationRemovalFenceSqlTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");
    @Test void primaryRejectsReplicaMissAndAnyRemainingLiveToken() throws Exception {
        var source = new JdbcDataSource();
        source.setURL("jdbc:h2:mem:" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1");
        var jdbc = new JdbcTemplate(source); jdbc.execute("CREATE SCHEMA tianquan_oauth");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_security_state (id BIGINT, tenant_id BIGINT, version BIGINT, target_type VARCHAR, target_key VARCHAR, deleted_at TIMESTAMP, update_user_id VARCHAR, update_time TIMESTAMP WITH TIME ZONE)");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_authorization (id BIGINT, tenant_id BIGINT, deleted_at TIMESTAMP)");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_token (id BIGINT, tenant_id BIGINT, authorization_pk BIGINT, consumed_at TIMESTAMP WITH TIME ZONE, revoked_at TIMESTAMP WITH TIME ZONE, deleted_at TIMESTAMP)");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_security_state (id,tenant_id,version,target_type,target_key) VALUES (42,7,3,'REALM','self')");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_authorization (id,tenant_id) VALUES (17,7)");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_token (id,tenant_id,authorization_pk) VALUES (19,7,17)");
        var factory = new SqlSessionFactoryBean(); factory.setDataSource(source);
        factory.setMapperLocations(new ClassPathResource("mapper/token/OAuthSecurityStateMapper.xml"));
        var mapper = new SqlSessionTemplate(factory.getObject()).getMapper(OAuthSecurityStateMapper.class);
        assertThat(mapper.fenceRealmIfAuthorizationAbsent(7L, 42L, 3L, 17L, NOW, "worker")).isZero();
        assertThat(mapper.fenceRealmIfAuthorizationTokensInactive(7L, 42L, 3L, 17L, NOW, "worker")).isZero();
        jdbc.update("UPDATE tianquan_oauth.oauth_token SET revoked_at=? WHERE id=19", NOW);
        assertThat(mapper.fenceRealmIfAuthorizationTokensInactive(7L, 42L, 3L, 17L, NOW, "worker")).isEqualTo(1);
        jdbc.update("DELETE FROM tianquan_oauth.oauth_authorization WHERE id=17");
        assertThat(mapper.fenceRealmIfAuthorizationAbsent(7L, 42L, 4L, 17L, NOW, "worker")).isEqualTo(1);
    }

    @Test void bothFencesPassPostgresParsingAndSameGroupRoutingGuards() throws Exception {
        var configuration = new Configuration(); String resource = "mapper/token/OAuthSecurityStateMapper.xml";
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
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
        var parameters = Map.<String, Object>of("tenantId", 7L, "id", 42L, "expectedVersion", 3L,
                "authorizationId", 17L, "now", NOW, "actor", "worker");
        MDC.put("tenantId", "7"); MDC.put("userId", "worker");
        try {
            Executor executor = mock(Executor.class);
            for (String method : List.of("fenceRealmIfAuthorizationAbsent", "fenceRealmIfAuthorizationTokensInactive")) {
                var statement = configuration.getMappedStatement(OAuthSecurityStateMapper.class.getName() + "." + method);
                String sql = statement.getBoundSql(parameters).getSql().toLowerCase();
                assertThat(sql).contains("not exists", "authorization").doesNotContain("for update", "for share");
                assertThat(parser.parse(sql, false)).isNotNull();
                var invocation = new Invocation(executor, Executor.class.getMethod("update", MappedStatement.class, Object.class),
                        new Object[]{statement, parameters});
                assertThatCode(() -> new EgonColaOriginalSqlGuardInterceptor(properties).intercept(invocation)).doesNotThrowAnyException();
                var handler = configuration.newStatementHandler(executor, statement, parameters, RowBounds.DEFAULT, null, statement.getBoundSql(parameters));
                assertThatCode(() -> guard.beforePrepare(handler, null, null)).doesNotThrowAnyException();
            }
        } finally { MDC.remove("tenantId"); MDC.remove("userId"); }
    }
}
