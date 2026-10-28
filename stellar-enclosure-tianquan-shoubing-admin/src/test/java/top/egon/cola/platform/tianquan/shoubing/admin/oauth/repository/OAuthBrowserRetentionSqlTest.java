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
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.OAuthDeviceSessionMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.OAuthAuthenticationMapper;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

class OAuthBrowserRetentionSqlTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");

    @Test void sessionCandidatesUseReplicaReadsAndPrimaryRejectsHiddenAuthorization() throws Exception {
        var source = new JdbcDataSource();
        source.setURL("jdbc:h2:mem:" + UUID.randomUUID().toString().replace("-", "") + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1");
        var jdbc = new JdbcTemplate(source); jdbc.execute("CREATE SCHEMA tianquan_oauth");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_device_session (id BIGINT, tenant_id BIGINT, version BIGINT, authentication_jti_digest VARCHAR, expires_at TIMESTAMP WITH TIME ZONE, deleted_at TIMESTAMP, update_time TIMESTAMP WITH TIME ZONE, update_user_id VARCHAR)");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_authentication (tenant_id BIGINT, jti_digest VARCHAR, expires_at TIMESTAMP WITH TIME ZONE, deleted_at TIMESTAMP)");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_authorization (tenant_id BIGINT, device_session_id BIGINT, deleted_at TIMESTAMP)");
        Instant cutoff = NOW.minusSeconds(86400);
        jdbc.update("INSERT INTO tianquan_oauth.oauth_device_session (id,tenant_id,version,authentication_jti_digest,expires_at) VALUES (30,1001,8,'auth',?)", cutoff.minusSeconds(1));
        jdbc.update("INSERT INTO tianquan_oauth.oauth_authentication (tenant_id,jti_digest,expires_at) VALUES (1001,'auth',?)", cutoff.minusSeconds(1));
        var factory = new SqlSessionFactoryBean(); factory.setDataSource(source);
        factory.setMapperLocations(new ClassPathResource("mapper/oauth/OAuthDeviceSessionMapper.xml"));
        var mapper = new SqlSessionTemplate(factory.getObject()).getMapper(OAuthDeviceSessionMapper.class);
        var candidates = mapper.selectRetainedCandidates(1001L, cutoff, 500);
        assertThat(candidates).singleElement().satisfies(candidate -> {
            assertThat(candidate.getId()).isEqualTo(30L); assertThat(candidate.getVersion()).isEqualTo(8L);
        });
        jdbc.update("INSERT INTO tianquan_oauth.oauth_authorization VALUES (1001,30,NULL)");
        assertThat(mapper.selectRetainedCandidates(1001L, cutoff, 500)).isEmpty();
        assertThat(mapper.deleteVersionedById(1001L, 30L, 8L, cutoff, NOW, "worker")).isZero();
        jdbc.update("UPDATE tianquan_oauth.oauth_authorization SET deleted_at=CURRENT_TIMESTAMP");
        assertThat(mapper.deleteVersionedById(1001L, 30L, 7L, cutoff, NOW, "worker")).isZero();
        assertThat(mapper.deleteVersionedById(1001L, 30L, 8L, cutoff.minusSeconds(2), NOW, "worker")).isZero();
        assertThat(mapper.deleteVersionedById(1001L, 30L, 8L, cutoff, NOW, "worker")).isEqualTo(1);
    }

    @Test void retainedSessionPreventsAuthenticationCleanupUntilSessionIsRetired() throws Exception {
        var source = new JdbcDataSource();
        source.setURL("jdbc:h2:mem:" + UUID.randomUUID().toString().replace("-", "") + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1");
        var jdbc = new JdbcTemplate(source); jdbc.execute("CREATE SCHEMA tianquan_oauth");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_authentication (id BIGINT, tenant_id BIGINT, version BIGINT, jti_digest VARCHAR, expires_at TIMESTAMP WITH TIME ZONE, retain_until TIMESTAMP WITH TIME ZONE, deleted_at TIMESTAMP, update_time TIMESTAMP WITH TIME ZONE, update_user_id VARCHAR)");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_authorization (tenant_id BIGINT, authentication_jti_digest VARCHAR, deleted_at TIMESTAMP)");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_interaction (tenant_id BIGINT, authentication_jti_digest VARCHAR, deleted_at TIMESTAMP)");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_device_session (tenant_id BIGINT, authentication_jti_digest VARCHAR, deleted_at TIMESTAMP)");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_authentication (id,tenant_id,version,jti_digest,expires_at,retain_until) VALUES (31,1001,3,'auth',?,?)", NOW.minusSeconds(86401), NOW.minusSeconds(1));
        jdbc.update("INSERT INTO tianquan_oauth.oauth_device_session VALUES (1001,'auth',NULL)");
        var factory = new SqlSessionFactoryBean(); factory.setDataSource(source);
        factory.setMapperLocations(new ClassPathResource("mapper/oauth/OAuthAuthenticationMapper.xml"));
        var mapper = new SqlSessionTemplate(factory.getObject()).getMapper(OAuthAuthenticationMapper.class);
        assertThat(mapper.deleteVersionedById(1001L, 31L, 3L, NOW, "worker")).isZero();
        jdbc.update("UPDATE tianquan_oauth.oauth_device_session SET deleted_at=CURRENT_TIMESTAMP");
        assertThat(mapper.deleteVersionedById(1001L, 31L, 3L, NOW, "worker")).isEqualTo(1);
    }

    @Test void allRetentionStatementsPassSqlGuardsWithoutLockingReads() throws Exception {
        var configuration = new Configuration();
        for (String resource : List.of("mapper/oauth/OAuthDeviceSessionMapper.xml", "mapper/oauth/OAuthAuthenticationMapper.xml",
                "mapper/oauth/OAuthInteractionMapper.xml", "mapper/audit/OAuthAuditInboxMapper.xml",
                "mapper/audit/OAuthAuditReceiptMapper.xml", "mapper/audit/OAuthAuditDeadLetterMapper.xml")) {
            try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
                new XMLMapperBuilder(input, configuration, resource, configuration.getSqlFragments()).parse();
            }
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
        var params = Map.<String, Object>of("tenantId", 1001L, "id", 30L, "expectedVersion", 8L,
                "cutoff", NOW.minusSeconds(86400), "now", NOW, "actor", "worker", "limit", 500);
        MDC.put("tenantId", "1001"); MDC.put("userId", "worker");
        try {
            Executor executor = mock(Executor.class);
            String base = "top.egon.cola.platform.tianquan.shoubing.admin.";
            var read = configuration.getMappedStatement(base + "oauth.dao.OAuthDeviceSessionMapper.selectRetainedCandidates");
            assertThat(read.getBoundSql(params).getSql().toLowerCase()).doesNotContain("for update", "skip locked");
            assertThat(parser.parse(read.getBoundSql(params).getSql(), false)).isNotNull();
            assertThatCode(() -> tenantGuard.beforeQuery(executor, read, params, RowBounds.DEFAULT, null, read.getBoundSql(params))).doesNotThrowAnyException();
            for (String name : List.of("oauth.dao.OAuthDeviceSessionMapper", "oauth.dao.OAuthAuthenticationMapper",
                    "oauth.dao.OAuthInteractionMapper", "audit.dao.OAuthAuditInboxMapper", "audit.dao.OAuthAuditReceiptMapper",
                    "audit.dao.OAuthAuditDeadLetterMapper")) {
                var update = configuration.getMappedStatement(base + name + ".deleteVersionedById");
                assertThat(parser.parse(update.getBoundSql(params).getSql(), false)).isNotNull();
                var invocation = new Invocation(executor, Executor.class.getMethod("update", MappedStatement.class, Object.class), new Object[]{update, params});
                assertThatCode(() -> new EgonColaOriginalSqlGuardInterceptor(properties).intercept(invocation)).as(name).doesNotThrowAnyException();
                var statement = configuration.newStatementHandler(executor, update, params, RowBounds.DEFAULT, null, update.getBoundSql(params));
                assertThatCode(() -> guard.beforePrepare(statement, null, null)).as(name).doesNotThrowAnyException();
            }
        } finally { MDC.remove("tenantId"); MDC.remove("userId"); }
    }
}
