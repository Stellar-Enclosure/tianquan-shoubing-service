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
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthDeviceSessionBO;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

class OAuthDeviceSessionFenceSqlTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");
    @Test void omittedLiveSessionAndHiddenAuthorizationPreventMutation() throws Exception {
        var source = new JdbcDataSource();
        source.setURL("jdbc:h2:mem:" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1");
        var jdbc = new JdbcTemplate(source); jdbc.execute("CREATE SCHEMA tianquan_oauth");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_device_session (id BIGINT, tenant_id BIGINT, version BIGINT, subject VARCHAR, status VARCHAR, expires_at TIMESTAMP WITH TIME ZONE, authentication_jti_digest VARCHAR, deleted_at TIMESTAMP, update_user_id VARCHAR, update_time TIMESTAMP WITH TIME ZONE)");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_authentication (tenant_id BIGINT, jti_digest VARCHAR, status VARCHAR, subject_generation BIGINT, realm_generation BIGINT, deleted_at TIMESTAMP)");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_security_state (id BIGINT, tenant_id BIGINT, version BIGINT, target_type VARCHAR, target_key VARCHAR, generation BIGINT, enabled BOOLEAN, deleted_at TIMESTAMP, update_user_id VARCHAR, update_time TIMESTAMP WITH TIME ZONE)");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_authorization (tenant_id BIGINT, device_session_id BIGINT, status VARCHAR, absolute_expires_at TIMESTAMP WITH TIME ZONE, deleted_at TIMESTAMP)");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_security_state (id,tenant_id,version,target_type,target_key,generation,enabled) VALUES (42,7,4,'REALM','self',0,TRUE),(43,7,0,'SUBJECT','alice',0,TRUE)");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_device_session (id,tenant_id,version,subject,status,expires_at,authentication_jti_digest) VALUES (1,7,0,'alice','ACTIVE',?,'a'),(2,7,0,'alice','ACTIVE',?,'b')", NOW.plusSeconds(100), NOW.plusSeconds(100));
        jdbc.update("INSERT INTO tianquan_oauth.oauth_authentication (tenant_id,jti_digest,status,subject_generation,realm_generation) VALUES (7,'a','ACTIVE',0,0),(7,'b','ACTIVE',0,0)");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_authorization (tenant_id,device_session_id,status,absolute_expires_at) VALUES (7,1,'ACTIVE',?),(7,2,'ACTIVE',?)", NOW.plusSeconds(100), NOW.plusSeconds(100));
        var factory = new SqlSessionFactoryBean(); factory.setDataSource(source);
        factory.setMapperLocations(new ClassPathResource("mapper/oauth/OAuthDeviceSessionMapper.xml"));
        var mapper = new SqlSessionTemplate(factory.getObject()).getMapper(OAuthDeviceSessionMapper.class);
        var first = OAuthDeviceSessionBO.builder().id(1L).version(0L).build();
        var second = OAuthDeviceSessionBO.builder().id(2L).version(0L).build();
        assertThat(mapper.fenceLiveSnapshot(7L, 42L, 4L, "alice", NOW, List.of(first), 1, "worker")).isZero();
        assertThat(mapper.fenceLiveSnapshot(7L, 42L, 4L, "alice", NOW, List.of(first, second), 2, "worker")).isEqualTo(1);
        jdbc.update("UPDATE tianquan_oauth.oauth_device_session SET status='REVOKED' WHERE id=1");
        assertThat(mapper.fenceRevokedWithoutLiveAuthorizations(7L, 1L, 0L, NOW, "worker")).isZero();
        jdbc.update("UPDATE tianquan_oauth.oauth_authorization SET status='REVOKED' WHERE device_session_id=1");
        assertThat(mapper.fenceRevokedWithoutLiveAuthorizations(7L, 1L, 0L, NOW, "worker")).isEqualTo(1);
    }

    @Test void sessionFencesPassPrimaryWriteAndSameGroupGuards() throws Exception {
        var config = new Configuration(); String resource = "mapper/oauth/OAuthDeviceSessionMapper.xml";
        try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
            new XMLMapperBuilder(input, config, resource, config.getSqlFragments()).parse();
        }
        config.setEnvironment(new Environment("test", new SpringManagedTransactionFactory(), mock(DataSource.class)));
        var properties = new EgonColaMybatisPlusProperties();
        var tenantGuard = new EgonColaTenantIdGuardInnerInterceptor(() -> "worker", properties);
        new CommonAnnotationBeanPostProcessor().postProcessBeforeInitialization(tenantGuard, "sqlGuard");
        var guard = new EgonColaLocalWriteGuardInnerInterceptor(query -> new EgonColaRouteResult(List.of(
                new EgonColaPhysicalTargetBO("primary", "tianquan_oauth", query.logicalTable())), "a".repeat(64)),
                tenantGuard, mock(EgonColaTwoLevelRouteStrategy.class), Map.of());
        var params = Map.<String, Object>of("tenantId", 7L, "stateId", 42L, "id", 1L, "expectedVersion", 4L,
                "subject", "alice", "now", NOW, "sessions", List.of(OAuthDeviceSessionBO.builder().id(1L).version(0L).build()),
                "count", 1, "actor", "worker");
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
        MDC.put("tenantId", "7"); MDC.put("userId", "worker");
        try {
            Executor executor = mock(Executor.class);
            for (String name : List.of("fenceLiveSnapshot", "fenceRevokedWithoutLiveAuthorizations")) {
                var statement = config.getMappedStatement(OAuthDeviceSessionMapper.class.getName() + "." + name);
                assertThat(statement.getBoundSql(params).getSql().toLowerCase()).doesNotContain("for update", "for share");
                assertThat(parser.parse(statement.getBoundSql(params).getSql(), false)).isNotNull();
                var invocation = new Invocation(executor, Executor.class.getMethod("update", MappedStatement.class, Object.class),
                        new Object[]{statement, params});
                assertThatCode(() -> new EgonColaOriginalSqlGuardInterceptor(properties).intercept(invocation)).doesNotThrowAnyException();
                var handler = config.newStatementHandler(executor, statement, params, RowBounds.DEFAULT, null, statement.getBoundSql(params));
                assertThatCode(() -> guard.beforePrepare(handler, null, null)).doesNotThrowAnyException();
            }
        } finally { MDC.remove("tenantId"); MDC.remove("userId"); }
    }
}
