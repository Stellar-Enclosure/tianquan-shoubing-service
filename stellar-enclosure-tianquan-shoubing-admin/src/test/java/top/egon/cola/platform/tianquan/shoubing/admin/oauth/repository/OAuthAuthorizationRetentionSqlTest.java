package top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.sql.DataSource;
import org.apache.ibatis.builder.xml.XMLMapperBuilder;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.plugin.Invocation;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.RowBounds;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.SqlSessionTemplate;
import org.mybatis.spring.transaction.SpringManagedTransactionFactory;
import org.slf4j.MDC;
import org.springframework.context.annotation.CommonAnnotationBeanPostProcessor;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties;
import top.egon.cola.component.common.mybatis.interceptor.EgonColaLocalWriteGuardInnerInterceptor;
import top.egon.cola.component.common.mybatis.interceptor.EgonColaOriginalSqlGuardInterceptor;
import top.egon.cola.component.common.mybatis.interceptor.EgonColaTenantIdGuardInnerInterceptor;
import top.egon.cola.component.common.mybatis.routing.EgonColaPhysicalTargetBO;
import top.egon.cola.component.common.mybatis.routing.EgonColaRouteResult;
import top.egon.cola.component.common.mybatis.routing.EgonColaTwoLevelRouteStrategy;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.OAuthAuthorizationMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.po.OAuthAuthorizationPO;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

class OAuthAuthorizationRetentionSqlTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");
    private JdbcDataSource source;
    private JdbcTemplate jdbc;
    private OAuthAuthorizationMapper mapper;
    private OAuthAuthorizationPO authorization;

    @BeforeEach void setup() throws Exception {
        source = new JdbcDataSource();
        source.setURL("jdbc:h2:mem:" + UUID.randomUUID().toString().replace("-", "") + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1;LOCK_TIMEOUT=5000");
        jdbc = new JdbcTemplate(source); jdbc.execute("CREATE SCHEMA tianquan_oauth");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_realm (id BIGINT PRIMARY KEY, version BIGINT)");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_authorization (id BIGINT, tenant_id BIGINT, version BIGINT, retain_until TIMESTAMP WITH TIME ZONE, deleted_at TIMESTAMP, update_user_id VARCHAR, update_time TIMESTAMP WITH TIME ZONE)");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_token (tenant_id BIGINT, authorization_pk BIGINT, deleted_at TIMESTAMP)");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_realm VALUES (1,0)");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_authorization (id,tenant_id,version,retain_until) VALUES (30,1001,8,?)", NOW.minusSeconds(1));
        var factory = new SqlSessionFactoryBean(); factory.setDataSource(source);
        factory.setMapperLocations(new ClassPathResource("mapper/oauth/OAuthAuthorizationMapper.xml"));
        mapper = new SqlSessionTemplate(factory.getObject()).getMapper(OAuthAuthorizationMapper.class);
        authorization = new OAuthAuthorizationPO(); authorization.setId(30L); authorization.setUpdateUserId("worker"); authorization.setUpdateTime(NOW);
    }

    @Test void primaryTokenAbsenceAndRetentionAreBothRequired() {
        jdbc.update("INSERT INTO tianquan_oauth.oauth_token VALUES (1001,30,NULL)");
        assertThat(mapper.deleteVersionedById(1001L, authorization, 8L, NOW)).isZero();
        jdbc.update("UPDATE tianquan_oauth.oauth_token SET deleted_at=CURRENT_TIMESTAMP");
        assertThat(mapper.deleteVersionedById(1002L, authorization, 8L, NOW)).isZero();
        assertThat(mapper.deleteVersionedById(1001L, authorization, 7L, NOW)).isZero();
        assertThat(mapper.deleteVersionedById(1001L, authorization, 8L, NOW.minusSeconds(2))).isZero();
        assertThat(mapper.deleteVersionedById(1001L, authorization, 8L, NOW)).isEqualTo(1);
    }

    @Test void realmWriteSerializesCleanupWithAuthorizationWrites() throws Exception {
        var cleanupStarted = new CountDownLatch(1); var releaseCleanup = new CountDownLatch(1); var writerStarted = new CountDownLatch(1);
        var transactions = new TransactionTemplate(new DataSourceTransactionManager(source));
        try (var workers = Executors.newFixedThreadPool(2)) {
            var cleanup = workers.submit(() -> transactions.execute(status -> {
                jdbc.update("UPDATE tianquan_oauth.oauth_realm SET version=version+1 WHERE id=1");
                cleanupStarted.countDown();
                try { if (!releaseCleanup.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("timeout"); }
                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new IllegalStateException(interrupted); }
                return mapper.deleteVersionedById(1001L, authorization, 8L, NOW);
            }));
            assertThat(cleanupStarted.await(5, TimeUnit.SECONDS)).isTrue();
            var writer = workers.submit(() -> transactions.execute(status -> {
                writerStarted.countDown();
                jdbc.update("UPDATE tianquan_oauth.oauth_realm SET version=version+1 WHERE id=1");
                return jdbc.update("UPDATE tianquan_oauth.oauth_authorization SET version=version+1 WHERE tenant_id=1001 AND id=30 AND version=8 AND deleted_at IS NULL");
            }));
            assertThat(writerStarted.await(5, TimeUnit.SECONDS)).isTrue();
            try { assertThatThrownBy(() -> writer.get(250, TimeUnit.MILLISECONDS)).isInstanceOf(TimeoutException.class); }
            finally { releaseCleanup.countDown(); }
            assertThat(cleanup.get(5, TimeUnit.SECONDS)).isEqualTo(1);
            assertThat(writer.get(5, TimeUnit.SECONDS)).isZero();
        }
    }

    @Test void cleanupSqlParsesAndMustStayOnTheSamePrimary() throws Exception {
        var configuration = new Configuration(); String resource = "mapper/oauth/OAuthAuthorizationMapper.xml";
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
                new EgonColaPhysicalTargetBO(query.logicalTable().equals("oauth_authorization") ? "a" : "b",
                        "tianquan_oauth", query.logicalTable())), "a".repeat(64)),
                tenantGuard, mock(EgonColaTwoLevelRouteStrategy.class), Map.of());
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
        var params = Map.<String, Object>of("tenantId", 1001L, "po", authorization, "expectedVersion", 8L, "cutoff", NOW);
        MDC.put("tenantId", "1001"); MDC.put("userId", "worker");
        try {
            Executor executor = mock(Executor.class);
            var update = configuration.getMappedStatement(OAuthAuthorizationMapper.class.getName() + ".deleteVersionedById");
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
