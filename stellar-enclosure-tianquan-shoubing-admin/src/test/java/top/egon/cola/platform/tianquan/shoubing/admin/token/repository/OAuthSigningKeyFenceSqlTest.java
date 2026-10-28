package top.egon.cola.platform.tianquan.shoubing.admin.token.repository;

import java.time.Instant;
import java.util.HashMap;
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
import top.egon.cola.platform.tianquan.shoubing.admin.token.dao.OAuthSigningKeyMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthKeyStatusEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.po.OAuthSigningKeyPO;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

class OAuthSigningKeyFenceSqlTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");

    @Test void primaryProtectsActiveKeyAndRejectsHiddenPublishedKey() throws Exception {
        var source = new JdbcDataSource(); source.setURL("jdbc:h2:mem:" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1");
        var jdbc = new JdbcTemplate(source); jdbc.execute("CREATE SCHEMA tianquan_oauth");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_security_state (id BIGINT, tenant_id BIGINT, version BIGINT, target_type VARCHAR, target_key VARCHAR, deleted_at TIMESTAMP, update_user_id VARCHAR, update_time TIMESTAMP WITH TIME ZONE)");
        jdbc.execute("CREATE TABLE tianquan_oauth.oauth_realm (id BIGINT, tenant_id BIGINT, version BIGINT, realm_key VARCHAR, trust_version BIGINT, status VARCHAR, active_kid VARCHAR, deleted_at TIMESTAMP)");
        jdbc.execute("""
                CREATE TABLE tianquan_oauth.oauth_signing_key (id BIGINT, tenant_id BIGINT, version BIGINT, kid VARCHAR,
                  algorithm VARCHAR, status VARCHAR, activated_at TIMESTAMP WITH TIME ZONE, last_issued_at TIMESTAMP WITH TIME ZONE,
                  verify_until TIMESTAMP WITH TIME ZONE, retired_at TIMESTAMP WITH TIME ZONE, deleted_at TIMESTAMP,
                  update_user_id VARCHAR, update_time TIMESTAMP WITH TIME ZONE,
                  active_slot BIGINT GENERATED ALWAYS AS (CASE WHEN status='ACTIVE' AND deleted_at IS NULL THEN tenant_id ELSE NULL END))
                """);
        jdbc.execute("CREATE UNIQUE INDEX one_active ON tianquan_oauth.oauth_signing_key(active_slot)");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_security_state (id,tenant_id,version,target_type,target_key) VALUES (42,7,3,'REALM','self')");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_realm (id,tenant_id,version,realm_key,trust_version,status,active_kid) VALUES (1,7,4,'tenant:7',1,'ACTIVE','old')");
        jdbc.update("INSERT INTO tianquan_oauth.oauth_signing_key (id,tenant_id,version,kid,algorithm,status) VALUES (10,7,2,'old','RS256','ACTIVE'),(11,7,0,'new','RS256','PUBLISHED')");
        var factory = new SqlSessionFactoryBean(); factory.setDataSource(source);
        factory.setMapperLocations(new ClassPathResource("mapper/token/OAuthSecurityStateMapper.xml"),
                new ClassPathResource("mapper/token/OAuthSigningKeyMapper.xml"));
        var session = new SqlSessionTemplate(factory.getObject());
        var states = session.getMapper(OAuthSecurityStateMapper.class);
        var keys = session.getMapper(OAuthSigningKeyMapper.class);
        assertThat(states.fenceRealmForKeyPublication(7L, 42L, 3L, 1L, 4L, 10L, 2L, "old", NOW, "worker")).isZero();
        var activate = new OAuthSigningKeyPO(); activate.setId(11L); activate.setKid("new"); activate.setAlgorithm("RS256");
        activate.setStatus(OAuthKeyStatusEnum.ACTIVE); activate.setVersion(1L); activate.setUpdateUserId("worker"); activate.setUpdateTime(NOW);
        assertThatThrownBy(() -> keys.updateExpectedVersion(7L, activate, 0L)).isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        var previous = new OAuthSigningKeyPO(); previous.setId(10L); previous.setKid("old"); previous.setAlgorithm("RS256");
        previous.setStatus(OAuthKeyStatusEnum.VERIFY_ONLY); previous.setVersion(3L); previous.setUpdateUserId("worker"); previous.setUpdateTime(NOW);
        var transaction = new org.springframework.transaction.support.TransactionTemplate(
                new org.springframework.jdbc.datasource.DataSourceTransactionManager(source));
        assertThatThrownBy(() -> transaction.executeWithoutResult(status -> {
            assertThat(keys.updateExpectedVersion(7L, previous, 2L)).isEqualTo(1);
            assertThat(keys.updateExpectedVersion(7L, activate, 0L)).isEqualTo(1);
            throw new IllegalStateException("realm version conflict");
        })).hasMessage("realm version conflict");
        assertThat(jdbc.queryForObject("SELECT status FROM tianquan_oauth.oauth_signing_key WHERE id=10", String.class)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT status FROM tianquan_oauth.oauth_signing_key WHERE id=11", String.class)).isEqualTo("PUBLISHED");
        jdbc.update("UPDATE tianquan_oauth.oauth_signing_key SET status='VERIFY_ONLY' WHERE id=11");
        assertThat(states.fenceRealmForKeyPublication(7L, 42L, 3L, 1L, 4L, 10L, 2L, "old", NOW, "worker")).isEqualTo(1);
        assertThat(keys.fenceObserved(7L, 10L, "old", 2L, OAuthKeyStatusEnum.ACTIVE, true, "tenant:7", 1L, NOW, "worker")).isEqualTo(1);
        var retire = new OAuthSigningKeyPO(); retire.setId(10L); retire.setKid("old"); retire.setAlgorithm("RS256");
        retire.setStatus(OAuthKeyStatusEnum.RETIRED); retire.setVersion(4L); retire.setUpdateUserId("worker"); retire.setUpdateTime(NOW);
        assertThat(keys.updateExpectedVersion(7L, retire, 3L)).isZero();
    }

    @Test void signingProofsUseTheSamePrimaryGroupAndNoLockingReads() throws Exception {
        var config = new Configuration();
        for (String resource : List.of("mapper/token/OAuthSecurityStateMapper.xml", "mapper/token/OAuthSigningKeyMapper.xml")) {
            try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
                new XMLMapperBuilder(input, config, resource, config.getSqlFragments()).parse();
            }
        }
        config.setEnvironment(new Environment("test", new SpringManagedTransactionFactory(), mock(DataSource.class)));
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
        var retired = new OAuthSigningKeyPO(); retired.setId(10L); retired.setKid("old"); retired.setAlgorithm("RS256");
        retired.setStatus(OAuthKeyStatusEnum.RETIRED); retired.setVersion(4L); retired.setUpdateUserId("worker"); retired.setUpdateTime(NOW);
        var params = new HashMap<String, Object>(); params.put("tenantId", 7L); params.put("id", 42L); params.put("expectedVersion", 3L);
        params.put("realmId", 1L); params.put("realmVersion", 4L); params.put("keyId", 10L); params.put("keyVersion", 2L);
        params.put("kid", "old"); params.put("status", OAuthKeyStatusEnum.ACTIVE); params.put("realmKey", "tenant:7");
        params.put("trustVersion", 1L); params.put("requireActiveBinding", true); params.put("po", retired);
        params.put("now", NOW); params.put("actor", "worker");
        MDC.put("tenantId", "7"); MDC.put("userId", "worker");
        try {
            Executor executor = mock(Executor.class);
            for (String id : List.of(OAuthSecurityStateMapper.class.getName() + ".fenceRealmForKeyPublication",
                    OAuthSigningKeyMapper.class.getName() + ".fenceObserved", OAuthSigningKeyMapper.class.getName() + ".updateExpectedVersion")) {
                var statement = config.getMappedStatement(id);
                String sql = statement.getBoundSql(params).getSql().toLowerCase();
                assertThat(sql).doesNotContain("for update", "for share");
                assertThat(parser.parse(sql, false)).isNotNull();
                var invocation = new Invocation(executor, Executor.class.getMethod("update", MappedStatement.class, Object.class), new Object[]{statement, params});
                assertThatCode(() -> new EgonColaOriginalSqlGuardInterceptor(properties).intercept(invocation)).doesNotThrowAnyException();
                var handler = config.newStatementHandler(executor, statement, params, RowBounds.DEFAULT, null, statement.getBoundSql(params));
                assertThatCode(() -> guard.beforePrepare(handler, null, null)).doesNotThrowAnyException();
            }
        } finally { MDC.remove("tenantId"); MDC.remove("userId"); }
    }
}
