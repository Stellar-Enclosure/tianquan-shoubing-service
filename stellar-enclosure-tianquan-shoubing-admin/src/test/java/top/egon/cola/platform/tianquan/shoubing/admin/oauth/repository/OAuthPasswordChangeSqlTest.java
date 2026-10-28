package top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository;

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
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.OAuthInteractionMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.PasswordChangeReceiptMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthInteractionBO;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

class OAuthPasswordChangeSqlTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");
    private final OAuthInteractionBO interaction = OAuthInteractionBO.builder().id(11L).version(0L).interactionId("interaction")
            .purpose("PASSWORD_CHANGE").restrictedSubject("alice").browserBindingDigest("a".repeat(64))
            .csrfDigest("b".repeat(64)).state("PENDING").build();

    @Test void claimAndCompletionUseBindingAndPrimaryVersionConditions() throws Exception {
        var source = new JdbcDataSource(); source.setURL("jdbc:h2:mem:" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1");
        var jdbc = new JdbcTemplate(source); jdbc.execute("CREATE SCHEMA tianquan_oauth");
        jdbc.execute("""
                CREATE TABLE tianquan_oauth.oauth_interaction (id BIGINT, tenant_id BIGINT, version BIGINT,
                  interaction_id VARCHAR, purpose VARCHAR, restricted_subject VARCHAR, browser_binding_digest VARCHAR,
                  csrf_digest VARCHAR, authentication_jti_digest VARCHAR, state VARCHAR, expires_at TIMESTAMP WITH TIME ZONE,
                  deleted_at TIMESTAMP, consumed_at TIMESTAMP WITH TIME ZONE, update_user_id VARCHAR, update_time TIMESTAMP WITH TIME ZONE)
                """);
        jdbc.update("INSERT INTO tianquan_oauth.oauth_interaction (id,tenant_id,version,interaction_id,purpose,restricted_subject,browser_binding_digest,csrf_digest,state,expires_at) VALUES (11,7,0,'interaction','PASSWORD_CHANGE','alice',?,?,'PENDING',?)",
                "a".repeat(64), "b".repeat(64), NOW.plusSeconds(20));
        var factory = new SqlSessionFactoryBean(); factory.setDataSource(source);
        factory.setMapperLocations(new ClassPathResource("mapper/oauth/OAuthInteractionMapper.xml"));
        var mapper = new SqlSessionTemplate(factory.getObject()).getMapper(OAuthInteractionMapper.class);
        assertThat(mapper.claimPasswordChange(7L, interaction.toBuilder().csrfDigest("c".repeat(64)).build(), NOW, "worker")).isZero();
        assertThat(mapper.claimPasswordChange(7L, interaction, NOW, "worker")).isEqualTo(1);
        assertThat(mapper.claimPasswordChange(7L, interaction, NOW, "worker")).isZero();
        var claimed = interaction.toBuilder().version(1L).state("AUTHENTICATED").build();
        assertThat(mapper.consumePasswordChange(7L, claimed, NOW, "worker")).isEqualTo(1);
        assertThat(mapper.consumePasswordChange(7L, claimed, NOW, "worker")).isZero();
        assertThat(jdbc.queryForObject("SELECT state FROM tianquan_oauth.oauth_interaction WHERE id=11", String.class)).isEqualTo("CONSUMED");
    }

    @Test void receiptAndInteractionWritesPassRoutingGuards() throws Exception {
        var config = new Configuration();
        for (String resource : List.of("mapper/oauth/OAuthInteractionMapper.xml", "mapper/oauth/PasswordChangeReceiptMapper.xml")) {
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
        var params = new HashMap<String, Object>();
        params.put("tenantId", 7L); params.put("id", 12L); params.put("interaction", interaction);
        params.put("operationKey", "c".repeat(64)); params.put("subject", "alice"); params.put("originTenantId", 7L);
        params.put("now", NOW); params.put("actor", "worker");
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
        MDC.put("tenantId", "7"); MDC.put("userId", "worker");
        try {
            Executor executor = mock(Executor.class);
            for (String id : List.of(OAuthInteractionMapper.class.getName() + ".claimPasswordChange",
                    OAuthInteractionMapper.class.getName() + ".consumePasswordChange", PasswordChangeReceiptMapper.class.getName() + ".insertIfAbsent")) {
                var statement = config.getMappedStatement(id);
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
