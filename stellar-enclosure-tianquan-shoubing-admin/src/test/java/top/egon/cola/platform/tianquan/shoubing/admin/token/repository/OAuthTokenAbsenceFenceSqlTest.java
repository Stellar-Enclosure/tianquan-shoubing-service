package top.egon.cola.platform.tianquan.shoubing.admin.token.repository;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.apache.ibatis.builder.xml.XMLMapperBuilder;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.plugin.Invocation;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.RowBounds;
import org.junit.jupiter.api.Test;
import org.mybatis.spring.transaction.SpringManagedTransactionFactory;
import org.slf4j.MDC;
import org.springframework.context.annotation.CommonAnnotationBeanPostProcessor;
import top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties;
import top.egon.cola.component.common.mybatis.interceptor.EgonColaLocalWriteGuardInnerInterceptor;
import top.egon.cola.component.common.mybatis.interceptor.EgonColaOriginalSqlGuardInterceptor;
import top.egon.cola.component.common.mybatis.interceptor.EgonColaTenantIdGuardInnerInterceptor;
import top.egon.cola.component.common.mybatis.routing.EgonColaPhysicalTargetBO;
import top.egon.cola.component.common.mybatis.routing.EgonColaRouteResult;
import top.egon.cola.component.common.mybatis.routing.EgonColaTwoLevelRouteStrategy;
import top.egon.cola.platform.tianquan.shoubing.admin.token.dao.OAuthSecurityStateMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class OAuthTokenAbsenceFenceSqlTest {
    @Test
    void replicaMissIsConfirmedOnlyByATenantScopedVersionedPrimaryWrite() throws Exception {
        var configuration = new Configuration();
        String resource = "mapper/token/OAuthSecurityStateMapper.xml";
        try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
            new XMLMapperBuilder(input, configuration, resource, configuration.getSqlFragments()).parse();
        }
        configuration.setEnvironment(new Environment("test", new SpringManagedTransactionFactory(), mock(DataSource.class)));
        var properties = new EgonColaMybatisPlusProperties();
        var tenantGuard = new EgonColaTenantIdGuardInnerInterceptor(() -> "service:tianquan-shoubing", properties);
        new CommonAnnotationBeanPostProcessor().postProcessBeforeInitialization(tenantGuard, "sqlGuard");
        var originalGuard = new EgonColaOriginalSqlGuardInterceptor(properties);
        var parameters = Map.<String, Object>of("tenantId", 101L, "id", 42L, "expectedVersion", 4L,
                "tokenDigest", "1".repeat(64), "now", Instant.parse("2026-10-28T00:00:00Z"), "actor", "service:tianquan-shoubing");
        var statement = configuration.getMappedStatement(OAuthSecurityStateMapper.class.getName() + ".fenceRealmWhenTokenAbsent");
        String sql = statement.getBoundSql(parameters).getSql().toLowerCase(java.util.Locale.ROOT).replaceAll("\\s+", " ");
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
        assertThat(parser.parse(sql, false)).isNotNull();
        assertThat(sql).startsWith("update ").contains("s.tenant_id = ?", "s.id = ?", "s.version = ?",
                "s.target_type = 'realm'", "s.target_key = 'self'", "version = s.version + 1", "s.deleted_at is null",
                "not exists", "t.tenant_id = ?", "t.token_digest = ?", "t.deleted_at is null").doesNotContain("for update");
        var tables = new ArrayList<String>();
        var guard = new EgonColaLocalWriteGuardInnerInterceptor(query -> {
            tables.add(query.logicalTable());
            return new EgonColaRouteResult(List.of(new EgonColaPhysicalTargetBO("primary", "tianquan_oauth", query.logicalTable())), "a".repeat(64));
        }, tenantGuard, mock(EgonColaTwoLevelRouteStrategy.class), Map.of());
        MDC.put("tenantId", "101");
        try {
            Executor executor = mock(Executor.class);
            var invocation = new Invocation(executor, Executor.class.getMethod("update", MappedStatement.class, Object.class),
                    new Object[]{statement, parameters});
            assertThatCode(() -> originalGuard.intercept(invocation)).doesNotThrowAnyException();
            var handler = configuration.newStatementHandler(executor, statement, parameters, RowBounds.DEFAULT, null, statement.getBoundSql(parameters));
            assertThatCode(() -> guard.beforePrepare(handler, null, null)).doesNotThrowAnyException();
            assertThat(tables).containsExactly("oauth_security_state", "oauth_token");
            var crossGroup = new EgonColaLocalWriteGuardInnerInterceptor(query -> new EgonColaRouteResult(
                    List.of(new EgonColaPhysicalTargetBO(query.logicalTable().equals("oauth_security_state") ? "primary_a" : "primary_b",
                            "tianquan_oauth", query.logicalTable())), "a".repeat(64)), tenantGuard,
                    mock(EgonColaTwoLevelRouteStrategy.class), Map.of());
            var crossHandler = configuration.newStatementHandler(executor, statement, parameters, RowBounds.DEFAULT, null, statement.getBoundSql(parameters));
            assertThatThrownBy(() -> crossGroup.beforePrepare(crossHandler, null, null)).hasMessageContaining("LOCAL_WRITE_TARGET_MISMATCH");
        } finally {
            MDC.remove("tenantId");
        }
    }
}
