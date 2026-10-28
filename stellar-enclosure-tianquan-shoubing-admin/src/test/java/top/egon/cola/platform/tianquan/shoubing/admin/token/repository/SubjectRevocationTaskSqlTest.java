package top.egon.cola.platform.tianquan.shoubing.admin.token.repository;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
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
import top.egon.cola.platform.tianquan.shoubing.admin.token.dao.SubjectRevocationTaskMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.SubjectRevocationTaskBO;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

class SubjectRevocationTaskSqlTest {
    @Test void sourceClaimsAndHistoryProofStayInOnePrimaryGroup() throws Exception {
        var configuration = new Configuration();
        String resource = "mapper/token/SubjectRevocationTaskMapper.xml";
        try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
            new XMLMapperBuilder(input, configuration, resource, configuration.getSqlFragments()).parse();
        }
        configuration.setEnvironment(new Environment("test", new SpringManagedTransactionFactory(), mock(DataSource.class)));
        var properties = new EgonColaMybatisPlusProperties();
        var tenantGuard = new EgonColaTenantIdGuardInnerInterceptor(() -> "system:subject-worker", properties);
        new CommonAnnotationBeanPostProcessor().postProcessBeforeInitialization(tenantGuard, "sqlGuard");
        var groups = new ArrayList<String>();
        var routeGuard = new EgonColaLocalWriteGuardInnerInterceptor(query -> {
            groups.add(query.logicalTable());
            return new EgonColaRouteResult(List.of(new EgonColaPhysicalTargetBO("source_primary", "tianquan_oauth", query.logicalTable())), "a".repeat(64));
        }, tenantGuard, mock(EgonColaTwoLevelRouteStrategy.class), Map.of());
        var task = new SubjectRevocationTaskBO(); task.setId(17L); task.setTenantId(9000L); task.setVersion(4L);
        task.setIdentitySub("alice"); task.setTargetTenantId("7"); task.setSourceRevision(8L);
        task.setSubjectEnabled(false); task.setReasonCode("USER_DISABLED");
        var parameters = new HashMap<String, Object>();
        parameters.put("tenantId", 9000L); parameters.put("task", task); parameters.put("id", 11L);
        parameters.put("expectedVersion", 4L); parameters.put("subject", "alice"); parameters.put("after", 0L);
        parameters.put("last", 7L); parameters.put("tenants", List.of(7L)); parameters.put("count", 1); parameters.put("owner", "worker");
        parameters.put("now", Instant.parse("2026-10-28T00:00:00Z")); parameters.put("until", Instant.parse("2026-10-28T00:01:00Z"));
        parameters.put("next", Instant.parse("2026-10-28T00:00:05Z")); parameters.put("actor", "system:subject-worker");
        parameters.put("limit", 100);
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
        MDC.put("tenantId", "9000"); MDC.put("userId", "system:subject-worker");
        try {
            Executor executor = mock(Executor.class);
            for (String method : List.of("selectHistoryPage", "selectDue")) {
                var read = configuration.getMappedStatement(SubjectRevocationTaskMapper.class.getName() + "." + method);
                var bound = read.getBoundSql(parameters);
                assertThat(bound.getSql().toLowerCase()).doesNotContain("for update", "for share");
                assertThat(parser.parse(bound.getSql(), false)).isNotNull();
                assertThatCode(() -> tenantGuard.beforeQuery(executor, read, parameters, RowBounds.DEFAULT, null, bound))
                        .doesNotThrowAnyException();
            }
            for (String method : List.of("fenceHistoryPage", "insertTask", "claim", "complete", "retry")) {
                var statement = configuration.getMappedStatement(SubjectRevocationTaskMapper.class.getName() + "." + method);
                String sql = statement.getBoundSql(parameters).getSql();
                assertThat(sql.toLowerCase()).doesNotContain("for update", "for share");
                assertThat(parser.parse(sql, false)).isNotNull();
                var invocation = new Invocation(executor, Executor.class.getMethod("update", MappedStatement.class, Object.class),
                        new Object[]{statement, parameters});
                assertThatCode(() -> new EgonColaOriginalSqlGuardInterceptor(properties).intercept(invocation)).doesNotThrowAnyException();
                var handler = configuration.newStatementHandler(executor, statement, parameters, RowBounds.DEFAULT, null, statement.getBoundSql(parameters));
                assertThatCode(() -> routeGuard.beforePrepare(handler, null, null)).doesNotThrowAnyException();
            }
            assertThat(groups).contains("oauth_security_state", "oauth_subject_tenant_history", "oauth_subject_revocation_task");
            var statement = configuration.getMappedStatement(SubjectRevocationTaskMapper.class.getName() + ".fenceHistoryPage");
            var cross = new EgonColaLocalWriteGuardInnerInterceptor(query -> new EgonColaRouteResult(List.of(
                    new EgonColaPhysicalTargetBO(query.logicalTable().equals("oauth_security_state") ? "source_a" : "source_b",
                            "tianquan_oauth", query.logicalTable())), "a".repeat(64)), tenantGuard,
                    mock(EgonColaTwoLevelRouteStrategy.class), Map.of());
            var handler = configuration.newStatementHandler(executor, statement, parameters, RowBounds.DEFAULT, null, statement.getBoundSql(parameters));
            assertThatThrownBy(() -> cross.beforePrepare(handler, null, null)).hasMessageContaining("LOCAL_WRITE_TARGET_MISMATCH");
        } finally { MDC.remove("tenantId"); MDC.remove("userId"); }
    }
}
