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
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;

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

    @Test
    void realmRevisionAdvancesOnlyWhenThePrimaryHasNoRevocation() throws Exception {
        var configuration = new Configuration();
        String resource = "mapper/token/OAuthSecurityStateMapper.xml";
        try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
            new XMLMapperBuilder(input, configuration, resource, configuration.getSqlFragments()).parse();
        }
        configuration.setEnvironment(new Environment("test", new SpringManagedTransactionFactory(), mock(DataSource.class)));
        var properties = new EgonColaMybatisPlusProperties();
        var tenantGuard = new EgonColaTenantIdGuardInnerInterceptor(() -> "service:tianquan-shoubing", properties);
        new CommonAnnotationBeanPostProcessor().postProcessBeforeInitialization(tenantGuard, "sqlGuard");
        var tables = new ArrayList<String>();
        var guard = new EgonColaLocalWriteGuardInnerInterceptor(query -> {
            tables.add(query.logicalTable());
            return new EgonColaRouteResult(List.of(new EgonColaPhysicalTargetBO("primary", "tianquan_oauth", query.logicalTable())), "a".repeat(64));
        }, tenantGuard, mock(EgonColaTwoLevelRouteStrategy.class), Map.of());
        var parameters = Map.<String, Object>of("tenantId", 101L, "id", 42L, "expectedVersion", 4L,
                "targetType", OAuthSecurityTargetEnum.JTI, "targetKey", "123456", "revision", 8L,
                "now", Instant.parse("2026-10-28T00:00:00Z"), "actor", "service:tianquan-shoubing");
        var statement = configuration.getMappedStatement(OAuthSecurityStateMapper.class.getName() + ".advanceRealmIfRevocationAbsent");
        String sql = statement.getBoundSql(parameters).getSql().toLowerCase(java.util.Locale.ROOT).replaceAll("\\s+", " ");
        assertThat(sql).startsWith("update ").contains("s.tenant_id = ?", "s.id = ?", "s.version = ?", "s.revision < ?",
                "revision = ?", "not exists", "r.tenant_id = ?", "r.target_type = ?", "r.target_key = ?", "r.deleted_at is null");
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
        assertThat(parser.parse(sql, false)).isNotNull();
        MDC.put("tenantId", "101");
        try {
            Executor executor = mock(Executor.class);
            var invocation = new Invocation(executor, Executor.class.getMethod("update", MappedStatement.class, Object.class),
                    new Object[]{statement, parameters});
            assertThatCode(() -> new EgonColaOriginalSqlGuardInterceptor(properties).intercept(invocation)).doesNotThrowAnyException();
            var handler = configuration.newStatementHandler(executor, statement, parameters, RowBounds.DEFAULT, null, statement.getBoundSql(parameters));
            assertThatCode(() -> guard.beforePrepare(handler, null, null)).doesNotThrowAnyException();
            assertThat(tables).containsExactly("oauth_security_state", "oauth_revocation");
        } finally {
            MDC.remove("tenantId");
        }
    }

    @Test
    void subjectSeedRequiresPrimaryAbsenceOfStateAndAuthorizationInTheSameGroup() throws Exception {
        var configuration = new Configuration();
        String resource = "mapper/token/OAuthSecurityStateMapper.xml";
        try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
            new XMLMapperBuilder(input, configuration, resource, configuration.getSqlFragments()).parse();
        }
        configuration.setEnvironment(new Environment("test", new SpringManagedTransactionFactory(), mock(DataSource.class)));
        var properties = new EgonColaMybatisPlusProperties();
        var tenantGuard = new EgonColaTenantIdGuardInnerInterceptor(() -> "service:tianquan-shoubing", properties);
        new CommonAnnotationBeanPostProcessor().postProcessBeforeInitialization(tenantGuard, "sqlGuard");
        var tables = new ArrayList<String>();
        var guard = new EgonColaLocalWriteGuardInnerInterceptor(query -> {
            tables.add(query.logicalTable());
            return new EgonColaRouteResult(List.of(new EgonColaPhysicalTargetBO("primary", "tianquan_oauth", query.logicalTable())), "a".repeat(64));
        }, tenantGuard, mock(EgonColaTwoLevelRouteStrategy.class), Map.of());
        var parameters = Map.<String, Object>of("tenantId", 101L, "id", 42L, "expectedVersion", 4L,
                "subject", "alice", "revision", 8L, "now", Instant.parse("2026-10-28T00:00:00Z"),
                "actor", "service:tianquan-shoubing");
        var statement = configuration.getMappedStatement(OAuthSecurityStateMapper.class.getName() + ".advanceRealmIfSubjectAbsent");
        String sql = statement.getBoundSql(parameters).getSql().toLowerCase(java.util.Locale.ROOT).replaceAll("\\s+", " ");
        assertThat(sql).contains("s.tenant_id = ?", "s.id = ?", "s.version = ?", "subject_state.tenant_id = ?",
                "subject_state.target_key = ?", "a.tenant_id = ?", "a.principal_name = ?", "a.principal_type = 'user'",
                "auth.tenant_id = ?", "auth.subject = ?");
        var parser = new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
        assertThat(parser.parse(sql, false)).isNotNull();
        MDC.put("tenantId", "101");
        try {
            Executor executor = mock(Executor.class);
            var invocation = new Invocation(executor, Executor.class.getMethod("update", MappedStatement.class, Object.class),
                    new Object[]{statement, parameters});
            assertThatCode(() -> new EgonColaOriginalSqlGuardInterceptor(properties).intercept(invocation)).doesNotThrowAnyException();
            var handler = configuration.newStatementHandler(executor, statement, parameters, RowBounds.DEFAULT, null, statement.getBoundSql(parameters));
            assertThatCode(() -> guard.beforePrepare(handler, null, null)).doesNotThrowAnyException();
            assertThat(tables).contains("oauth_security_state", "oauth_authorization", "oauth_authentication");
            var seed = configuration.getMappedStatement(OAuthSecurityStateMapper.class.getName() + ".fenceRealmIfSubjectAbsent");
            var seedSql = seed.getBoundSql(parameters).getSql().toLowerCase(java.util.Locale.ROOT);
            assertThat(seedSql).contains("s.version = ?", "subject_state.tenant_id = ?", "a.principal_name = ?")
                    .doesNotContain("for update");
            assertThat(parser.parse(seedSql, false)).isNotNull();
            var seedInvocation = new Invocation(executor, Executor.class.getMethod("update", MappedStatement.class, Object.class),
                    new Object[]{seed, parameters});
            assertThatCode(() -> new EgonColaOriginalSqlGuardInterceptor(properties).intercept(seedInvocation)).doesNotThrowAnyException();
            var seedHandler = configuration.newStatementHandler(executor, seed, parameters, RowBounds.DEFAULT, null, seed.getBoundSql(parameters));
            assertThatCode(() -> guard.beforePrepare(seedHandler, null, null)).doesNotThrowAnyException();
            var duplicateParameters = Map.<String, Object>of("tenantId", 101L, "id", 42L, "expectedVersion", 4L,
                    "subject", "alice", "sourceRevision", 7L, "fingerprint", "a".repeat(64), "now", Instant.parse("2026-10-28T00:00:00Z"),
                    "actor", "service:tianquan-shoubing");
            var duplicate = configuration.getMappedStatement(OAuthSecurityStateMapper.class.getName() + ".fenceSubjectAtLeast");
            assertThat(duplicate.getBoundSql(duplicateParameters).getSql().toLowerCase(java.util.Locale.ROOT))
                    .contains("directory_subject_revision > ?", "directory_subject_fingerprint = ?", "tenant_id = ?", "version = ?");
            var duplicateHandler = configuration.newStatementHandler(executor, duplicate, duplicateParameters,
                    RowBounds.DEFAULT, null, duplicate.getBoundSql(duplicateParameters));
            assertThatCode(() -> guard.beforePrepare(duplicateHandler, null, null)).doesNotThrowAnyException();
        } finally {
            MDC.remove("tenantId");
        }
    }
    @Test
    void consentAbsenceFenceIsTenantScopedAndGuarded() throws Exception {
        var configuration = new Configuration();
        String resource = "mapper/token/OAuthSecurityStateMapper.xml";
        try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
            new XMLMapperBuilder(input, configuration, resource, configuration.getSqlFragments()).parse();
        }
        configuration.setEnvironment(new Environment("test", new SpringManagedTransactionFactory(), mock(DataSource.class)));
        var properties = new EgonColaMybatisPlusProperties();
        var tenantGuard = new EgonColaTenantIdGuardInnerInterceptor(() -> "service:tianquan-shoubing", properties);
        new CommonAnnotationBeanPostProcessor().postProcessBeforeInitialization(tenantGuard, "sqlGuard");
        var tables = new ArrayList<String>();
        var guard = new EgonColaLocalWriteGuardInnerInterceptor(query -> {
            tables.add(query.logicalTable());
            return new EgonColaRouteResult(List.of(new EgonColaPhysicalTargetBO("primary", "tianquan_oauth", query.logicalTable())), "a".repeat(64));
        }, tenantGuard, mock(EgonColaTwoLevelRouteStrategy.class), Map.of());
        var parameters = Map.<String, Object>of("tenantId", 101L, "id", 42L, "expectedVersion", 4L,
                "clientPk", 5L, "subject", "alice", "resourceUri", "https://api.example.test", "now", Instant.parse("2026-10-28T00:00:00Z"), "actor", "service:tianquan-shoubing");
        var statement = configuration.getMappedStatement(OAuthSecurityStateMapper.class.getName() + ".fenceRealmIfConsentInactive");
        var sql = statement.getBoundSql(parameters).getSql().toLowerCase(java.util.Locale.ROOT);
        assertThat(sql).contains("not exists", "c.client_pk = ?", "c.subject = ?", "c.resource_uri = ?", "c.status = 'active'")
                .doesNotContain("for update");
        assertThat(postgresParser().parse(sql, false)).isNotNull();
        MDC.put("tenantId", "101");
        try {
            Executor executor = mock(Executor.class);
            var invocation = new Invocation(executor, Executor.class.getMethod("update", MappedStatement.class, Object.class),
                    new Object[]{statement, parameters});
            assertThatCode(() -> new EgonColaOriginalSqlGuardInterceptor(properties).intercept(invocation)).doesNotThrowAnyException();
            var handler = configuration.newStatementHandler(executor, statement, parameters, RowBounds.DEFAULT, null, statement.getBoundSql(parameters));
            assertThatCode(() -> guard.beforePrepare(handler, null, null)).doesNotThrowAnyException();
            assertThat(tables).containsExactly("oauth_security_state", "oauth_consent");
        } finally { MDC.remove("tenantId"); }
    }

    @Test
    void orderedDeliveryReceiptAndPredecessorUseTheSameShardGuard() throws Exception {
        var configuration = new Configuration();
        for (String resource : List.of("mapper/token/OAuthSecurityStateMapper.xml", "mapper/token/SubjectDeliveryReceiptMapper.xml")) {
            try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
                new XMLMapperBuilder(input, configuration, resource, configuration.getSqlFragments()).parse();
            }
        }
        configuration.setEnvironment(new Environment("test", new SpringManagedTransactionFactory(), mock(DataSource.class)));
        var properties = new EgonColaMybatisPlusProperties();
        var tenantGuard = new EgonColaTenantIdGuardInnerInterceptor(() -> "service:tianquan-shoubing", properties);
        new CommonAnnotationBeanPostProcessor().postProcessBeforeInitialization(tenantGuard, "sqlGuard");
        var tables = new ArrayList<String>();
        var guard = new EgonColaLocalWriteGuardInnerInterceptor(query -> {
            tables.add(query.logicalTable());
            return new EgonColaRouteResult(List.of(new EgonColaPhysicalTargetBO("primary", "tianquan_oauth", query.logicalTable())), "a".repeat(64));
        }, tenantGuard, mock(EgonColaTwoLevelRouteStrategy.class), Map.of());
        var parameters = new java.util.HashMap<String, Object>();
        parameters.put("tenantId", 101L); parameters.put("id", 42L); parameters.put("expectedVersion", 4L);
        parameters.put("subject", "alice"); parameters.put("sourceRevision", 20L); parameters.put("previousRevision", 10L);
        parameters.put("payloadFingerprint", "a".repeat(64));
        parameters.put("eventId", "event-20"); parameters.put("now", Instant.parse("2026-10-28T00:00:00Z"));
        parameters.put("actor", "service:tianquan-shoubing");
        MDC.put("tenantId", "101"); MDC.put("userId", "service:tianquan-shoubing");
        try {
            Executor executor = mock(Executor.class);
            for (String id : List.of(OAuthSecurityStateMapper.class.getName() + ".fenceSubjectDelivery",
                    OAuthSecurityStateMapper.class.getName() + ".fenceSubjectDeliveryDuplicate",
                    top.egon.cola.platform.tianquan.shoubing.admin.token.dao.SubjectDeliveryReceiptMapper.class.getName() + ".insertIfAbsent")) {
                var statement = configuration.getMappedStatement(id);
                assertThat(statement.getBoundSql(parameters).getSql().toLowerCase()).doesNotContain("for update", "for share");
                assertThat(postgresParser().parse(statement.getBoundSql(parameters).getSql(), false)).isNotNull();
                var invocation = new Invocation(executor, Executor.class.getMethod("update", MappedStatement.class, Object.class),
                        new Object[]{statement, parameters});
                assertThatCode(() -> new EgonColaOriginalSqlGuardInterceptor(properties).intercept(invocation)).doesNotThrowAnyException();
                var handler = configuration.newStatementHandler(executor, statement, parameters, RowBounds.DEFAULT, null, statement.getBoundSql(parameters));
                assertThatCode(() -> guard.beforePrepare(handler, null, null)).doesNotThrowAnyException();
            }
            assertThat(tables).contains("oauth_security_state", "oauth_subject_delivery_receipt");
            var cross = new EgonColaLocalWriteGuardInnerInterceptor(query -> new EgonColaRouteResult(List.of(
                    new EgonColaPhysicalTargetBO(query.logicalTable().equals("oauth_security_state") ? "primary_a" : "primary_b",
                            "tianquan_oauth", query.logicalTable())), "a".repeat(64)), tenantGuard,
                    mock(EgonColaTwoLevelRouteStrategy.class), Map.of());
            var statement = configuration.getMappedStatement(OAuthSecurityStateMapper.class.getName() + ".fenceSubjectDelivery");
            var handler = configuration.newStatementHandler(executor, statement, parameters, RowBounds.DEFAULT, null, statement.getBoundSql(parameters));
            assertThatThrownBy(() -> cross.beforePrepare(handler, null, null)).hasMessageContaining("LOCAL_WRITE_TARGET_MISMATCH");
        } finally { MDC.remove("tenantId"); MDC.remove("userId"); }
    }

    private static org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine postgresParser() {
        return new org.apache.shardingsphere.infra.parser.ShardingSphereSQLParserEngine(
                org.apache.shardingsphere.infra.spi.type.typed.TypedSPILoader.getService(
                        org.apache.shardingsphere.database.connector.core.type.DatabaseType.class, "PostgreSQL"),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64),
                new org.apache.shardingsphere.sql.parser.engine.api.CacheOption(16, 64));
    }
}
