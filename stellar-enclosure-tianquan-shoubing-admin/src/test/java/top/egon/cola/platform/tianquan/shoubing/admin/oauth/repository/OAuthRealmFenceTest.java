package top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
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
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.OAuthRealmMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.OAuthClientMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter.OAuthRealmConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.po.OAuthRealmPO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.impl.OAuthRealmRepositoryImpl;
import top.egon.cola.platform.tianquan.shoubing.admin.token.dao.OAuthRevocationMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OAuthRealmFenceTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/101"))
            .realmType(RealmTypeEnum.TENANT).realmKey("tenant:101").storagePartitionId(101L)
            .businessTenantId(101L).trustVersion(0L).build();

    @Test
    void observedRealmUsesAReplicaReadAndAConditionalWrite() {
        var mapper = mock(OAuthRealmMapper.class);
        var row = new OAuthRealmPO();
        row.setId(42L); row.setVersion(3L); row.setIssuer(realm.getIssuer().toASCIIString());
        row.setRealmKey(realm.getRealmKey()); row.setRealmType(realm.getRealmType());
        row.setStoragePartitionId(101L); row.setBusinessTenantId(101L);
        when(mapper.selectByRealmKey(101L, "tenant:101")).thenReturn(row);
        when(mapper.fenceObservedVersion(101L, 42L, "tenant:101", 3L, NOW, "service:tianquan-shoubing"))
                .thenReturn(1, 0);
        var repository = new OAuthRealmRepositoryImpl(mapper, new EgonColaMybatisPlusProperties(),
                mock(OAuthRealmConverter.class), () -> "service:tianquan-shoubing", Clock.fixed(NOW, ZoneOffset.UTC));
        MDC.put("tenantId", "777");
        try {
            assertThat(repository.fenceObservedVersion(realm)).isTrue();
            assertThat(repository.fenceObservedVersion(realm)).isFalse();
            assertThat(MDC.get("tenantId")).isEqualTo("777");
            verify(mapper, never()).selectByRealmKeyForUpdate(anyLong(), anyString());
        } finally {
            MDC.remove("tenantId");
        }
    }

    @Test
    void realmFencePassesTheOriginalAndFinalWriteGuards() throws Exception {
        var configuration = new Configuration();
        String resource = "mapper/oauth/OAuthRealmMapper.xml";
        try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
            new XMLMapperBuilder(input, configuration, resource, configuration.getSqlFragments()).parse();
        }
        configuration.setEnvironment(new Environment("test", new SpringManagedTransactionFactory(), mock(DataSource.class)));
        var properties = new EgonColaMybatisPlusProperties();
        var tenantGuard = new EgonColaTenantIdGuardInnerInterceptor(() -> "service:tianquan-shoubing", properties);
        new CommonAnnotationBeanPostProcessor().postProcessBeforeInitialization(tenantGuard, "sqlGuard");
        var routeGuard = new EgonColaLocalWriteGuardInnerInterceptor(query -> new EgonColaRouteResult(
                List.of(new EgonColaPhysicalTargetBO("primary", "tianquan_oauth", query.logicalTable())), "a".repeat(64)),
                tenantGuard, mock(EgonColaTwoLevelRouteStrategy.class), Map.of());
        var parameters = Map.<String, Object>of("tenantId", 101L, "id", 42L, "realmKey", "tenant:101",
                "expectedVersion", 3L, "now", NOW, "actor", "service:tianquan-shoubing");
        var statement = configuration.getMappedStatement(OAuthRealmMapper.class.getName() + ".fenceObservedVersion");
        String sql = statement.getBoundSql(parameters).getSql().toLowerCase(java.util.Locale.ROOT).replaceAll("\\s+", " ");
        assertThat(sql).startsWith("update ").contains("tenant_id = ?", "id = ?", "realm_key = ?", "version = ?",
                "version = version + 1", "deleted_at is null").doesNotContain("select", "for update");
        MDC.put("tenantId", "101");
        try {
            Executor executor = mock(Executor.class);
            var invocation = new Invocation(executor, Executor.class.getMethod("update", MappedStatement.class, Object.class),
                    new Object[]{statement, parameters});
            assertThatCode(() -> new EgonColaOriginalSqlGuardInterceptor(properties).intercept(invocation)).doesNotThrowAnyException();
            var handler = configuration.newStatementHandler(executor, statement, parameters, RowBounds.DEFAULT, null, statement.getBoundSql(parameters));
            assertThatCode(() -> routeGuard.beforePrepare(handler, null, null)).doesNotThrowAnyException();
        } finally {
            MDC.remove("tenantId");
        }
    }

    @Test
    void clientFenceIsTenantScopedAndPassesTheWriteGuards() throws Exception {
        var configuration = new Configuration();
        String resource = "mapper/oauth/OAuthClientMapper.xml";
        try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
            new XMLMapperBuilder(input, configuration, resource, configuration.getSqlFragments()).parse();
        }
        configuration.setEnvironment(new Environment("test", new SpringManagedTransactionFactory(), mock(DataSource.class)));
        var properties = new EgonColaMybatisPlusProperties();
        var tenantGuard = new EgonColaTenantIdGuardInnerInterceptor(() -> "service:tianquan-shoubing", properties);
        new CommonAnnotationBeanPostProcessor().postProcessBeforeInitialization(tenantGuard, "sqlGuard");
        var routeGuard = new EgonColaLocalWriteGuardInnerInterceptor(query -> new EgonColaRouteResult(
                List.of(new EgonColaPhysicalTargetBO("primary", "tianquan_oauth", query.logicalTable())), "a".repeat(64)),
                tenantGuard, mock(EgonColaTwoLevelRouteStrategy.class), Map.of());
        var parameters = Map.<String, Object>of("tenantId", 101L, "id", 42L, "clientId", "client-1",
                "expectedVersion", 3L, "now", NOW, "actor", "service:tianquan-shoubing");
        var statement = configuration.getMappedStatement(OAuthClientMapper.class.getName() + ".fenceObservedVersion");
        String sql = statement.getBoundSql(parameters).getSql().toLowerCase(java.util.Locale.ROOT).replaceAll("\\s+", " ");
        assertThat(sql).startsWith("update ").contains("tenant_id = ?", "id = ?", "client_id = ?", "version = ?",
                "version = version + 1", "deleted_at is null").doesNotContain("select", "for update");
        MDC.put("tenantId", "101");
        try {
            Executor executor = mock(Executor.class);
            var invocation = new Invocation(executor, Executor.class.getMethod("update", MappedStatement.class, Object.class),
                    new Object[]{statement, parameters});
            assertThatCode(() -> new EgonColaOriginalSqlGuardInterceptor(properties).intercept(invocation)).doesNotThrowAnyException();
            var handler = configuration.newStatementHandler(executor, statement, parameters, RowBounds.DEFAULT, null, statement.getBoundSql(parameters));
            assertThatCode(() -> routeGuard.beforePrepare(handler, null, null)).doesNotThrowAnyException();
        } finally {
            MDC.remove("tenantId");
        }
    }

    @Test
    void observedRevocationFenceIsVersionedAndRoutesAsAWrite() throws Exception {
        var configuration = new Configuration();
        String resource = "mapper/token/OAuthRevocationMapper.xml";
        try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
            new XMLMapperBuilder(input, configuration, resource, configuration.getSqlFragments()).parse();
        }
        configuration.setEnvironment(new Environment("test", new SpringManagedTransactionFactory(), mock(DataSource.class)));
        var properties = new EgonColaMybatisPlusProperties();
        var tenantGuard = new EgonColaTenantIdGuardInnerInterceptor(() -> "service:tianquan-shoubing", properties);
        new CommonAnnotationBeanPostProcessor().postProcessBeforeInitialization(tenantGuard, "sqlGuard");
        var routeGuard = new EgonColaLocalWriteGuardInnerInterceptor(query -> new EgonColaRouteResult(
                List.of(new EgonColaPhysicalTargetBO("primary", "tianquan_oauth", query.logicalTable())), "a".repeat(64)),
                tenantGuard, mock(EgonColaTwoLevelRouteStrategy.class), Map.of());
        var parameters = Map.<String, Object>of("tenantId", 101L, "id", 42L, "targetType", OAuthSecurityTargetEnum.JTI,
                "targetKey", "123456", "expectedVersion", 3L, "now", NOW, "actor", "service:tianquan-shoubing");
        var statement = configuration.getMappedStatement(OAuthRevocationMapper.class.getName() + ".fenceObservedVersion");
        String sql = statement.getBoundSql(parameters).getSql().toLowerCase(java.util.Locale.ROOT).replaceAll("\\s+", " ");
        assertThat(sql).startsWith("update ").contains("tenant_id = ?", "id = ?", "target_type = ?", "target_key = ?",
                "version = ?", "version = version + 1", "deleted_at is null").doesNotContain("select", "for update");
        MDC.put("tenantId", "101");
        try {
            Executor executor = mock(Executor.class);
            var invocation = new Invocation(executor, Executor.class.getMethod("update", MappedStatement.class, Object.class),
                    new Object[]{statement, parameters});
            assertThatCode(() -> new EgonColaOriginalSqlGuardInterceptor(properties).intercept(invocation)).doesNotThrowAnyException();
            var handler = configuration.newStatementHandler(executor, statement, parameters, RowBounds.DEFAULT, null, statement.getBoundSql(parameters));
            assertThatCode(() -> routeGuard.beforePrepare(handler, null, null)).doesNotThrowAnyException();
        } finally {
            MDC.remove("tenantId");
        }
    }
}
