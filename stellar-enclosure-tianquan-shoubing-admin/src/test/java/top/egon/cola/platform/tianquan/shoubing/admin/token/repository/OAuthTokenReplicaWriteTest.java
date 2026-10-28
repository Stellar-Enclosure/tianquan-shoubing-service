package top.egon.cola.platform.tianquan.shoubing.admin.token.repository;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.dao.OptimisticLockingFailureException;
import top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.dao.OAuthTokenMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthTokenBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.converter.OAuthTokenConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthTokenTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.po.OAuthTokenPO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.impl.OAuthTokenRepositoryImpl;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthPayloadCipherComponent;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OAuthTokenReplicaWriteTest {
    @Test
    void tokenSaveReadsWithoutALockAndWritesUnderVersionCas() throws Exception {
        var configuration = new org.apache.ibatis.session.Configuration();
        String resource = "mapper/token/OAuthTokenMapper.xml";
        try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
            new org.apache.ibatis.builder.xml.XMLMapperBuilder(input, configuration, resource,
                    configuration.getSqlFragments()).parse();
        }
        String prefix = OAuthTokenMapper.class.getName() + ".";
        String read = configuration.getMappedStatement(prefix + "selectByTokenDigest")
                .getBoundSql(java.util.Map.of("tenantId", 1001L, "tokenDigest", "a".repeat(64))).getSql()
                .toLowerCase(java.util.Locale.ROOT).replaceAll("\\s+", " ");
        var row = new OAuthTokenPO();
        String write = configuration.getMappedStatement(prefix + "updateExpectedVersion")
                .getBoundSql(java.util.Map.of("tenantId", 1001L, "po", row, "expectedVersion", 1L)).getSql()
                .toLowerCase(java.util.Locale.ROOT).replaceAll("\\s+", " ");
        assertThat(read).contains("tenant_id = ?", "token_digest = ?", "deleted_at is null")
                .doesNotContain("for update", "for share");
        assertThat(write).contains("tenant_id = ?", "id = ?", "token_digest = ?", "version = ?", "deleted_at is null");
    }

    @Test
    void tokenAndAuthorizationAreReadInOneReplicaSnapshotAtTheObservedVersion() throws Exception {
        var configuration = new org.apache.ibatis.session.Configuration();
        String resource = "mapper/token/OAuthTokenMapper.xml";
        try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
            new org.apache.ibatis.builder.xml.XMLMapperBuilder(input, configuration, resource,
                    configuration.getSqlFragments()).parse();
        }
        var statement = configuration.getMappedStatement(OAuthTokenMapper.class.getName() + ".selectAtAuthorizationVersion");
        var parameters = java.util.Map.<String, Object>of("tenantId", 1001L, "tokenDigest", "a".repeat(64),
                "authorizationPk", 9L, "authorizationVersion", 7L);
        String sql = statement.getBoundSql(parameters).getSql().toLowerCase(java.util.Locale.ROOT).replaceAll("\\s+", " ");
        assertThat(sql).contains("a.tenant_id = t.tenant_id", "a.id = t.authorization_pk",
                "t.tenant_id = ?", "t.authorization_pk = ?", "a.version = ?", "a.status = 'active'",
                "t.deleted_at is null", "a.deleted_at is null").doesNotContain("for update", "for share");
        var guard = new top.egon.cola.component.common.mybatis.interceptor.EgonColaTenantIdGuardInnerInterceptor(
                () -> "service:tianquan-shoubing", new EgonColaMybatisPlusProperties());
        new org.springframework.context.annotation.CommonAnnotationBeanPostProcessor()
                .postProcessBeforeInitialization(guard, "sqlGuard");
        configuration.setEnvironment(new org.apache.ibatis.mapping.Environment("test",
                new org.mybatis.spring.transaction.SpringManagedTransactionFactory(), mock(javax.sql.DataSource.class)));
        var routeGuard = new top.egon.cola.component.common.mybatis.interceptor.EgonColaLocalWriteGuardInnerInterceptor(
                query -> new top.egon.cola.component.common.mybatis.routing.EgonColaRouteResult(
                        java.util.List.of(new top.egon.cola.component.common.mybatis.routing.EgonColaPhysicalTargetBO(
                                "primary", "tianquan_oauth", query.logicalTable())), "a".repeat(64)),
                guard, mock(top.egon.cola.component.common.mybatis.routing.EgonColaTwoLevelRouteStrategy.class), java.util.Map.of());
        org.slf4j.MDC.put("tenantId", "1001");
        try {
            org.assertj.core.api.Assertions.assertThatCode(() -> guard.beforeQuery(
                    mock(org.apache.ibatis.executor.Executor.class), statement, parameters,
                    org.apache.ibatis.session.RowBounds.DEFAULT, null, statement.getBoundSql(parameters)))
                    .doesNotThrowAnyException();
            var handler = configuration.newStatementHandler(mock(org.apache.ibatis.executor.Executor.class), statement,
                    parameters, org.apache.ibatis.session.RowBounds.DEFAULT, null, statement.getBoundSql(parameters));
            org.assertj.core.api.Assertions.assertThatCode(() -> routeGuard.beforePrepare(handler, null, null))
                    .doesNotThrowAnyException();
        } finally {
            org.slf4j.MDC.remove("tenantId");
        }
    }

    @Test
    void staleReplicaCandidatesCannotBothUpdateTheSameToken() throws Exception {
        var mapper = mock(OAuthTokenMapper.class);
        var converter = mock(OAuthTokenConverter.class);
        var cipher = mock(OAuthPayloadCipherComponent.class);
        var json = new ObjectMapper();
        var now = Instant.parse("2026-10-28T00:00:00Z");
        var row = new OAuthTokenPO();
        row.setId(101L); row.setTenantId(1001L); row.setVersion(1L); row.setAuthorizationPk(9L);
        row.setTokenType(OAuthTokenTypeEnum.REFRESH); row.setTokenDigest("a".repeat(64));
        row.setTokenCiphertext("ciphertext"); row.setJti("jti"); row.setIssuedAt(now); row.setExpiresAt(now.plusSeconds(300));
        var requested = OAuthTokenBO.builder().id(101L).version(2L).authorizationPk(9L)
                .tokenType(OAuthTokenTypeEnum.REFRESH).tokenDigest("a".repeat(64)).jti("jti")
                .issuedAt(now).expiresAt(now.plusSeconds(300)).build();
        var realm = TrustedRealmBO.builder().issuer(URI.create("https://auth.example/tenants/1001"))
                .realmKey("tenant:1001").realmType(RealmTypeEnum.TENANT).storagePartitionId(1001L)
                .businessTenantId(1001L).trustVersion(0L).build();
        var barrier = new CyclicBarrier(2);
        var written = new AtomicBoolean();
        when(mapper.selectByTokenDigest(anyLong(), anyString())).thenAnswer(call -> {
            assertThat(call.<Long>getArgument(0)).isEqualTo(1001L);
            barrier.await(5, TimeUnit.SECONDS);
            return row;
        });
        when(mapper.updateExpectedVersion(anyLong(), any(), anyLong()))
                .thenAnswer(call -> written.compareAndSet(false, true) ? 1 : 0);
        when(converter.toSource(any(), any(), any(), anyString(), any())).thenAnswer(call -> new OAuthTokenPO());
        when(converter.toTarget(any(), any(), any(), anyString(), any())).thenReturn(requested);
        var repository = new OAuthTokenRepositoryImpl(mapper, new EgonColaMybatisPlusProperties(), converter,
                cipher, json, () -> "service:tianquan-shoubing", Clock.fixed(now, java.time.ZoneOffset.UTC));
        try (var workers = Executors.newFixedThreadPool(2)) {
            var first = workers.submit(() -> save(repository, realm, requested));
            var second = workers.submit(() -> save(repository, realm, requested));
            assertThat(java.util.List.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(true, false);
        }
        verify(mapper, never()).selectByTokenDigestForUpdate(anyLong(), anyString());
    }

    private static boolean save(OAuthTokenRepositoryImpl repository, TrustedRealmBO realm, OAuthTokenBO token) {
        org.slf4j.MDC.put("tenantId", "777");
        org.slf4j.MDC.put("userId", "original");
        try {
            repository.save(realm, token, 1L);
            return true;
        } catch (OptimisticLockingFailureException conflict) {
            assertThat(conflict).hasMessageContaining("version changed after the candidate read");
            return false;
        } finally {
            assertThat(org.slf4j.MDC.get("tenantId")).isEqualTo("777");
            assertThat(org.slf4j.MDC.get("userId")).isEqualTo("original");
            org.slf4j.MDC.clear();
        }
    }
}
