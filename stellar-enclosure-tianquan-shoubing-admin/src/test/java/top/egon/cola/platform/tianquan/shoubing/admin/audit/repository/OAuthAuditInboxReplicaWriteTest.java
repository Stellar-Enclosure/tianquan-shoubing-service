package top.egon.cola.platform.tianquan.shoubing.admin.audit.repository;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.ibatis.builder.xml.XMLMapperBuilder;
import org.apache.ibatis.session.Configuration;
import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;
import org.slf4j.MDC;
import org.springframework.dao.OptimisticLockingFailureException;
import top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.dao.OAuthAuditInboxMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditInboxBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.converter.OAuthAuditInboxConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.po.OAuthAuditInboxPO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.impl.OAuthAuditInboxRepositoryImpl;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class OAuthAuditInboxReplicaWriteTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");

    @Test
    void mappedReadIsUnlockedAndUpdateGuardsTenantIdentityAndVersion() throws Exception {
        var configuration = new Configuration();
        String resource = "mapper/audit/OAuthAuditInboxMapper.xml";
        try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
            new XMLMapperBuilder(input, configuration, resource, configuration.getSqlFragments()).parse();
        }
        String prefix = OAuthAuditInboxMapper.class.getName() + ".";
        String read = configuration.getMappedStatement(prefix + "selectByKey")
                .getBoundSql(Map.of("tenantId", 1001L, "key", "event-1")).getSql()
                .toLowerCase(java.util.Locale.ROOT).replaceAll("\\s+", " ");
        String update = configuration.getMappedStatement(prefix + "updateExpectedVersion")
                .getBoundSql(Map.of("tenantId", 1001L, "po", new OAuthAuditInboxPO(), "expectedVersion", 0L)).getSql()
                .toLowerCase(java.util.Locale.ROOT).replaceAll("\\s+", " ");
        assertThat(read).contains("tenant_id = ?", "event_id = ?").doesNotContain("for update", "for share");
        assertThat(update).contains("tenant_id = ?", "id = ?", "event_id = ?", "version = ?", "deleted_at is null");
    }

    @Test
    void observedUpdatePassesTheStarterTenantAndLocalRouteGuards() throws Exception {
        var configuration = new com.baomidou.mybatisplus.core.MybatisConfiguration();
        String resource = "mapper/audit/OAuthAuditInboxMapper.xml";
        try (var input = getClass().getClassLoader().getResourceAsStream(resource)) {
            new XMLMapperBuilder(input, configuration, resource, configuration.getSqlFragments()).parse();
        }
        configuration.setEnvironment(new org.apache.ibatis.mapping.Environment("test",
                new org.mybatis.spring.transaction.SpringManagedTransactionFactory(), mock(javax.sql.DataSource.class)));
        var properties = new EgonColaMybatisPlusProperties();
        var guard = new top.egon.cola.component.common.mybatis.interceptor.EgonColaTenantIdGuardInnerInterceptor(
                () -> "service:tianquan-shoubing", properties);
        new org.springframework.context.annotation.CommonAnnotationBeanPostProcessor()
                .postProcessBeforeInitialization(guard, "sqlGuard");
        var routeGuard = new top.egon.cola.component.common.mybatis.interceptor.EgonColaLocalWriteGuardInnerInterceptor(
                query -> new top.egon.cola.component.common.mybatis.routing.EgonColaRouteResult(
                        java.util.List.of(new top.egon.cola.component.common.mybatis.routing.EgonColaPhysicalTargetBO(
                                "primary", "tianquan_oauth", "oauth_audit_inbox")), "a".repeat(64)),
                guard, mock(top.egon.cola.component.common.mybatis.routing.EgonColaTwoLevelRouteStrategy.class), Map.of());
        var row = new OAuthAuditInboxPO();
        row.setId(11L); row.setTenantId(1001L); row.setEventId("event-1"); row.setVersion(1L);
        row.setUpdateUserId("service:tianquan-shoubing"); row.setUpdateTime(NOW);
        Map<String, Object> parameters = Map.of("tenantId", 1001L, "po", row, "expectedVersion", 0L);
        var statement = configuration.getMappedStatement(OAuthAuditInboxMapper.class.getName() + ".updateExpectedVersion");
        var handler = configuration.newStatementHandler(mock(org.apache.ibatis.executor.Executor.class), statement,
                parameters, org.apache.ibatis.session.RowBounds.DEFAULT, null, statement.getBoundSql(parameters));
        MDC.put("tenantId", "1001"); MDC.put("userId", "service:tianquan-shoubing");
        try {
            org.assertj.core.api.Assertions.assertThatCode(() -> {
                guard.beforePrepare(handler, null, null);
                routeGuard.beforePrepare(handler, null, null);
            }).doesNotThrowAnyException();
        } finally {
            MDC.remove("tenantId"); MDC.remove("userId");
        }
    }

    @Test
    void observedSnapshotsCompeteAtPrimaryWithoutRereadingReplica() throws Exception {
        var mapper = mock(OAuthAuditInboxMapper.class);
        var barrier = new CyclicBarrier(2);
        var winner = new AtomicBoolean();
        when(mapper.updateExpectedVersion(anyLong(), any(), anyLong())).thenAnswer(call -> {
            assertThat(call.<Long>getArgument(0)).isEqualTo(1001L);
            assertThat(call.<Long>getArgument(2)).isEqualTo(0L);
            barrier.await(5, TimeUnit.SECONDS);
            return winner.compareAndSet(false, true) ? 1 : 0;
        });
        var repository = new OAuthAuditInboxRepositoryImpl(mapper, new EgonColaMybatisPlusProperties(),
                Mappers.getMapper(OAuthAuditInboxConverter.class), () -> "service:tianquan-shoubing",
                Clock.fixed(NOW, ZoneOffset.UTC));
        var realm = TrustedRealmBO.builder().issuer(URI.create("https://auth.example/tenants/1001"))
                .realmKey("tenant:1001").realmType(RealmTypeEnum.TENANT).storagePartitionId(1001L)
                .businessTenantId(1001L).trustVersion(0L).build();
        var observed = OAuthAuditInboxBO.builder().id(11L).version(0L).eventId("event-1")
                .eventFingerprint("a".repeat(64)).schemaVersion(1).sourceClientPk(2L)
                .sourceIssuer("https://auth.example/tenants/1001").sourceResourceUri("https://api.example")
                .eventPayload(JsonNodeFactory.instance.objectNode()).occurredAt(NOW.minusSeconds(1))
                .receivedAt(NOW.minusSeconds(1)).state("PENDING").attemptCount(0).nextAttemptAt(NOW)
                .claimGeneration(0L).processingDeadline(NOW.plusSeconds(300)).retainUntil(NOW.plusSeconds(1000)).build();
        var claimed = observed.toBuilder().version(1L).state("PROCESSING").attemptCount(1).claimGeneration(1L)
                .claimOwner("worker").claimToken("token").leaseUntil(NOW.plusSeconds(30)).build();
        try (var workers = Executors.newFixedThreadPool(2)) {
            var first = workers.submit(() -> save(repository, realm, observed, claimed));
            var second = workers.submit(() -> save(repository, realm, observed, claimed));
            assertThat(java.util.List.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(true, false);
        }
        verify(mapper, never()).selectByKey(anyLong(), anyString());
        verify(mapper, never()).selectByKeyForUpdate(anyLong(), anyString());
    }

    private static boolean save(OAuthAuditInboxRepositoryImpl repository, TrustedRealmBO realm,
            OAuthAuditInboxBO observed, OAuthAuditInboxBO requested) {
        try {
            repository.saveObserved(realm, observed, requested);
            return true;
        } catch (OptimisticLockingFailureException conflict) {
            return false;
        }
    }
}
