package top.egon.cola.platform.tianquan.shoubing.admin.resource.service.impl;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.LazyConnectionDataSourceProxy;
import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import top.egon.cola.component.common.mybatis.routing.EgonColaTransactionWriteTarget;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.bo.OAuthResourceBO;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthResourceFenceRepository;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class ResourceGrantTransactionCoordinatorTest {
    private final TrustedRealmBO platform = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/platform"))
            .realmKey("platform").realmType(RealmTypeEnum.PLATFORM).storagePartitionId(1L).trustVersion(0L).build();
    private final OAuthResourceBO resource = OAuthResourceBO.builder().id(11L).version(3L).resourceServerId("orders").build();
    private final OAuthResourceFenceRepository fences = mock(OAuthResourceFenceRepository.class);
    private final Object factory = new Object();
    private JdbcTemplate platformJdbc;
    private JdbcTemplate tenantJdbc;
    private JdbcTemplate routedJdbc;
    private LazyConnectionDataSourceProxy logical;
    private DataSourceTransactionManager manager;
    private ResourceGrantTransactionCoordinator coordinator;

    @BeforeEach void setup() {
        var primary = dataSource(); var target = dataSource();
        platformJdbc = new JdbcTemplate(primary); tenantJdbc = new JdbcTemplate(target);
        platformJdbc.execute("CREATE TABLE resource_fence (id BIGINT PRIMARY KEY, version BIGINT)");
        platformJdbc.update("INSERT INTO resource_fence VALUES (11,0)");
        tenantJdbc.execute("CREATE TABLE grants (id BIGINT PRIMARY KEY)");
        tenantJdbc.execute("CREATE TABLE outbox (id BIGINT PRIMARY KEY)");
        var router = new AbstractRoutingDataSource() {
            @Override protected Object determineCurrentLookupKey() { return "7".equals(MDC.get("tenantId")) ? "tenant" : "platform"; }
        };
        router.setTargetDataSources(Map.of("platform", primary, "tenant", target));
        router.setDefaultTargetDataSource(primary); router.afterPropertiesSet();
        logical = new LazyConnectionDataSourceProxy(router);
        manager = new DataSourceTransactionManager(logical); routedJdbc = new JdbcTemplate(logical);
        coordinator = new ResourceGrantTransactionCoordinator(manager, fences);
        when(fences.fenceCurrent(eq(platform), any())).thenAnswer(invocation -> {
            OAuthResourceBO candidate = invocation.getArgument(1);
            String before = MDC.get("tenantId"); MDC.put("tenantId", "1");
            try {
                var state = EgonColaTransactionWriteTarget.capture(logical);
                state.pin("platform", factory);
                return routedJdbc.update("UPDATE resource_fence SET version=version+1 WHERE id=?", candidate.getId()) == 1;
            } finally { if (before == null) MDC.remove("tenantId"); else MDC.put("tenantId", before); }
        });
    }

    @Test void batchFencesResourcesInStableOrder() {
        var second = OAuthResourceBO.builder().id(12L).version(1L).resourceServerId("billing").build();
        platformJdbc.update("INSERT INTO resource_fence VALUES (12,0)");
        coordinator.execute(platform, List.of(second, resource), () -> null);
        var order = inOrder(fences);
        order.verify(fences).fenceCurrent(platform, resource);
        order.verify(fences).fenceCurrent(platform, second);
    }

    @Test void rejectsAmbientTransactionBeforeCommittingAnIndependentShard() {
        new TransactionTemplate(manager).execute(status -> {
            assertThatThrownBy(() -> coordinator.execute(platform, List.of(resource), () -> "unexpected"))
                    .hasMessage("OAUTH_RESOURCE_GRANT_AMBIENT_TRANSACTION_UNSUPPORTED");
            return null;
        });
        verify(fences, never()).fenceCurrent(any(), any());
        assertThat(platformJdbc.queryForObject("SELECT version FROM resource_fence WHERE id=11", Long.class)).isZero();
    }

    @Test void targetGrantAndOutboxCommitTogetherInASeparateWriteGroup() {
        String value = coordinator.execute(platform, List.of(resource), () -> {
            MDC.put("tenantId", "7");
            try {
                var state = EgonColaTransactionWriteTarget.capture(logical);
                assertThat(state.group()).isNull(); state.pin("tenant", factory);
                routedJdbc.update("INSERT INTO grants VALUES (1)"); routedJdbc.update("INSERT INTO outbox VALUES (1)");
                return "ok";
            } finally { MDC.remove("tenantId"); }
        });
        assertThat(value).isEqualTo("ok");
        assertThat(platformJdbc.queryForObject("SELECT version FROM resource_fence WHERE id=11", Long.class)).isEqualTo(1L);
        assertThat(tenantJdbc.queryForObject("SELECT count(*) FROM grants", Integer.class)).isEqualTo(1);
        assertThat(tenantJdbc.queryForObject("SELECT count(*) FROM outbox", Integer.class)).isEqualTo(1);
    }

    @Test void targetFailureRollsBackGrantOutboxAndPlatformFence() {
        assertThatThrownBy(() -> coordinator.execute(platform, List.of(resource), () -> {
            MDC.put("tenantId", "7");
            try {
                EgonColaTransactionWriteTarget.capture(logical).pin("tenant", factory);
                routedJdbc.update("INSERT INTO grants VALUES (1)"); routedJdbc.update("INSERT INTO outbox VALUES (1)");
                throw new IllegalStateException("rollback");
            } finally { MDC.remove("tenantId"); }
        })).hasMessage("rollback");
        assertThat(platformJdbc.queryForObject("SELECT version FROM resource_fence WHERE id=11", Long.class)).isZero();
        assertThat(tenantJdbc.queryForObject("SELECT count(*) FROM grants", Integer.class)).isZero();
        assertThat(tenantJdbc.queryForObject("SELECT count(*) FROM outbox", Integer.class)).isZero();
    }

    @Test void platformFenceRemainsHeldUntilTheOwningShardCommits() throws Exception {
        var targetStarted = new CountDownLatch(1); var releaseTarget = new CountDownLatch(1); var competitorStarted = new CountDownLatch(1);
        try (var workers = Executors.newFixedThreadPool(2)) {
            var grant = workers.submit(() -> coordinator.execute(platform, List.of(resource), () -> {
                MDC.put("tenantId", "7");
                try {
                    EgonColaTransactionWriteTarget.capture(logical).pin("tenant", factory);
                    routedJdbc.update("INSERT INTO grants VALUES (1)"); targetStarted.countDown();
                    if (!releaseTarget.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("timeout");
                    routedJdbc.update("INSERT INTO outbox VALUES (1)"); return "ok";
                } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new IllegalStateException(interrupted); }
                finally { MDC.remove("tenantId"); }
            }));
            assertThat(targetStarted.await(5, TimeUnit.SECONDS)).isTrue();
            var competitor = workers.submit(() -> {
                competitorStarted.countDown();
                return new TransactionTemplate(new DataSourceTransactionManager(platformJdbc.getDataSource()))
                        .execute(status -> platformJdbc.update("UPDATE resource_fence SET version=version+1 WHERE id=11"));
            });
            assertThat(competitorStarted.await(5, TimeUnit.SECONDS)).isTrue();
            try { assertThatThrownBy(() -> competitor.get(250, TimeUnit.MILLISECONDS)).isInstanceOf(TimeoutException.class); }
            finally { releaseTarget.countDown(); }
            assertThat(grant.get(5, TimeUnit.SECONDS)).isEqualTo("ok");
            assertThat(competitor.get(5, TimeUnit.SECONDS)).isEqualTo(1);
        }
    }

    private static JdbcDataSource dataSource() {
        var source = new JdbcDataSource(); source.setURL("jdbc:h2:mem:" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1;LOCK_TIMEOUT=5000"); return source;
    }
}
