package top.egon.cola.platform.tianquan.shoubing.admin.token.repository.impl;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.component.common.mybatis.business.EgonColaUserIdProvider;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.repo.IdentityDirectoryContext;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.dao.SubjectRevocationTaskMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSecurityStateBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.SubjectRevocationTaskBO;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class SubjectRevocationTaskRepositoryTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");
    private final SubjectRevocationTaskMapper mapper = mock(SubjectRevocationTaskMapper.class);
    private final EgonColaUserIdProvider actor = () -> "system:subject-worker";
    private final SubjectRevocationTaskRepository repository = new SubjectRevocationTaskRepository(mapper,
            new IdentityDirectoryContext(9000L, "tenantId"), actor, Clock.fixed(NOW, ZoneOffset.UTC));
    private final TrustedRealmBO platform = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/platform"))
            .realmKey("platform").realmType(RealmTypeEnum.PLATFORM).storagePartitionId(9000L).trustVersion(0L).build();

    @BeforeAll static void ids() { SnowflakeIdGenerator.initialize(0L, Duration.ofMillis(5)); }

    @Test void completeReplicaPagesCreateOneDurableIntentPerTenant() {
        when(mapper.selectHistoryPage(9000L, "alice", 0L, 200)).thenReturn(List.of(2L, 10L));
        when(mapper.selectHistoryPage(9000L, "alice", 10L, 200)).thenReturn(List.of());
        when(mapper.fenceHistoryPage(anyLong(), anyLong(), anyLong(), anyString(), anyLong(), anyLong(), anyList(), anyInt(), any(), anyString())).thenReturn(1);
        when(mapper.insertTask(any(), any(), anyString())).thenReturn(1);
        var realm = OAuthSecurityStateBO.builder().id(31L).version(4L).build();
        repository.enqueueForSubject(platform, realm, "alice", 8L, false, "USER_DISABLED");
        var captured = org.mockito.ArgumentCaptor.forClass(SubjectRevocationTaskBO.class);
        verify(mapper, times(2)).insertTask(captured.capture(), any(), anyString());
        assertThat(captured.getAllValues()).extracting(SubjectRevocationTaskBO::getTargetTenantId).containsExactly("2", "10");
        assertThat(captured.getAllValues()).allSatisfy(task -> {
            assertThat(task.getTenantId()).isEqualTo(9000L);
            assertThat(task.getSourceRevision()).isEqualTo(8L);
            assertThat(task.getSubjectEnabled()).isFalse();
        });
        assertThat(realm.getVersion()).isEqualTo(6L);
    }

    @Test void replicaGapRollsBackBeforeCreatingAnyIntent() {
        when(mapper.selectHistoryPage(9000L, "alice", 0L, 200)).thenReturn(List.of(10L));
        when(mapper.fenceHistoryPage(anyLong(), anyLong(), anyLong(), anyString(), anyLong(), anyLong(), anyList(), anyInt(), any(), anyString())).thenReturn(0);
        var manager = mock(org.springframework.transaction.PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new org.springframework.transaction.support.SimpleTransactionStatus());
        var tx = new org.springframework.transaction.support.TransactionTemplate(manager);
        var realm = OAuthSecurityStateBO.builder().id(31L).version(4L).build();
        assertThatThrownBy(() -> tx.executeWithoutResult(status -> repository.enqueueForSubject(platform, realm,
                "alice", 8L, false, "USER_DISABLED"))).isInstanceOf(org.springframework.dao.OptimisticLockingFailureException.class);
        verify(manager).rollback(any());
        verify(mapper, never()).insertTask(any(), any(), anyString());
    }

    @Test void concurrentClaimsHaveOneOwnerAndStaleCompletionCannotWin() throws Exception {
        var claimed = new AtomicBoolean();
        when(mapper.claim(anyLong(), any(), anyString(), any(), any(), anyString()))
                .thenAnswer(call -> claimed.compareAndSet(false, true) ? 1 : 0);
        var first = task(); var second = task(); var start = new CountDownLatch(1);
        try (var threads = Executors.newFixedThreadPool(2)) {
            var a = threads.submit(() -> { start.await(); return repository.claim(first, "a", Duration.ofSeconds(30)); });
            var b = threads.submit(() -> { start.await(); return repository.claim(second, "b", Duration.ofSeconds(30)); });
            start.countDown();
            assertThat(List.of(a.get(5, TimeUnit.SECONDS), b.get(5, TimeUnit.SECONDS)).stream().filter(Boolean::booleanValue)).hasSize(1);
        }
        assertThat(repository.complete(first, "old-owner")).isFalse();
    }

    private static SubjectRevocationTaskBO task() {
        var task = new SubjectRevocationTaskBO(); task.setId(55L); task.setTenantId(9000L); task.setVersion(2L); return task;
    }
}
