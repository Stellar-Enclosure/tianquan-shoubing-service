package top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl;

import java.net.URI;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthManagementRealmResolver;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.SubjectRevocationTaskBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.impl.SubjectRevocationTaskRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.TokenRevocationService;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class SubjectRevocationTaskWorkerTest {
    private final SubjectRevocationTaskRepository tasks = mock(SubjectRevocationTaskRepository.class);
    private final OAuthManagementRealmResolver realms = mock(OAuthManagementRealmResolver.class);
    private final TokenRevocationService revocations = mock(TokenRevocationService.class);
    private final SubjectRevocationTaskWorker worker = new SubjectRevocationTaskWorker(tasks, realms, revocations);
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/7"))
            .realmKey("tenant:7").realmType(RealmTypeEnum.TENANT).storagePartitionId(7L).businessTenantId(7L).trustVersion(0L).build();

    @Test void targetFailureKeepsTheSourceTaskForRetry() {
        var task = task(); when(tasks.due(100)).thenReturn(List.of(task));
        when(tasks.claim(eq(task), anyString(), any())).thenReturn(true);
        when(realms.resolveTenantForRevocation("7")).thenReturn(realm);
        doThrow(new org.springframework.dao.TransientDataAccessResourceException("replica delayed"))
                .when(revocations).applySubjectTask(realm, task);
        worker.dispatch();
        verify(tasks).retry(eq(task), anyString(), any());
        verify(tasks, never()).complete(any(), anyString());
    }

    @Test void concurrentWorkersOnlyDeliverTheClaimedTask() throws Exception {
        var task = task(); var winner = new AtomicBoolean();
        when(tasks.due(100)).thenReturn(List.of(task));
        when(tasks.claim(eq(task), anyString(), any())).thenAnswer(call -> winner.compareAndSet(false, true));
        when(realms.resolveTenantForRevocation("7")).thenReturn(realm);
        when(tasks.complete(eq(task), anyString())).thenReturn(true);
        var start = new CountDownLatch(1);
        try (var threads = Executors.newFixedThreadPool(2)) {
            var a = threads.submit(() -> { start.await(); worker.dispatch(); return true; });
            var b = threads.submit(() -> { start.await(); worker.dispatch(); return true; });
            start.countDown(); assertThat(a.get(5, TimeUnit.SECONDS)).isTrue(); assertThat(b.get(5, TimeUnit.SECONDS)).isTrue();
        }
        verify(revocations, times(1)).applySubjectTask(realm, task);
        verify(tasks, times(1)).complete(eq(task), anyString());
    }

    @Test void lostSourceAcknowledgementReplaysTheSameTargetRevision() {
        var task = task(); task.setIdentitySub("alice"); task.setSourceRevision(42L);
        when(tasks.due(100)).thenReturn(List.of(task));
        when(tasks.claim(eq(task), anyString(), any())).thenReturn(true);
        when(realms.resolveTenantForRevocation("7")).thenReturn(realm);
        when(tasks.complete(eq(task), anyString())).thenReturn(false, true);
        worker.dispatch();
        worker.dispatch();
        var captured = org.mockito.ArgumentCaptor.forClass(SubjectRevocationTaskBO.class);
        verify(revocations, times(2)).applySubjectTask(eq(realm), captured.capture());
        assertThat(captured.getAllValues()).extracting(SubjectRevocationTaskBO::getSourceRevision).containsExactly(42L, 42L);
        verify(tasks, never()).retry(any(), anyString(), any());
    }

    private static SubjectRevocationTaskBO task() {
        var task = new SubjectRevocationTaskBO(); task.setId(10L); task.setVersion(0L); task.setTargetTenantId("7"); return task;
    }
}
