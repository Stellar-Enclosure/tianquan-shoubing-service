package top.egon.cola.platform.tianquan.shoubing.admin.oauth.support;

import java.net.URI;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.bo.OAuthGrantBO;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class OAuthTransactionFencesTest {
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/7"))
            .realmKey("tenant:7").realmType(RealmTypeEnum.TENANT).storagePartitionId(7L).businessTenantId(7L).trustVersion(1L).build();
    private final OAuthClientBO client = OAuthClientBO.builder().id(31L).clientId("client").version(4L)
            .status(OAuthClient.Status.ACTIVE).build();
    private final OAuthGrantBO grant = OAuthGrantBO.builder().id(40L).clientPk(31L).version(8L).build();
    private final OAuthRealmRepository realms = mock(OAuthRealmRepository.class);
    private final OAuthClientRepository clients = mock(OAuthClientRepository.class);

    @BeforeEach void begin() {
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        when(realms.fenceObservedVersion(realm)).thenReturn(true);
        when(realms.fenceActiveObservedVersion(realm)).thenReturn(true);
        when(clients.fenceObservedVersion(realm, client)).thenReturn(true);
        when(clients.fenceGrantObservedVersion(eq(realm), eq(client), anyLong(), eq(grant))).thenReturn(true);
    }

    @AfterEach void end() {
        TransactionSynchronizationManager.getSynchronizations().forEach(sync -> sync.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));
        TransactionSynchronizationManager.clearSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(false);
    }

    @Test void nestedCallsReuseFencesButRecheckGrantsOnThePrimary() {
        assertThat(OAuthTransactionFences.realm(realms, realm)).isTrue();
        assertThat(OAuthTransactionFences.realm(realms, realm)).isTrue();
        assertThat(OAuthTransactionFences.client(clients, realm, client)).isTrue();
        assertThat(OAuthTransactionFences.client(clients, realm, client)).isTrue();
        assertThat(OAuthTransactionFences.grant(clients, realm, client, grant)).isTrue();
        assertThat(OAuthTransactionFences.grant(clients, realm, client, grant)).isTrue();
        verify(realms, times(1)).fenceObservedVersion(realm);
        verify(clients, times(1)).fenceObservedVersion(realm, client);
        verify(clients).fenceGrantObservedVersion(realm, client, 5L, grant);
        verify(clients).fenceGrantObservedVersion(realm, client, 6L, grant);
        assertThat(grant.getVersion()).isEqualTo(8L);
    }

    @Test void activeRealmProofCanBeReusedForRevocationInTheSameTransaction() {
        assertThat(OAuthTransactionFences.activeRealm(realms, realm)).isTrue();
        assertThat(OAuthTransactionFences.realm(realms, realm)).isTrue();
        verify(realms).fenceActiveObservedVersion(realm);
        verify(realms, never()).fenceObservedVersion(realm);
    }

    @Test void savepointRollbackRestoresTheVersionAndRejectsUnprovenWrites() {
        assertThat(OAuthTransactionFences.client(clients, realm, client)).isTrue();
        var sync = TransactionSynchronizationManager.getSynchronizations().getFirst();
        Object point = new Object();
        sync.savepoint(point);
        assertThat(OAuthTransactionFences.grant(clients, realm, client, grant)).isTrue();
        OAuthTransactionFences.clientWritten(realm, client);
        assertThat(OAuthTransactionFences.isClientWritten(realm, client)).isTrue();
        var subject = top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSecurityStateBO.builder()
                .id(51L).version(0L).targetType(top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum.SUBJECT)
                .targetKey("alice").generation(2L).revision(7L).enabled(true).reasonCode("CREATED").build();
        OAuthTransactionFences.securityStateWritten(realm, subject);
        assertThat(OAuthTransactionFences.securityState(realm, subject.getTargetType(), "alice").getGeneration()).isEqualTo(2L);
        sync.savepointRollback(point);
        assertThat(OAuthTransactionFences.isClientWritten(realm, client)).isFalse();
        assertThat(OAuthTransactionFences.securityState(realm, subject.getTargetType(), "alice")).isNull();
        assertThat(OAuthTransactionFences.grant(clients, realm, client, grant)).isTrue();
        verify(clients, times(2)).fenceGrantObservedVersion(realm, client, 5L, grant);
        sync.suspend();
        assertThat(TransactionSynchronizationManager.hasResource(OAuthTransactionFences.class)).isFalse();
        sync.resume();
        assertThat(TransactionSynchronizationManager.hasResource(OAuthTransactionFences.class)).isTrue();
        sync.savepointRollback(new Object());
        assertThat(OAuthTransactionFences.isClientWritten(realm, client)).isFalse();
    }

    @Test void aFailedGrantFenceDoesNotAdvanceOrAuthorize() {
        when(clients.fenceGrantObservedVersion(realm, client, 5L, grant)).thenReturn(false, true);
        assertThat(OAuthTransactionFences.client(clients, realm, client)).isTrue();
        assertThat(OAuthTransactionFences.grant(clients, realm, client, grant)).isFalse();
        assertThat(OAuthTransactionFences.grant(clients, realm, client, grant)).isTrue();
        verify(clients, times(2)).fenceGrantObservedVersion(realm, client, 5L, grant);
    }
}
