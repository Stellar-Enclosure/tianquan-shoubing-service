package top.egon.cola.platform.tianquan.shoubing.admin.identity.repo;

import java.time.Clock;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties;
import top.egon.cola.component.common.mybatis.business.EgonColaUserIdProvider;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.dao.IdentityCredentialDAO;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.dao.IdentityUserDAO;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.domain.converter.IdentityCredentialConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.domain.converter.IdentityUserConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.domain.po.IdentityCredentialPO;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.domain.po.IdentityUserPO;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.repository.IdentityCredentialRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.repository.IdentityUserRepository;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityUser;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityUserStatus;
import top.egon.cola.platform.tianquan.shoubing.core.identity.PasswordCredential;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class IdentityDirectoryReplicaWriteTest {
    private final IdentityUserDAO users = mock(IdentityUserDAO.class);
    private final IdentityCredentialDAO credentials = mock(IdentityCredentialDAO.class);
    private final IdentityDirectoryContext context = new IdentityDirectoryContext(9000L, "tenantId");
    private final EgonColaUserIdProvider actor = mock(EgonColaUserIdProvider.class);
    private final EgonColaMybatisPlusProperties properties = new EgonColaMybatisPlusProperties();
    private final IdentityUserRepository userRepository = new IdentityUserRepository(users, properties,
            Mappers.getMapper(IdentityUserConverter.class), context, actor, Clock.systemUTC());
    private final IdentityCredentialRepository credentialRepository = new IdentityCredentialRepository(credentials, properties,
            Mappers.getMapper(IdentityCredentialConverter.class), context, actor, Clock.systemUTC());

    @Test void missingReplicaCandidatesRetryWithoutAWriteOrLockingRead() {
        var user = new IdentityUser("alice", "alice", "alice", "Alice", IdentityUserStatus.ACTIVE, 0, null, null, 1L);
        var credential = new PasswordCredential("alice", "test-hash", Instant.EPOCH, false, PasswordCredential.Status.ACTIVE, 1L);
        assertThatThrownBy(() -> userRepository.save(user, 0L)).isInstanceOf(org.springframework.dao.TransientDataAccessResourceException.class);
        assertThatThrownBy(() -> credentialRepository.save(credential, 0L)).isInstanceOf(org.springframework.dao.TransientDataAccessResourceException.class);
        verify(users, never()).selectForUpdate(anyLong(), anyString());
        verify(credentials, never()).selectForUpdate(anyLong(), anyString());
        verify(users, never()).updateExpectedVersion(anyLong(), any(), anyLong());
        verify(credentials, never()).updateExpectedVersion(anyLong(), any(), anyLong());
    }

    @Test void stalePrimaryVersionsRejectBothWrites() {
        var userRow = new IdentityUserPO(); userRow.setId(11L); userRow.setVersion(0L);
        var credentialRow = new IdentityCredentialPO(); credentialRow.setId(12L); credentialRow.setVersion(0L);
        when(users.selectByExternalKey(9000L, "alice")).thenReturn(userRow);
        when(credentials.selectByExternalKey(9000L, "alice")).thenReturn(credentialRow);
        var user = new IdentityUser("alice", "alice", "alice", "Alice", IdentityUserStatus.ACTIVE, 0, null, null, 1L);
        var credential = new PasswordCredential("alice", "test-hash", Instant.EPOCH, false, PasswordCredential.Status.ACTIVE, 1L);
        assertThatThrownBy(() -> userRepository.save(user, 0L)).isInstanceOf(org.springframework.dao.OptimisticLockingFailureException.class);
        assertThatThrownBy(() -> credentialRepository.save(credential, 0L)).isInstanceOf(org.springframework.dao.OptimisticLockingFailureException.class);
        verify(users).updateExpectedVersion(eq(9000L), any(), eq(0L));
        verify(credentials).updateExpectedVersion(eq(9000L), any(), eq(0L));
        verify(users, never()).selectForUpdate(anyLong(), anyString());
        verify(credentials, never()).selectForUpdate(anyLong(), anyString());
    }

    @Test void identityPublicationSeesOnlyTheSuccessfulWriteInItsOwnTransaction() {
        var old = new IdentityUser("alice", "alice", "alice", "Alice", IdentityUserStatus.ACTIVE, 0, null, null, 0L);
        var oldRow = Mappers.getMapper(IdentityUserConverter.class).toSource(old);
        oldRow.setId(11L);
        when(users.selectByExternalKey(9000L, "alice")).thenReturn(oldRow);
        when(users.updateExpectedVersion(eq(9000L), any(), eq(0L))).thenReturn(1);
        when(actor.currentUserId()).thenReturn("service:test");
        var publisher = new top.egon.cola.platform.tianquan.shoubing.admin.support.outbox.service.IdentityOutboxPublisher(
                mock(top.egon.cola.platform.tianquan.shoubing.admin.audit.repository.OAuthAuditRepository.class),
                mock(top.egon.cola.component.outbox.api.TransactionalOutbox.class), userRepository,
                new com.fasterxml.jackson.databind.ObjectMapper(),
                mock(top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthManagementRealmResolver.class),
                Clock.systemUTC());
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        try {
            var disabled = old.withStatus(IdentityUserStatus.DISABLED);
            userRepository.save(disabled, 0L);
            assertThatCode(() -> publisher.publish(new top.egon.cola.platform.tianquan.shoubing.contract.IdentityUserState(
                    "alice", top.egon.cola.platform.tianquan.shoubing.contract.IdentityUserState.Status.DISABLED, Instant.EPOCH)))
                    .doesNotThrowAnyException();
            assertThat(userRepository.findByIdentitySub("alice")).contains(disabled);
            verify(users, times(1)).selectByExternalKey(9000L, "alice");
        } finally {
            TransactionSynchronizationManager.getSynchronizations().forEach(sync -> sync.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));
            TransactionSynchronizationManager.clearSynchronization();
            TransactionSynchronizationManager.setActualTransactionActive(false);
        }
        assertThat(userRepository.findByIdentitySub("alice")).contains(old);
        verify(users, times(2)).selectByExternalKey(9000L, "alice");
    }

    @Test void insertedIdentityIsVisibleWithoutReadingAnUncommittedRowFromTheReplica() {
        var created = new IdentityUser("alice", "alice", "alice", "Alice", IdentityUserStatus.ACTIVE, 0, null, null, 0L);
        var priorBinding = top.egon.cola.component.common.mybatis.model.EgonColaModelValidationUtils.current();
        var factory = priorBinding == null ? jakarta.validation.Validation.buildDefaultValidatorFactory() : null;
        var binding = priorBinding == null ? top.egon.cola.component.common.mybatis.model.EgonColaModelValidationUtils.initialize(
                new top.egon.cola.component.common.core.validation.ValidationUtils(factory.getValidator()), this) : priorBinding;
        when(users.insert(any(IdentityUserPO.class))).thenAnswer(invocation -> {
            ((IdentityUserPO) invocation.getArgument(0)).setId(11L);
            return 1;
        });
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        try {
            userRepository.save(created, 0L);
            assertThat(userRepository.findByIdentitySub("alice")).contains(created);
            verify(users, times(1)).selectByExternalKey(9000L, "alice");
        } finally {
            TransactionSynchronizationManager.getSynchronizations().forEach(sync -> sync.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));
            TransactionSynchronizationManager.clearSynchronization();
            TransactionSynchronizationManager.setActualTransactionActive(false);
            if (factory != null) { binding.close(); factory.close(); }
        }
        assertThat(userRepository.findByIdentitySub("alice")).isEmpty();
    }
}
