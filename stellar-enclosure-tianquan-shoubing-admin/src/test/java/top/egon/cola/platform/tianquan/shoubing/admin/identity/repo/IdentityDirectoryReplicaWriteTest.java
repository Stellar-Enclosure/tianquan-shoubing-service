package top.egon.cola.platform.tianquan.shoubing.admin.identity.repo;

import java.time.Clock;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;
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
}
