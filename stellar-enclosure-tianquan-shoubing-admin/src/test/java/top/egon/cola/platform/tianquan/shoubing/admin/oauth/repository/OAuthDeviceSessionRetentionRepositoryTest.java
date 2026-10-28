package top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;
import top.egon.cola.component.common.mybatis.autoconfigure.EgonColaMybatisPlusProperties;
import top.egon.cola.component.common.mybatis.business.EgonColaUserIdProvider;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.OAuthDeviceSessionMapper;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter.OAuthDeviceSessionConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.po.OAuthDeviceSessionPO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.impl.OAuthDeviceSessionRepositoryImpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class OAuthDeviceSessionRetentionRepositoryTest {
    @Test void countsOnlyCandidatesWhosePrimaryVersionStillMatches() {
        var mapper = mock(OAuthDeviceSessionMapper.class);
        var user = mock(EgonColaUserIdProvider.class);
        Instant now = Instant.parse("2026-10-28T00:00:00Z");
        Instant cutoff = now.minusSeconds(86400);
        var first = new OAuthDeviceSessionPO(); first.setId(10L); first.setVersion(3L);
        var second = new OAuthDeviceSessionPO(); second.setId(11L); second.setVersion(4L);
        when(user.currentUserId()).thenReturn("worker");
        when(mapper.selectRetainedCandidates(1001L, cutoff, 500)).thenReturn(List.of(first, second));
        when(mapper.deleteVersionedById(1001L, 10L, 3L, cutoff, now, "worker")).thenReturn(1);
        when(mapper.deleteVersionedById(1001L, 11L, 4L, cutoff, now, "worker")).thenReturn(0);
        var repository = new OAuthDeviceSessionRepositoryImpl(mapper, new EgonColaMybatisPlusProperties(),
                mock(OAuthDeviceSessionConverter.class), user, Clock.fixed(now, ZoneOffset.UTC));
        var realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/1001"))
                .realmKey("tenant:1001").realmType(RealmTypeEnum.TENANT).storagePartitionId(1001L)
                .businessTenantId(1001L).trustVersion(0L).build();

        assertThat(repository.deleteRetained(realm, now, 500)).isEqualTo(1);
        verify(mapper).deleteVersionedById(1001L, 10L, 3L, cutoff, now, "worker");
        verify(mapper).deleteVersionedById(1001L, 11L, 4L, cutoff, now, "worker");
    }
}
