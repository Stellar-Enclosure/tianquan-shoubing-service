package top.egon.cola.platform.tianquan.shoubing.admin.audit.service.impl;

import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthManagementRealmResolver;
import static org.mockito.Mockito.*;

class OAuthAuditConsumerTest {
    @Test void recoversOnlyRegisteredActiveRealmsFromTheDatabaseInbox() {
        var delivery = mock(OAuthAuditDeliveryService.class); var realms = mock(OAuthRealmRepository.class);
        var management = mock(OAuthManagementRealmResolver.class); var issuers = mock(TenantIssuerService.class);
        var platform = TrustedRealmBO.builder().build(); var active = TrustedRealmBO.builder().build();
        URI issuer = URI.create("https://idp.example/tenants/1");
        when(management.platformRealm()).thenReturn(platform);
        when(realms.findAllByStoragePartition(platform)).thenReturn(List.of(
                OAuthRealmBO.builder().issuer(issuer).realmKey("tenant:1").status("ACTIVE").build(),
                OAuthRealmBO.builder().issuer(URI.create("https://idp.example/tenants/2")).status("SUSPENDED").build()));
        when(issuers.resolveExactIssuer(issuer)).thenReturn(active);
        new OAuthAuditConsumer(delivery, realms, management, issuers).consume();
        verify(delivery).drain(active); verifyNoMoreInteractions(delivery);
    }

    @Test void failureInOneRealmDoesNotAcknowledgeOrSuppressOtherRealmRecovery() {
        var delivery = mock(OAuthAuditDeliveryService.class); var realms = mock(OAuthRealmRepository.class);
        var management = mock(OAuthManagementRealmResolver.class); var issuers = mock(TenantIssuerService.class);
        var platform = TrustedRealmBO.builder().build(); var second = TrustedRealmBO.builder().build();
        URI first = URI.create("https://idp.example/tenants/1"), next = URI.create("https://idp.example/tenants/2");
        when(management.platformRealm()).thenReturn(platform);
        when(realms.findAllByStoragePartition(platform)).thenReturn(List.of(
                OAuthRealmBO.builder().issuer(first).realmKey("tenant:1").status("ACTIVE").build(),
                OAuthRealmBO.builder().issuer(next).realmKey("tenant:2").status("ACTIVE").build()));
        when(issuers.resolveExactIssuer(first)).thenThrow(new IllegalStateException("unavailable"));
        when(issuers.resolveExactIssuer(next)).thenReturn(second);
        new OAuthAuditConsumer(delivery, realms, management, issuers).consume();
        verify(delivery).drain(second);
    }
}
