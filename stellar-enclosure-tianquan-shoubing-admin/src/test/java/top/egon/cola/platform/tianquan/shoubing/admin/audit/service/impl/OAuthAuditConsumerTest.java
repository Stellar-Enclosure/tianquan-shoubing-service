package top.egon.cola.platform.tianquan.shoubing.admin.audit.service.impl;

import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthScheduledRealmCatalog;
import static org.mockito.Mockito.*;

class OAuthAuditConsumerTest {
    @Test void recoversOnlyRegisteredActiveRealmsFromTheDatabaseInbox() {
        var delivery = mock(OAuthAuditDeliveryService.class); var catalog = mock(OAuthScheduledRealmCatalog.class);
        var issuers = mock(TenantIssuerService.class);
        var active = TrustedRealmBO.builder().build();
        URI issuer = URI.create("https://idp.example/tenants/1");
        when(catalog.findAll()).thenReturn(List.of(
                OAuthRealmBO.builder().issuer(issuer).realmKey("tenant:1").status("ACTIVE").build(),
                OAuthRealmBO.builder().issuer(URI.create("https://idp.example/tenants/2")).status("SUSPENDED").build()));
        when(issuers.resolveExactIssuer(issuer)).thenReturn(active);
        new OAuthAuditConsumer(delivery, catalog, issuers).consume();
        verify(delivery).drain(active); verifyNoMoreInteractions(delivery);
    }

    @Test void failureInOneRealmDoesNotAcknowledgeOrSuppressOtherRealmRecovery() {
        var delivery = mock(OAuthAuditDeliveryService.class); var catalog = mock(OAuthScheduledRealmCatalog.class);
        var issuers = mock(TenantIssuerService.class);
        var second = TrustedRealmBO.builder().build();
        URI first = URI.create("https://idp.example/tenants/1"), next = URI.create("https://idp.example/tenants/2");
        when(catalog.findAll()).thenReturn(List.of(
                OAuthRealmBO.builder().issuer(first).realmKey("tenant:1").status("ACTIVE").build(),
                OAuthRealmBO.builder().issuer(next).realmKey("tenant:2").status("ACTIVE").build()));
        when(issuers.resolveExactIssuer(first)).thenThrow(new IllegalStateException("unavailable"));
        when(issuers.resolveExactIssuer(next)).thenReturn(second);
        new OAuthAuditConsumer(delivery, catalog, issuers).consume();
        verify(delivery).drain(second);
    }
}
