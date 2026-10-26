package top.egon.cola.platform.tianquan.shoubing.admin.oauth;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthenticationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthenticationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthorizationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthSsoLifecycleService;
import top.egon.cola.platform.tianquan.shoubing.core.audit.IdentitySecurityEventPort;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SsoRevocationScopeTest {
    private static final Instant NOW = Instant.parse("2026-10-25T00:00:00Z");
    private static final String CURRENT = "1".repeat(64);
    private static final String BINDING = "2".repeat(64);
    private final OAuthRealmRepository realms = mock(OAuthRealmRepository.class);
    private final OAuthAuthenticationRepository authentications = mock(OAuthAuthenticationRepository.class);
    private final OAuthAuthorizationRepository grants = mock(OAuthAuthorizationRepository.class);
    private final IdentitySecurityEventPort events = mock(IdentitySecurityEventPort.class);
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/101"))
            .realmType(RealmTypeEnum.TENANT).realmKey("tenant:101").storagePartitionId(101L).businessTenantId(101L).trustVersion(0L).build();
    private final OAuthSsoLifecycleService service = new OAuthSsoLifecycleService(realms, authentications, grants, events, Clock.fixed(NOW, ZoneOffset.UTC));
    private OAuthAuthenticationBO current;

    @BeforeEach void setUp() {
        current = OAuthAuthenticationBO.builder().jtiDigest(CURRENT).subject("alice").browserBindingDigest(BINDING)
                .status("ACTIVE").version(3L).build();
        when(realms.findByRealmKeyForUpdate(realm)).thenReturn(Optional.of(OAuthRealmBO.builder().build()));
        when(authentications.findByJtiDigestForUpdate(realm, CURRENT)).thenReturn(Optional.of(current));
    }

    @Test void oneSsoLogoutClosesItsTwoClientsAndLeavesAnotherAuthenticationUntouched() {
        var first = OAuthAuthorizationBO.builder().id(11L).clientPk(21L).principalName("alice").authenticationJtiDigest(CURRENT).status("ACTIVE").version(0L).build();
        var second = OAuthAuthorizationBO.builder().id(12L).clientPk(22L).principalName("alice").authenticationJtiDigest(CURRENT).status("ACTIVE").version(5L).build();
        when(grants.findByAuthentication(realm, CURRENT, 0L, 500)).thenReturn(List.of(first, second));
        when(grants.findByIdForUpdate(realm, 11L)).thenReturn(Optional.of(first));
        when(grants.findByIdForUpdate(realm, 12L)).thenReturn(Optional.of(second));

        service.logout(realm, CURRENT, BINDING, "alice");

        assertEquals("REVOKED", current.getStatus());
        assertEquals("REVOKED", first.getStatus()); assertEquals("REVOKED", second.getStatus());
        assertEquals(NOW, current.getRevokedAt());
        verify(authentications).save(realm, current, 3L);
        verify(grants).save(realm, first, 0L); verify(grants).save(realm, second, 5L);
        verify(grants, never()).findByPrincipalName(any(), anyString(), anyString(), anyLong(), anyInt());
        verify(authentications, never()).findActiveByBrowser(any(), anyString(), anyLong(), anyInt());
        verify(events).append(argThat(event -> "CURRENT_SSO_LOGOUT".equals(event.reason())));
    }

    @Test void anotherBrowserOrSubjectCannotRevokeTheAuthentication() {
        assertThrows(IllegalArgumentException.class, () -> service.logout(realm, CURRENT, "3".repeat(64), "alice"));
        assertThrows(IllegalArgumentException.class, () -> service.logout(realm, CURRENT, BINDING, "bob"));
        verify(authentications, never()).save(any(), any(), anyLong());
        verifyNoInteractions(grants, events);
    }

    @Test void repeatedCompletedLogoutIsIdempotent() {
        current.setStatus("REVOKED").setRevokedAt(NOW);
        service.logout(realm, CURRENT, BINDING, "alice");
        verify(authentications, never()).save(any(), any(), anyLong());
        verifyNoInteractions(grants, events);
    }

    @Test void auditFailureIsPropagatedToTheOwningTransaction() {
        when(grants.findByAuthentication(realm, CURRENT, 0L, 500)).thenReturn(List.of());
        doThrow(new IllegalStateException("audit unavailable")).when(events).append(any());
        assertThrows(IllegalStateException.class, () -> service.logout(realm, CURRENT, BINDING, "alice"));
    }
}
