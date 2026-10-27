package top.egon.cola.platform.tianquan.shoubing.admin.oauth;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.stream.LongStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.*;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.*;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthDeviceSessionService;
import top.egon.cola.platform.tianquan.shoubing.core.audit.IdentitySecurityEventPort;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DeviceSessionServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-27T00:00:00Z");
    private static final String DIGEST = "a".repeat(64);
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/7"))
            .realmType(RealmTypeEnum.TENANT).realmKey("tenant:7").storagePartitionId(7L).businessTenantId(7L).trustVersion(0L).build();
    private final OAuthRealmRepository realms = mock(OAuthRealmRepository.class);
    private final OAuthDeviceSessionRepository sessions = mock(OAuthDeviceSessionRepository.class);
    private final OAuthAuthorizationRepository grants = mock(OAuthAuthorizationRepository.class);
    private final OAuthClientRepository clients = mock(OAuthClientRepository.class);
    private final IdentitySecurityEventPort events = mock(IdentitySecurityEventPort.class);
    private final OAuthDeviceSessionService service = new OAuthDeviceSessionService(realms, sessions, grants, clients, events, Clock.fixed(NOW, ZoneOffset.UTC));
    private final OAuthClientBO client = OAuthClientBO.builder().id(11L).clientId("browser").clientName("Browser").browserBound(true).build();
    private final MockHttpServletRequest request = new MockHttpServletRequest();

    @BeforeEach void setUp() {
        when(realms.findByRealmKeyForUpdate(realm)).thenReturn(Optional.of(OAuthRealmBO.builder().build()));
        when(sessions.save(eq(realm), any(), anyLong())).thenAnswer(i -> {
            OAuthDeviceSessionBO value = i.getArgument(1);
            return value.toBuilder().id(value.getId() == null ? 6L : value.getId()).build();
        });
        request.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/1.0");
        request.setRemoteAddr("192.0.2.1");
    }

    @Test void sixthSessionEvictsOnlyTheOldestClientSessionAndItsGrants() {
        var live = LongStream.rangeClosed(1, 5).mapToObj(this::session).toList();
        when(sessions.findLiveBySubject(realm, "alice", NOW)).thenReturn(live);
        var oldGrant = grant(51L, 1L);
        when(grants.findByDeviceSession(realm, 1L, 0L, 500)).thenReturn(List.of(oldGrant));
        when(grants.findByIdForUpdate(realm, 51L)).thenReturn(Optional.of(oldGrant));
        assertEquals(6L, service.register(realm, client, grant(null, null), request));
        verify(sessions).save(eq(realm), argThat(value -> value.getId() != null && value.getId() == 1L
                && "REVOKED".equals(value.getStatus()) && "DEVICE_SESSION_LIMIT".equals(value.getReasonCode())), eq(0L));
        verify(grants).save(eq(realm), argThat(value -> "REVOKED".equals(value.getStatus())), eq(0L));
        verify(grants, never()).findByAuthentication(any(), anyString(), anyLong(), anyInt());
        verify(grants, never()).findByPrincipalName(any(), anyString(), anyString(), anyLong(), anyInt());
    }

    @Test void theSameClientAndSsoReuseOneSlotAcrossResourcesAndExtendExpiry() {
        var current = session(1L).setExpiresAt(NOW.plusSeconds(60));
        when(sessions.findByAuthentication(realm, DIGEST, 11L)).thenReturn(Optional.of(current));
        when(sessions.findLiveBySubject(realm, "alice", NOW)).thenReturn(LongStream.rangeClosed(1, 5).mapToObj(this::session).toList());
        assertEquals(1L, service.register(realm, client, grant(null, null), request));
        verify(sessions).save(eq(realm), argThat(value -> value.getId() == 1L && "ACTIVE".equals(value.getStatus())
                && value.getExpiresAt().equals(NOW.plusSeconds(3600))), eq(0L));
        verifyNoInteractions(grants, events);
    }

    @Test void kickingTheBrowserDoesNotRevokeTheAppSharingItsSsoAuthentication() {
        when(sessions.findById(realm, 1L)).thenReturn(Optional.of(session(1L)));
        var browser = grant(51L, 1L);
        var app = grant(52L, 2L);
        when(grants.findByDeviceSession(realm, 1L, 0L, 500)).thenReturn(List.of(browser));
        when(grants.findByIdForUpdate(realm, 51L)).thenReturn(Optional.of(browser));
        service.revoke(realm, "alice", 1L);
        assertEquals("REVOKED", browser.getStatus());
        assertEquals("ACTIVE", app.getStatus());
        verify(grants, never()).findByIdForUpdate(realm, 52L);
        verify(events).append(argThat(event -> "DEVICE_SESSION_KICKED".equals(event.reason())));
    }

    @Test void anotherAccountCannotKickADeviceEvenWithAKnownSessionId() {
        when(sessions.findById(realm, 1L)).thenReturn(Optional.of(session(1L)));
        assertThrows(AccessDeniedException.class, () -> service.revoke(realm, "bob", 1L));
        verify(sessions, never()).save(any(), any(), anyLong());
        verifyNoInteractions(grants, events);
    }

    @Test void revokedSessionCannotBeRecreatedWithTheSameSsoProof() {
        when(sessions.findByAuthentication(realm, DIGEST, 11L)).thenReturn(Optional.of(session(1L).setStatus("REVOKED")));
        var rejected = assertThrows(OAuth2AuthenticationException.class, () -> service.register(realm, client, grant(null, null), request));
        assertEquals("login_required", rejected.getError().getErrorCode());
        verify(sessions, never()).save(any(), any(), anyLong());
    }

    @Test void repeatedKickIsIdempotentAndAuditFailuresPropagateToTheTransaction() {
        when(sessions.findById(realm, 1L)).thenReturn(Optional.of(session(1L).setStatus("REVOKED")));
        service.revoke(realm, "alice", 1L);
        verifyNoInteractions(grants, events);
        when(sessions.findById(realm, 1L)).thenReturn(Optional.of(session(1L)));
        doThrow(new IllegalStateException("audit unavailable")).when(events).append(any());
        assertThrows(IllegalStateException.class, () -> service.revoke(realm, "alice", 1L));
    }

    @Test void listingReturnsOnlyLoginMetadataForTheRequestedOwner() {
        when(sessions.findLiveBySubject(realm, "alice", NOW)).thenReturn(List.of(session(1L).setUserAgent("Windows Chrome")));
        when(clients.findById(realm, 11L)).thenReturn(Optional.of(client));
        var view = service.list(realm, "alice").getFirst();
        assertEquals("1", view.sessionId());
        assertEquals("BROWSER", view.channel());
        assertEquals("Windows", view.platform());
        assertEquals("Browser", view.clientName());
    }

    private OAuthDeviceSessionBO session(long id) {
        return OAuthDeviceSessionBO.builder().id(id).subject("alice").clientPk(11L).authenticationJtiDigest(DIGEST)
                .status("ACTIVE").authenticatedAt(NOW.minusSeconds(100 - id)).expiresAt(NOW.plusSeconds(3600)).build();
    }

    private OAuthAuthorizationBO grant(Long id, Long sessionId) {
        return OAuthAuthorizationBO.builder().id(id).clientPk(11L).principalName("alice").principalType("USER")
                .authenticationJtiDigest(DIGEST).deviceSessionId(sessionId).status("ACTIVE").absoluteExpiresAt(NOW.plusSeconds(3600)).build();
    }
}
