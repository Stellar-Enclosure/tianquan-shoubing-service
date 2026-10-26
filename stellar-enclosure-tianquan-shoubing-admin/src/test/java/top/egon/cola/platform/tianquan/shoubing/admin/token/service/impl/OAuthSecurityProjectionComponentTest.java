package top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthorizationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthManagementRealmResolver;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSecurityStateBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthRevocationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository;
import top.egon.cola.platform.tianquan.shoubing.core.audit.OAuthSecurityChangedEvent;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class OAuthSecurityProjectionComponentTest {
    private static final Instant NOW = Instant.parse("2026-10-23T00:00:00Z");
    private static final TrustedRealmBO REALM = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/101"))
            .realmKey("tenant:101").realmType(RealmTypeEnum.TENANT).storagePartitionId(101L).businessTenantId(101L).trustVersion(2L).build();
    private final OAuthSecurityStateRepository states = mock(OAuthSecurityStateRepository.class);
    private final OAuthRevocationRepository revocations = mock(OAuthRevocationRepository.class);
    private final OAuthAuthorizationRepository authorizations = mock(OAuthAuthorizationRepository.class);
    private final OAuthClientRepository clients = mock(OAuthClientRepository.class);
    private final OAuthRealmRepository realms = mock(OAuthRealmRepository.class);
    private final OAuthManagementRealmResolver management = mock(OAuthManagementRealmResolver.class);
    private final Map<String, OAuthSecurityStateBO> rows = new HashMap<>();
    private OAuthSecurityProjectionComponent component;

    @BeforeEach void setUp() {
        component = new OAuthSecurityProjectionComponent(states, revocations, authorizations, clients, realms, management, Clock.fixed(NOW, ZoneOffset.UTC));
        var row = OAuthRealmBO.builder().issuer(REALM.getIssuer()).realmKey(REALM.getRealmKey()).status("ACTIVE").activeKid("key").build();
        when(realms.findByRealmKeyForUpdate(REALM)).thenReturn(Optional.of(row));
        when(realms.findByIssuer(REALM)).thenReturn(Optional.of(row));
        when(clients.findAllByRealm(REALM)).thenReturn(List.of(OAuthClientBO.builder().id(501L).clientId("client").status(OAuthClient.Status.ACTIVE).build()));
        when(states.findByTarget(eq(REALM), any(), anyString())).thenAnswer(call -> Optional.ofNullable(rows.get(call.getArgument(1) + ":" + call.getArgument(2))));
        when(states.save(eq(REALM), any(), eq(0L))).thenAnswer(call -> {
            OAuthSecurityStateBO value = call.getArgument(1); rows.put(value.getTargetType() + ":" + value.getTargetKey(), value); return value;
        });
        when(states.findSnapshot(eq(REALM), eq(501L), any())).thenAnswer(call -> rows.values().stream()
                .filter(value -> value.getTargetType() != OAuthSecurityTargetEnum.SUBJECT || value.getTargetKey().equals(call.getArgument(2))).toList());
        put(OAuthSecurityTargetEnum.REALM, "self", 1, 4); put(OAuthSecurityTargetEnum.CLIENT, "501", 2, 5); put(OAuthSecurityTargetEnum.SUBJECT, "alice", 3, 6);
    }

    @Test void snapshotUsesCommittedGenerationsWithoutRedisReadiness() {
        var snapshot = component.snapshotForAuthorization(REALM, 501L, "USER", "alice");
        assertEquals(1L, snapshot.getRealmGeneration()); assertEquals(2L, snapshot.getClientGeneration());
        assertEquals(3L, snapshot.getSubjectGeneration()); assertEquals(6L, snapshot.getRevision());
        assertEquals("postgresql:2", snapshot.getReadyEpoch());
        verify(realms).findByRealmKeyForUpdate(REALM);
    }

    @Test void currentSnapshotReadsOneRepositorySnapshotAndRejectsRevocation() {
        var expected = component.snapshotForAuthorization(REALM, 501L, "USER", "alice");
        assertDoesNotThrow(() -> component.requireCurrentSnapshot(REALM, 501L, "USER", "alice", expected));
        put(OAuthSecurityTargetEnum.SUBJECT, "alice", 4, 7);
        assertThrows(OAuth2AuthenticationException.class, () -> component.requireCurrentSnapshot(REALM, 501L, "USER", "alice", expected));
        verify(states, times(2)).findSnapshot(REALM, 501L, "alice");
    }

    @Test void disabledStateFailsClosed() {
        rows.get("SUBJECT:alice").setEnabled(false);
        assertThrows(OAuth2AuthenticationException.class, () -> component.snapshotForAuthorization(REALM, 501L, "USER", "alice"));
        rows.get("REALM:self").setEnabled(false); assertFalse(component.isIssuerReady(REALM));
    }

    @Test void missingStateCannotResetGenerationWhenHistoryExists() {
        rows.clear();
        when(authorizations.findExpiredBefore(eq(REALM), any(), eq(0L), eq(1))).thenReturn(List.of(OAuthAuthorizationBO.builder().id(1L).build()));
        assertThrows(OAuth2AuthenticationException.class, () -> component.recover(REALM));
        verify(states, never()).save(any(), any(), anyLong());
    }

    @Test void emptyAuthorityBootstrapIsIdempotent() {
        rows.clear(); assertEquals(0, component.recover(REALM)); assertEquals(2, rows.size());
        assertEquals(0, component.recover(REALM)); verify(states, times(2)).save(eq(REALM), any(), eq(0L));
    }

    @Test void outboxAcknowledgementCannotInventARevisionOrChangeAuthority() {
        var event = new OAuthSecurityChangedEvent("event", 1, REALM.getIssuer(), REALM.getRealmKey(), 4,
                "REALM", "self", 1L, null, "CHANGED", NOW, null);
        component.applyProjection(REALM, event);
        assertThrows(OAuth2AuthenticationException.class, () -> component.applyProjection(REALM,
                new OAuthSecurityChangedEvent("event2", 1, REALM.getIssuer(), REALM.getRealmKey(), 99,
                        "REALM", "self", 1L, null, "CHANGED", NOW, null)));
        verify(states, never()).save(any(), any(), anyLong());
    }

    private void put(OAuthSecurityTargetEnum target, String key, long generation, long revision) {
        rows.put(target + ":" + key, OAuthSecurityStateBO.builder().targetType(target).targetKey(key)
                .generation(generation).revision(revision).enabled(true).reasonCode("INITIALIZED").build());
    }
}
