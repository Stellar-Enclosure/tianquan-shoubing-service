package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthConsentBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter.SasConsentConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthConsentRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSecurityStateBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class TenantConsentReplicaFenceTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/7"))
            .realmKey("tenant:7").realmType(RealmTypeEnum.TENANT).storagePartitionId(7L).businessTenantId(7L).trustVersion(0L).build();
    private final TenantIssuerService issuers = mock(TenantIssuerService.class);
    private final OAuthConsentRepository consents = mock(OAuthConsentRepository.class);
    private final OAuthRealmRepository realms = mock(OAuthRealmRepository.class);
    private final OAuthSecurityStateRepository states = mock(OAuthSecurityStateRepository.class);
    private final TenantConsentServiceImpl service = new TenantConsentServiceImpl(issuers, consents,
            mock(OAuthClientRepository.class), mock(SasConsentConverter.class), Clock.fixed(NOW, ZoneOffset.UTC), realms, states);
    private final OAuth2AuthorizationConsent consent = OAuth2AuthorizationConsent.withId("5", "alice").scope("openid").build();

    @Test void replicaMissRequiresPrimaryProofBeforeReturning() {
        when(issuers.resolveCurrentIssuer()).thenReturn(realm);
        when(realms.fenceActiveObservedVersion(realm)).thenReturn(true);
        var state = OAuthSecurityStateBO.builder().id(9L).version(3L).targetType(OAuthSecurityTargetEnum.REALM).targetKey("self").build();
        when(states.findByTarget(realm, OAuthSecurityTargetEnum.REALM, "self")).thenReturn(Optional.of(state));
        when(states.fenceRealmIfConsentInactive(realm, 9L, 3L, 5L, "alice", NOW)).thenReturn(false, true);
        assertThatThrownBy(() -> service.remove(consent)).isInstanceOf(TransientDataAccessResourceException.class);
        assertThatCode(() -> service.remove(consent)).doesNotThrowAnyException();
        verify(consents, never()).findConsentForUpdate(any(), any(), any());
        verify(consents, never()).save(any(), any(), anyLong());
    }

    @Test void alreadyRevokedReplicaRowIsStillVersionFencedOnThePrimary() {
        when(issuers.resolveCurrentIssuer()).thenReturn(realm);
        when(realms.fenceActiveObservedVersion(realm)).thenReturn(true);
        var existing = OAuthConsentBO.builder().id(11L).version(4L).clientPk(5L).subject("alice").status("REVOKED").build();
        when(consents.findConsent(realm, 5L, "alice")).thenReturn(Optional.of(existing));
        service.remove(consent);
        verify(consents).save(eq(realm), argThat(value -> value.getVersion() == 5L && "REVOKED".equals(value.getStatus())), eq(4L));
        verify(consents, never()).findConsentForUpdate(any(), any(), any());
    }
}
