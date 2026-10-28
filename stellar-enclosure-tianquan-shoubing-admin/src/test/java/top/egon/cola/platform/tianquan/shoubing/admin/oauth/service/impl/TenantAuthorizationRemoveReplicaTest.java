package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationAttributesBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter.SasAuthorizationConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter.SasRegisteredClientConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthenticationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthorizationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.OAuthTokenIssueService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSecurityStateBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthTokenBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthTokenMetadataBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthTokenTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthTokenRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthSecurityProjectionComponent;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class TenantAuthorizationRemoveReplicaTest {
    private static final Instant NOW = Instant.parse("2026-10-28T00:00:00Z");
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/7"))
            .realmKey("tenant:7").realmType(RealmTypeEnum.TENANT).storagePartitionId(7L).businessTenantId(7L).trustVersion(0L).build();
    private final TenantIssuerService issuers = mock(TenantIssuerService.class);
    private final OAuthRealmRepository realms = mock(OAuthRealmRepository.class);
    private final OAuthAuthorizationRepository authorizations = mock(OAuthAuthorizationRepository.class);
    private final OAuthTokenRepository tokens = mock(OAuthTokenRepository.class);
    private final OAuthSecurityStateRepository states = mock(OAuthSecurityStateRepository.class);
    private final PlatformTransactionManager transactions = mock(PlatformTransactionManager.class);
    private final TenantAuthorizationServiceImpl service = new TenantAuthorizationServiceImpl(issuers, realms, authorizations,
            mock(OAuthAuthenticationRepository.class), tokens, mock(OAuthClientRepository.class), mock(SasAuthorizationConverter.class),
            mock(SasRegisteredClientConverter.class), new ObjectMapper(), Clock.fixed(NOW, ZoneOffset.UTC),
            mock(OAuthSecurityProjectionComponent.class), mock(OAuthTokenIssueService.class), mock(OAuthBrowserInteractionComponent.class),
            mock(OAuthDeviceSessionService.class), states);
    private final OAuth2Authorization source = OAuth2Authorization.withRegisteredClient(
                    RegisteredClient.withId("5").clientId("client").clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build())
            .id("17").principalName("service").authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build();

    @BeforeEach void setup() {
        when(issuers.resolveCurrentIssuer()).thenReturn(realm);
        when(realms.fenceObservedVersion(realm)).thenReturn(true);
        when(states.findByTarget(realm, OAuthSecurityTargetEnum.REALM, "self")).thenReturn(Optional.of(
                OAuthSecurityStateBO.builder().id(42L).version(3L).targetType(OAuthSecurityTargetEnum.REALM).targetKey("self").build()));
        when(transactions.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
    }

    @Test void missingReplicaAuthorizationMustBeConfirmedBeforeReturning() {
        when(states.fenceRealmIfAuthorizationAbsent(realm, 42L, 3L, 17L, NOW)).thenReturn(false, true);
        assertThatThrownBy(() -> new TransactionTemplate(transactions).executeWithoutResult(status -> service.remove(source)))
                .isInstanceOf(TransientDataAccessResourceException.class);
        verify(transactions).rollback(any());
        assertThatCode(() -> service.remove(source)).doesNotThrowAnyException();
        verify(authorizations, never()).findByIdForUpdate(any(), anyLong());
        verify(realms, never()).findByRealmKeyForUpdate(any());
        verifyNoInteractions(tokens);
    }

    @Test void hiddenLiveTokenRollsBackAuthorizationAndVisibleTokenUpdates() {
        var authorization = OAuthAuthorizationBO.builder().id(17L).version(4L).status("ACTIVE")
                .attributes(OAuthAuthorizationAttributesBO.builder().build()).build();
        when(authorizations.findById(realm, 17L)).thenReturn(Optional.of(authorization));
        var token = OAuthTokenBO.builder().id(19L).version(0L).authorizationPk(17L).tokenType(OAuthTokenTypeEnum.ACCESS)
                .tokenDigest("a".repeat(64)).metadata(OAuthTokenMetadataBO.builder().build()).build();
        when(tokens.findByAuthorization(realm, 17L, OAuthTokenTypeEnum.ACCESS, 0L, 500)).thenReturn(List.of(token));
        when(states.fenceRealmIfAuthorizationTokensInactive(realm, 42L, 3L, 17L, NOW)).thenReturn(false);
        assertThatThrownBy(() -> new TransactionTemplate(transactions).executeWithoutResult(status -> service.remove(source)))
                .isInstanceOf(TransientDataAccessResourceException.class);
        verify(transactions).rollback(any());
        verify(tokens).save(eq(realm), argThat(value -> value.getRevokedAt().equals(NOW) && value.getMetadata().isInvalidated()), eq(0L));
        verify(authorizations).save(eq(realm), argThat(value -> "REVOKED".equals(value.getStatus())), eq(4L));
        verify(authorizations, never()).findByIdForUpdate(any(), anyLong());
    }

    @Test void invalidatedLegacyTokenWithoutTimestampIsFencedBeforeSuccess() {
        var authorization = OAuthAuthorizationBO.builder().id(17L).version(4L).status("ACTIVE")
                .attributes(OAuthAuthorizationAttributesBO.builder().build()).build();
        when(authorizations.findById(realm, 17L)).thenReturn(Optional.of(authorization));
        var token = OAuthTokenBO.builder().id(19L).version(0L).authorizationPk(17L).tokenType(OAuthTokenTypeEnum.ACCESS)
                .tokenDigest("a".repeat(64)).metadata(OAuthTokenMetadataBO.builder().invalidated(true).build()).build();
        when(tokens.findByAuthorization(realm, 17L, OAuthTokenTypeEnum.ACCESS, 0L, 500)).thenReturn(List.of(token));
        when(states.fenceRealmIfAuthorizationTokensInactive(realm, 42L, 3L, 17L, NOW)).thenReturn(true);
        service.remove(source);
        verify(tokens).save(eq(realm), argThat(value -> NOW.equals(value.getRevokedAt())), eq(0L));
    }
}
