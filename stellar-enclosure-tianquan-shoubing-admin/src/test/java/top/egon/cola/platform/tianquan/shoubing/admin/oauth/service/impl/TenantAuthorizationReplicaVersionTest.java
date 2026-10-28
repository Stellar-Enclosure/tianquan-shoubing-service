package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthRealmBO;
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
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthTokenRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthSecurityProjectionComponent;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class TenantAuthorizationReplicaVersionTest {
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void staleOrMissingSasSnapshotVersionRollsBackWithoutWriting(boolean includeStaleVersion) {
        var realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/101"))
                .realmType(RealmTypeEnum.TENANT).realmKey("tenant:101").storagePartitionId(101L)
                .businessTenantId(101L).trustVersion(0L).build();
        var issuers = mock(TenantIssuerService.class); var realms = mock(OAuthRealmRepository.class);
        var authorizations = mock(OAuthAuthorizationRepository.class); var tokens = mock(OAuthTokenRepository.class);
        var clients = mock(OAuthClientRepository.class); var transactions = mock(PlatformTransactionManager.class);
        var client = OAuthClientBO.builder().id(501L).clientId("client-501").status(OAuthClient.Status.ACTIVE).build();
        when(issuers.resolveCurrentIssuer()).thenReturn(realm);
        when(realms.findByRealmKeyForUpdate(realm)).thenReturn(Optional.of(OAuthRealmBO.builder().build()));
        when(clients.findById(realm, 501L)).thenReturn(Optional.of(client));
        when(clients.findByClientIdForUpdate(realm, "client-501")).thenReturn(Optional.of(client));
        when(authorizations.findById(realm, 700L)).thenReturn(Optional.of(OAuthAuthorizationBO.builder().id(700L).version(2L).build()));
        when(transactions.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        var service = new TenantAuthorizationServiceImpl(issuers, realms, authorizations, mock(OAuthAuthenticationRepository.class),
                tokens, clients, mock(SasAuthorizationConverter.class), mock(SasRegisteredClientConverter.class), new ObjectMapper(),
                Clock.fixed(Instant.parse("2026-10-28T00:00:00Z"), ZoneOffset.UTC), mock(OAuthSecurityProjectionComponent.class),
                mock(OAuthTokenIssueService.class), mock(OAuthBrowserInteractionComponent.class), mock(OAuthDeviceSessionService.class));
        var registered = RegisteredClient.withId("501").clientId("client-501").clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build();
        var builder = OAuth2Authorization.withRegisteredClient(registered).id("700").principalName("service")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
        if (includeStaleVersion) builder.attribute(SasAuthorizationConverter.AUTHORIZATION_VERSION_ATTRIBUTE, 1L);
        var source = builder.build();

        assertThatThrownBy(() -> new TransactionTemplate(transactions).executeWithoutResult(status -> service.save(source)))
                .isInstanceOf(OptimisticLockingFailureException.class);
        verify(transactions).rollback(any());
        verify(authorizations).findById(realm, 700L);
        verify(authorizations, never()).findByIdForUpdate(any(), anyLong());
        verify(authorizations, never()).save(any(), any(), anyLong());
        verifyNoInteractions(tokens);
    }
}
