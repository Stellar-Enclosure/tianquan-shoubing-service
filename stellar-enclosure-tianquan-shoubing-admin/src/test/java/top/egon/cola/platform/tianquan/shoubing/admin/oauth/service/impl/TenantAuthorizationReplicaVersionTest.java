package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
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
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationAttributesBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthSecuritySnapshotBO;
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
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.support.OAuthTransactionFences;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.bo.OAuthGrantBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthTokenRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthSecurityProjectionComponent;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class TenantAuthorizationReplicaVersionTest {
    @Test
    void serviceAuthorizationPersistsAfterReloadingTheClientAdvancedByItsOwnFences() {
        var realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/101"))
                .realmType(RealmTypeEnum.TENANT).realmKey("tenant:101").storagePartitionId(101L)
                .businessTenantId(101L).trustVersion(0L).build();
        var issuers = mock(TenantIssuerService.class); var realms = mock(OAuthRealmRepository.class);
        var authorizations = mock(OAuthAuthorizationRepository.class); var tokens = mock(OAuthTokenRepository.class);
        var clients = mock(OAuthClientRepository.class);
        var converter = mock(SasAuthorizationConverter.class); var clientConverter = mock(SasRegisteredClientConverter.class);
        var projection = mock(OAuthSecurityProjectionComponent.class);
        var mapper = new ObjectMapper();
        var now = Instant.parse("2026-10-28T00:00:00Z");
        var observed = OAuthClientBO.builder().id(501L).clientId("client-501").version(4L)
                .status(OAuthClient.Status.ACTIVE).allowedScopes(List.of("read")).build();
        var reloaded = OAuthClientBO.builder().id(501L).clientId("client-501").version(6L)
                .status(OAuthClient.Status.ACTIVE).allowedScopes(List.of("read")).build();
        var grant = OAuthGrantBO.builder().id(9L).clientPk(501L).version(1L).build();
        var registered = RegisteredClient.withId("501").clientId("client-501")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("read").build();
        var source = OAuth2Authorization.withRegisteredClient(registered).principalName("client-501")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).authorizedScopes(java.util.Set.of("read")).build();
        var value = OAuthAuthorizationBO.builder().id(700L).clientPk(501L).principalName("client-501")
                .principalType("SERVICE").status("ACTIVE").authorizedScopes(List.of("read"))
                .audiences(List.of("https://api.example/orders")).absoluteExpiresAt(now.plusSeconds(300))
                .attributes(OAuthAuthorizationAttributesBO.builder().schemaVersion(1).build()).build();
        when(issuers.resolveCurrentIssuer()).thenReturn(realm);
        when(realms.fenceActiveObservedVersion(realm)).thenReturn(true);
        when(clients.fenceObservedVersion(realm, observed)).thenReturn(true);
        when(clients.fenceGrantObservedVersion(realm, observed, 5L, grant)).thenReturn(true);
        when(clients.findById(realm, 501L)).thenReturn(Optional.of(reloaded));
        when(clientConverter.toTarget(reloaded)).thenReturn(registered);
        when(converter.toSource(any(), isNull(), eq(mapper))).thenReturn(value);
        when(projection.snapshotForFencedRealm(realm, 501L, "SERVICE", null))
                .thenReturn(OAuthSecuritySnapshotBO.builder().realmGeneration(1L).clientGeneration(1L).build());
        when(authorizations.save(eq(realm), any(), eq(0L))).thenAnswer(call -> call.getArgument(1));
        var service = new TenantAuthorizationServiceImpl(issuers, realms, authorizations, mock(OAuthAuthenticationRepository.class),
                tokens, clients, converter, clientConverter, mapper, Clock.fixed(now, ZoneOffset.UTC), projection,
                mock(OAuthTokenIssueService.class), mock(OAuthBrowserInteractionComponent.class), mock(OAuthDeviceSessionService.class),
                mock(top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository.class));
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
        try {
            assertThat(OAuthTransactionFences.client(clients, realm, observed)).isTrue();
            assertThat(OAuthTransactionFences.grant(clients, realm, observed, grant)).isTrue();

            service.save(source);

            verify(authorizations).save(realm, value, 0L);
            verify(clients, never()).fenceObservedVersion(realm, reloaded);
        } finally {
            TransactionSynchronizationManager.getSynchronizations().forEach(
                    sync -> sync.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));
            TransactionSynchronizationManager.clearSynchronization();
            TransactionSynchronizationManager.setActualTransactionActive(false);
        }
    }

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
        when(realms.fenceActiveObservedVersion(realm)).thenReturn(true);
        when(clients.findById(realm, 501L)).thenReturn(Optional.of(client));
        when(clients.fenceObservedVersion(realm, client)).thenReturn(true);
        when(authorizations.findById(realm, 700L)).thenReturn(Optional.of(OAuthAuthorizationBO.builder().id(700L).version(2L).build()));
        when(transactions.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        var service = new TenantAuthorizationServiceImpl(issuers, realms, authorizations, mock(OAuthAuthenticationRepository.class),
                tokens, clients, mock(SasAuthorizationConverter.class), mock(SasRegisteredClientConverter.class), new ObjectMapper(),
                Clock.fixed(Instant.parse("2026-10-28T00:00:00Z"), ZoneOffset.UTC), mock(OAuthSecurityProjectionComponent.class),
                mock(OAuthTokenIssueService.class), mock(OAuthBrowserInteractionComponent.class), mock(OAuthDeviceSessionService.class),
                mock(top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository.class));
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
        verify(realms, never()).findByRealmKeyForUpdate(any());
        verify(clients, never()).findByClientIdForUpdate(any(), anyString());
        verify(authorizations, never()).findByIdForUpdate(any(), anyLong());
        verify(authorizations, never()).save(any(), any(), anyLong());
        verifyNoInteractions(tokens);
    }
}
