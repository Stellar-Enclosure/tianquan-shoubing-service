package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import java.net.URI;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.TokenRevocationService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class OAuthRevocationReplicaMissTest {
    private static final String TOKEN = "test-token";
    private final OAuth2AuthorizationService authorizations = mock(OAuth2AuthorizationService.class);
    private final TokenRevocationService revocations = mock(TokenRevocationService.class);
    private final TenantIssuerService issuers = mock(TenantIssuerService.class);
    private final PlatformTransactionManager transactions = mock(PlatformTransactionManager.class);
    private final SimpleTransactionStatus status = new SimpleTransactionStatus();
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/tenants/101"))
            .realmType(RealmTypeEnum.TENANT).realmKey("tenant:101").storagePartitionId(101L)
            .businessTenantId(101L).trustVersion(0L).build();
    private final RegisteredClient client = client("501");
    private final OAuth2ClientAuthenticationToken principal = new OAuth2ClientAuthenticationToken(
            client, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "secret");
    private final OAuth2TokenRevocationAuthenticationToken request = new OAuth2TokenRevocationAuthenticationToken(TOKEN, principal, "access_token");
    private final TransactionalOAuthRevocationAuthenticationProvider provider =
            new TransactionalOAuthRevocationAuthenticationProvider(authorizations, revocations, issuers, transactions);

    @BeforeEach
    void setUp() {
        when(transactions.getTransaction(any())).thenReturn(status);
        when(issuers.resolveCurrentIssuer()).thenReturn(realm);
    }

    @Test
    void anUnknownReplicaTokenStillRunsTheAuthoritativeAbsenceCheck() {
        when(authorizations.findByToken(TOKEN, null)).thenReturn(null);

        assertThat(provider.authenticate(request)).isSameAs(request);
        verify(revocations).revoke(eq(realm), argThat(command -> command.getClientPk().equals(501L)));
        verify(authorizations, never()).save(any());
        verify(transactions).commit(status);
    }

    @Test
    void anUnconfirmedReplicaMissRollsBackAndReturnsRetryableOAuthError() {
        when(authorizations.findByToken(TOKEN, null)).thenReturn(null);
        doThrow(new TransientDataAccessResourceException("replica lag")).when(revocations).revoke(eq(realm), any());

        assertThatThrownBy(() -> provider.authenticate(request)).isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(error -> assertThat(((OAuth2AuthenticationException) error).getError().getErrorCode())
                        .isEqualTo("temporarily_unavailable"));
        verify(transactions).rollback(status);
        verify(transactions, never()).commit(any());
    }

    @Test
    void sasClientBindingRejectionDoesNotCallTheRevocationWriter() {
        var otherClient = client("502");
        var authorization = OAuth2Authorization.withRegisteredClient(otherClient).principalName("service")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .token(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, TOKEN,
                        Instant.parse("2026-10-28T00:00:00Z"), Instant.parse("2026-10-29T00:00:00Z"))).build();
        when(authorizations.findByToken(TOKEN, null)).thenReturn(authorization);

        assertThatThrownBy(() -> provider.authenticate(request)).isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(error -> assertThat(((OAuth2AuthenticationException) error).getError().getErrorCode()).isEqualTo("invalid_client"));
        verifyNoInteractions(revocations);
        verify(transactions).rollback(status);
    }

    private static RegisteredClient client(String id) {
        return RegisteredClient.withId(id).clientId("client-" + id).clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build();
    }
}
