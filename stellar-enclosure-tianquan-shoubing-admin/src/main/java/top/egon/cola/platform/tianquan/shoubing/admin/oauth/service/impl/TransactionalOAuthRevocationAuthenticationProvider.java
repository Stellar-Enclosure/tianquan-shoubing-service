package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import top.egon.cola.component.common.crypto.digest.Digests;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.command.RevokeOAuthTokenCommand;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.TokenRevocationService;

/** Keeps SAS token-revocation checks and the durable security event in one transaction. */
@RequiredArgsConstructor
@Slf4j
public final class TransactionalOAuthRevocationAuthenticationProvider implements AuthenticationProvider {

    @Qualifier("tenantAuthorizationService")
    private final OAuth2AuthorizationService authorizations;
    @Qualifier("tokenRevocationService")
    private final TokenRevocationService revocations;
    @Qualifier("tenantIssuerService")
    private final TenantIssuerService issuers;
    @Qualifier("transactionManager")
    private final PlatformTransactionManager transactionManager;

    @Override
    public Authentication authenticate(Authentication authentication) throws OAuth2AuthenticationException {
        OAuth2TokenRevocationAuthenticationToken request = (OAuth2TokenRevocationAuthenticationToken) authentication;
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        transaction.setName("oauthTokenRevocation");
        try {
            return transaction.execute(status -> {
                OAuth2TokenRevocationAuthenticationProvider delegate = new OAuth2TokenRevocationAuthenticationProvider(
                        new ValidationOnlyAuthorizationService(authorizations));
                Authentication result = delegate.authenticate(request);
                OAuth2ClientAuthenticationToken client = (OAuth2ClientAuthenticationToken) request.getPrincipal();
                long clientPk = positiveClientId(client.getRegisteredClient().getId());
                TrustedRealmBO trustedRealm = issuers.resolveCurrentIssuer();
                revocations.revoke(trustedRealm, RevokeOAuthTokenCommand.builder()
                        .tokenDigest(Digests.sha256Hex(request.getToken()))
                        .clientPk(clientPk)
                        .reasonCode("RFC7009_REVOKE")
                        .build());
                return result;
            });
        } catch (org.springframework.dao.DataAccessException failure) {
            throw new OAuth2AuthenticationException(new OAuth2Error("temporarily_unavailable", "Request temporarily unavailable", null), failure);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2TokenRevocationAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /** SAS validates the client and token; the revocation service performs the authoritative write. */
    private record ValidationOnlyAuthorizationService(OAuth2AuthorizationService delegate) implements OAuth2AuthorizationService {
        @Override public void save(OAuth2Authorization authorization) { }
        @Override public void remove(OAuth2Authorization authorization) { throw new UnsupportedOperationException("OAUTH_REVOCATION_REMOVE_UNSUPPORTED"); }
        @Override public OAuth2Authorization findById(String id) { return delegate.findById(id); }
        @Override public OAuth2Authorization findByToken(String token, OAuth2TokenType type) { return delegate.findByToken(token, type); }
    }

    private static long positiveClientId(String value) {
        try {
            long clientPk = Long.parseLong(value);
            if (clientPk > 0L) {
                return clientPk;
            }
        } catch (NumberFormatException invalid) {
            throw new IllegalStateException("OAUTH_REVOCATION_CLIENT_ID_INVALID", invalid);
        }
        throw new IllegalStateException("OAUTH_REVOCATION_CLIENT_ID_INVALID");
    }
}
