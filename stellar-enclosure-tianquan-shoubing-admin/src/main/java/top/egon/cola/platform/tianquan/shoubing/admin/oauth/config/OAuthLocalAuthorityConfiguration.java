package top.egon.cola.platform.tianquan.shoubing.admin.oauth.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthorityService;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuditReceipt;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentitySecurityStateRequest;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentitySecurityStateResponse;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditEvent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TrustedIssuerRegistry;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClient;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClientResolver;

/** The IdP's own resource verifier terminates at its database and cannot recursively call AUTH-07. */
@Configuration(proxyBeanMethods = false)
public class OAuthLocalAuthorityConfiguration {
    @Bean("identityAuthorityClientResolver")
    IdentityAuthorityClientResolver identityAuthorityClientResolver(@Qualifier("oauthAuthorityService") OAuthAuthorityService authority,
            @Qualifier("tenantIssuerService") TenantIssuerService issuers, @Qualifier("trustedIssuerRegistry") TrustedIssuerRegistry trust) {
        return issuer -> {
            trust.findByIssuer(issuer.toASCIIString()).orElseThrow(() -> new IllegalArgumentException("IDENTITY_AUTHORITY_ISSUER_UNTRUSTED"));
            var realm = issuers.resolveExactIssuer(issuer);
            return new IdentityAuthorityClient() {
                @Override public IdentitySecurityStateResponse resolve(IdentitySecurityStateRequest request) { return authority.resolveOwnedResource(realm, request); }
                @Override public IdentityAuditReceipt appendAudit(TokenUsageAuditEvent event) { return authority.appendOwnedAudit(realm, event); }
            };
        };
    }
}
