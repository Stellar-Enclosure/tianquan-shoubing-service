package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import java.time.Clock;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthenticationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthorizationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.core.audit.IdentitySecurityEvent;
import top.egon.cola.platform.tianquan.shoubing.core.audit.IdentitySecurityEventPort;

/** Closes one SSO authentication and only its linked grants in the same database transaction. */
@Service("oauthSsoLifecycleService")
@RequiredArgsConstructor
public class OAuthSsoLifecycleService {
    @Qualifier("oAuthRealmRepository") private final OAuthRealmRepository realms;
    @Qualifier("oAuthAuthenticationRepository") private final OAuthAuthenticationRepository authentications;
    @Qualifier("oAuthAuthorizationRepository") private final OAuthAuthorizationRepository authorizations;
    @Qualifier("identityOutboxPublisher") private final IdentitySecurityEventPort events;
    @Qualifier("idpClock") private final Clock clock;

    @Transactional
    public void logout(TrustedRealmBO realm, String authenticationDigest, String bindingDigest, String subject) {
        realms.findByRealmKeyForUpdate(realm).orElseThrow(() -> new IllegalStateException("OAUTH_SSO_REALM_MISSING"));
        var current = authentications.findByJtiDigest(realm, authenticationDigest)
                .orElseThrow(() -> new IllegalArgumentException("OAUTH_SSO_AUTHENTICATION_MISSING"));
        if (!Objects.equals(current.getBrowserBindingDigest(), bindingDigest) || !Objects.equals(current.getSubject(), subject)) {
            throw new IllegalArgumentException("OAUTH_SSO_BINDING_MISMATCH");
        }
        long version = current.getVersion();
        boolean alreadyRevoked = "REVOKED".equals(current.getStatus());
        current.setVersion(Math.addExact(version, 1L));
        if (!alreadyRevoked) {
            current.setStatus("REVOKED").setRevokedAt(clock.instant()).setReasonCode("CURRENT_SSO_LOGOUT");
        }
        authentications.save(realm, current, version);
        long after = 0L;
        while (true) {
            var grants = authorizations.findByAuthentication(realm, authenticationDigest, after, 500);
            for (var candidate : grants) {
                after = Math.max(after, candidate.getId());
                var grant = candidate;
                if (!authenticationDigest.equals(grant.getAuthenticationJtiDigest()) || !subject.equals(grant.getPrincipalName())) {
                    throw new IllegalStateException("OAUTH_SSO_GRANT_BINDING_MISMATCH");
                }
                long grantVersion = grant.getVersion();
                grant.setVersion(Math.addExact(grantVersion, 1L)).setStatus("REVOKED").setRevokedAt(clock.instant());
                authorizations.save(realm, grant, grantVersion);
            }
            if (grants.size() < 500) { break; }
        }
        // The primary predicate catches grants that a lagging replica did not return.
        if (!authentications.fenceRevokedWithoutLiveAuthorizations(realm, current.getId(), authenticationDigest,
                current.getVersion(), clock.instant())) {
            throw new org.springframework.dao.TransientDataAccessResourceException("SSO authorizations are not yet visible on a replica");
        }
        if (!alreadyRevoked) {
            events.append(new IdentitySecurityEvent("IDENTITY_SSO_REVOKED", subject, "CURRENT_SSO_LOGOUT", "NATIVE_SSO", clock.instant()));
        }
    }
}
