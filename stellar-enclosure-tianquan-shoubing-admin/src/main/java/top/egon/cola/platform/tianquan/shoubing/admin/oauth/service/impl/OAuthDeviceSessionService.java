package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.util.List;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthDeviceSessionBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.vo.OAuthDeviceSessionVO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthorizationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthDeviceSessionRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.support.OAuthTransactionFences;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.core.audit.IdentitySecurityEvent;
import top.egon.cola.platform.tianquan.shoubing.core.audit.IdentitySecurityEventPort;

/** Realm locking serializes admission, eviction and grant issuance across nodes. */
@Service("oauthDeviceSessionService")
@RequiredArgsConstructor
public class OAuthDeviceSessionService {
    public static final int MAXIMUM_SESSIONS = 5;
    @Qualifier("oAuthRealmRepository") private final OAuthRealmRepository realms;
    @Qualifier("oAuthDeviceSessionRepository") private final OAuthDeviceSessionRepository sessions;
    @Qualifier("oAuthAuthorizationRepository") private final OAuthAuthorizationRepository grants;
    @Qualifier("oAuthClientRepository") private final OAuthClientRepository clients;
    @Qualifier("identityOutboxPublisher") private final IdentitySecurityEventPort events;
    @Qualifier("idpClock") private final Clock clock;
    @Qualifier("oAuthSecurityStateRepository") private final OAuthSecurityStateRepository securityStates;

    @Transactional
    public Long register(TrustedRealmBO realm, OAuthClientBO client, OAuthAuthorizationBO grant, HttpServletRequest request) {
        lockRealm(realm);
        var existing = sessions.findByAuthentication(realm, grant.getAuthenticationJtiDigest(), client.getId()).orElse(null);
        if (existing != null && (!"ACTIVE".equals(existing.getStatus()) || !grant.getPrincipalName().equals(existing.getSubject()))) {
            throw new OAuth2AuthenticationException(new OAuth2Error("login_required", "Fresh authentication required", null));
        }
        var now = clock.instant().truncatedTo(java.time.temporal.ChronoUnit.MICROS);
        var live = sessions.findLiveBySubject(realm, grant.getPrincipalName(), now);
        var state = securityStates.findByTarget(realm, OAuthSecurityTargetEnum.REALM, "self")
                .orElseThrow(() -> new org.springframework.dao.TransientDataAccessResourceException("OAuth realm state is not visible"));
        if (!sessions.fenceLiveSnapshot(realm, state.getId(), state.getVersion(), grant.getPrincipalName(), now, live)) {
            throw new org.springframework.dao.TransientDataAccessResourceException("OAuth device sessions are not yet visible");
        }
        state.setVersion(Math.addExact(state.getVersion(), 1L));
        OAuthTransactionFences.securityStateWritten(realm, state);
        boolean alreadyLive = existing != null && live.stream().anyMatch(value -> Objects.equals(value.getId(), existing.getId()));
        int count = live.size();
        for (var candidate : live) {
            if (count < MAXIMUM_SESSIONS || alreadyLive && count <= MAXIMUM_SESSIONS) { break; }
            if (existing != null && Objects.equals(candidate.getId(), existing.getId())) { continue; }
            revoke(realm, candidate, "DEVICE_SESSION_LIMIT");
            count--;
        }
        if (existing != null) {
            if (grant.getAbsoluteExpiresAt().isAfter(existing.getExpiresAt())) {
                long version = existing.getVersion();
                sessions.save(realm, existing.toBuilder().version(version + 1).expiresAt(grant.getAbsoluteExpiresAt()).build(), version);
            }
            return existing.getId();
        }
        var created = sessions.save(realm, OAuthDeviceSessionBO.builder().clientPk(client.getId())
                .subject(grant.getPrincipalName()).authenticationJtiDigest(grant.getAuthenticationJtiDigest())
                .authenticatedAt(clock.instant()).expiresAt(grant.getAbsoluteExpiresAt()).status("ACTIVE")
                .userAgent(displayValue(request.getHeader("User-Agent"), 512)).ipAddress(displayValue(request.getRemoteAddr(), 64)).build(), 0L);
        events.appendForTenant(realm.getStoragePartitionId(), new IdentitySecurityEvent("IDENTITY_DEVICE_SESSION_CREATED", created.getSubject(),
                "DEVICE_SESSION_LOGIN", "NATIVE_SSO", clock.instant()));
        return created.getId();
    }

    @Transactional(readOnly = true)
    public List<OAuthDeviceSessionVO> list(TrustedRealmBO realm, String subject) {
        return sessions.findLiveBySubject(realm, subject, clock.instant()).stream().map(session -> {
            var client = clients.findById(realm, session.getClientPk()).orElseThrow(() -> new IllegalStateException("OAUTH_SESSION_CLIENT_MISSING"));
            return new OAuthDeviceSessionVO(Long.toString(session.getId()), client.getClientId(), client.getClientName(),
                    client.isBrowserBound() ? "BROWSER" : "APP", platform(session.getUserAgent()), session.getUserAgent(),
                    session.getIpAddress(), session.getAuthenticatedAt(), session.getExpiresAt());
        }).toList();
    }

    @Transactional
    public void revoke(TrustedRealmBO realm, String subject, long sessionId) {
        lockRealm(realm);
        var session = sessions.findById(realm, sessionId).filter(value -> subject.equals(value.getSubject()))
                .orElseThrow(() -> new AccessDeniedException("OAUTH_DEVICE_SESSION_FORBIDDEN"));
        revoke(realm, session, "DEVICE_SESSION_KICKED");
    }

    private void revoke(TrustedRealmBO realm, OAuthDeviceSessionBO session, String reason) {
        if ("REVOKED".equals(session.getStatus())) { return; }
        long version = session.getVersion();
        var revoked = sessions.save(realm, session.toBuilder().version(version + 1).status("REVOKED").revokedAt(clock.instant()).reasonCode(reason).build(), version);
        long after = 0L;
        while (true) {
            var page = grants.findByDeviceSession(realm, session.getId(), after, 500);
            for (var candidate : page) {
                after = Math.max(after, candidate.getId());
                var grant = candidate;
                if (!Objects.equals(grant.getDeviceSessionId(), session.getId()) || !session.getSubject().equals(grant.getPrincipalName())) {
                    throw new IllegalStateException("OAUTH_DEVICE_SESSION_GRANT_MISMATCH");
                }
                long grantVersion = grant.getVersion();
                grant.setVersion(grantVersion + 1).setStatus("REVOKED").setRevokedAt(clock.instant());
                grants.save(realm, grant, grantVersion);
            }
            if (page.size() < 500) { break; }
        }
        if (!sessions.fenceRevokedWithoutLiveAuthorizations(realm, revoked.getId(), revoked.getVersion(), clock.instant())) {
            throw new org.springframework.dao.TransientDataAccessResourceException("OAuth device authorizations are not yet visible");
        }
        events.appendForTenant(realm.getStoragePartitionId(), new IdentitySecurityEvent("IDENTITY_DEVICE_SESSION_REVOKED", session.getSubject(), reason, "NATIVE_SSO", clock.instant()));
    }

    private void lockRealm(TrustedRealmBO realm) {
        if (!OAuthTransactionFences.realm(realms, realm)) {
            throw new org.springframework.dao.OptimisticLockingFailureException("OAuth realm changed before device session update");
        }
    }

    private static String displayValue(String value, int limit) {
        if (value == null) { return null; }
        String safe = value.replaceAll("[\\p{Cntrl}]", " ");
        return safe.substring(0, Math.min(safe.length(), limit));
    }

    private static String platform(String userAgent) {
        if (userAgent == null) { return "UNKNOWN"; }
        if (userAgent.contains("Android")) { return "Android"; }
        if (userAgent.contains("iPhone") || userAgent.contains("iPad")) { return "iOS"; }
        if (userAgent.contains("Windows")) { return "Windows"; }
        if (userAgent.contains("Macintosh") || userAgent.contains("Mac OS")) { return "macOS"; }
        if (userAgent.contains("Linux")) { return "Linux"; }
        return "UNKNOWN";
    }
}
