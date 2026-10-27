package top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthDeviceSessionBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;

/** All mutations participate in the caller's realm-locked transaction. */
public interface OAuthDeviceSessionRepository {
    Optional<OAuthDeviceSessionBO> findById(TrustedRealmBO realm, long id);
    Optional<OAuthDeviceSessionBO> findByAuthentication(TrustedRealmBO realm, String digest, Long clientPk);
    List<OAuthDeviceSessionBO> findLiveBySubject(TrustedRealmBO realm, String subject, Instant now);
    int deleteRetained(TrustedRealmBO realm, Instant now, int limit);
    OAuthDeviceSessionBO save(TrustedRealmBO realm, OAuthDeviceSessionBO session, long expectedVersion);
}
