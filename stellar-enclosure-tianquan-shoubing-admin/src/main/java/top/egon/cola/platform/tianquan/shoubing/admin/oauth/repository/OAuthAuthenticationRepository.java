package top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthenticationBO;

/** Database authority scoped only by a previously verified realm. */
public interface OAuthAuthenticationRepository {

    Optional<OAuthAuthenticationBO> findByJtiDigest(TrustedRealmBO realm, String key);

    Optional<OAuthAuthenticationBO> findByJtiDigestForUpdate(TrustedRealmBO realm, String key);

    OAuthAuthenticationBO save(TrustedRealmBO realm, OAuthAuthenticationBO value, long expectedVersion);

    List<OAuthAuthenticationBO> findRetainedBefore(TrustedRealmBO realm, Instant now, long afterId, int limit);

    List<OAuthAuthenticationBO> findActiveByBrowser(TrustedRealmBO realm, String binding, long afterId, int limit);
    boolean deleteRetained(TrustedRealmBO realm, long id, long expectedVersion, Instant now);
}
