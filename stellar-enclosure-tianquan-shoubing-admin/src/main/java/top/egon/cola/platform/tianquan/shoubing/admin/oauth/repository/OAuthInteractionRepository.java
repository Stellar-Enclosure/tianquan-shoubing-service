package top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthInteractionBO;

/** Database authority scoped only by a previously verified realm. */
public interface OAuthInteractionRepository {

    Optional<OAuthInteractionBO> findByInteractionId(TrustedRealmBO realm, String key);

    Optional<OAuthInteractionBO> findByInteractionIdForUpdate(TrustedRealmBO realm, String key);

    OAuthInteractionBO save(TrustedRealmBO realm, OAuthInteractionBO value, long expectedVersion);

    List<OAuthInteractionBO> findRetainedBefore(TrustedRealmBO realm, Instant now, long afterId, int limit);
    boolean deleteRetained(TrustedRealmBO realm, long id, long expectedVersion, Instant now);
}
