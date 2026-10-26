package top.egon.cola.platform.tianquan.shoubing.admin.audit.repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditDeadLetterBO;

/** Database authority scoped only by a previously verified realm. */
public interface OAuthAuditDeadLetterRepository {

    Optional<OAuthAuditDeadLetterBO> findByInboxPk(TrustedRealmBO realm, Long key);

    Optional<OAuthAuditDeadLetterBO> findByInboxPkForUpdate(TrustedRealmBO realm, Long key);

    OAuthAuditDeadLetterBO save(TrustedRealmBO realm, OAuthAuditDeadLetterBO value, long expectedVersion);

    List<OAuthAuditDeadLetterBO> findRetainedBefore(TrustedRealmBO realm, Instant now, long afterId, int limit);
    boolean deleteRetained(TrustedRealmBO realm, long id, long expectedVersion, Instant now);
}
