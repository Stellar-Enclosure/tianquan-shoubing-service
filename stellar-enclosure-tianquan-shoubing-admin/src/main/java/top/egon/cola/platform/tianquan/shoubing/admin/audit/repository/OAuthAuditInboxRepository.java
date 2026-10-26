package top.egon.cola.platform.tianquan.shoubing.admin.audit.repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditInboxBO;

/** Database authority scoped only by a previously verified realm. */
public interface OAuthAuditInboxRepository {

    Optional<OAuthAuditInboxBO> findByEventId(TrustedRealmBO realm, String key);

    Optional<OAuthAuditInboxBO> findByEventIdForUpdate(TrustedRealmBO realm, String key);

    OAuthAuditInboxBO save(TrustedRealmBO realm, OAuthAuditInboxBO value, long expectedVersion);

    List<OAuthAuditInboxBO> findRetainedBefore(TrustedRealmBO realm, Instant now, long afterId, int limit);

    List<OAuthAuditInboxBO> findDue(TrustedRealmBO realm, Instant now, int limit);
    boolean deleteRetained(TrustedRealmBO realm, long id, long expectedVersion, Instant now);
}
