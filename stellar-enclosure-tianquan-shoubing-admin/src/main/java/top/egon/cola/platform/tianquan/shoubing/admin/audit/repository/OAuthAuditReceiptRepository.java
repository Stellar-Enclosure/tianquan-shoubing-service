package top.egon.cola.platform.tianquan.shoubing.admin.audit.repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo.OAuthAuditReceiptBO;

/** Database authority scoped only by a previously verified realm. */
public interface OAuthAuditReceiptRepository {

    Optional<OAuthAuditReceiptBO> findByEventId(TrustedRealmBO realm, String key);

    Optional<OAuthAuditReceiptBO> findByEventIdForUpdate(TrustedRealmBO realm, String key);

    OAuthAuditReceiptBO save(TrustedRealmBO realm, OAuthAuditReceiptBO value, long expectedVersion);

    List<OAuthAuditReceiptBO> findRetainedBefore(TrustedRealmBO realm, Instant now, long afterId, int limit);
    boolean deleteRetained(TrustedRealmBO realm, long id, long expectedVersion, Instant now);
}
