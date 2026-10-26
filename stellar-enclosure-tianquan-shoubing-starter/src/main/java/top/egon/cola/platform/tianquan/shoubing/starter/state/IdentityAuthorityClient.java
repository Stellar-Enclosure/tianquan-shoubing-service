package top.egon.cola.platform.tianquan.shoubing.starter.state;

import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuditReceipt;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentitySecurityStateRequest;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentitySecurityStateResponse;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditEvent;

/** Calls an explicitly configured authority; implementations cannot select hosts from JWT claims. */
public interface IdentityAuthorityClient {
    IdentitySecurityStateResponse resolve(IdentitySecurityStateRequest request);

    IdentityAuditReceipt appendAudit(TokenUsageAuditEvent event);
}
