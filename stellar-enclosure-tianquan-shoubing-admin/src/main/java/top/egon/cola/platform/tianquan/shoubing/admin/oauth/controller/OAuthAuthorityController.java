package top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller.filter.OAuthAuthorityAuthenticationFilter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthorityService;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuditReceipt;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentitySecurityStateRequest;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentitySecurityStateResponse;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditEvent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;

@RestController
@io.swagger.v3.oas.annotations.Hidden
@RequiredArgsConstructor
public class OAuthAuthorityController {

    @Qualifier("oauthAuthorityService") private final OAuthAuthorityService authority;

    @PostMapping("/internal/v1/identity/security-state:resolve")
    public ResponseEntity<IdentitySecurityStateResponse> resolve(@Valid @RequestBody IdentitySecurityStateRequest body,
            HttpServletRequest request) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(authority.resolve(caller(request), body));
    }

    @PostMapping("/internal/v1/identity/audit-events")
    public ResponseEntity<IdentityAuditReceipt> append(@Valid @RequestBody TokenUsageAuditEvent event,
            HttpServletRequest request) {
        var receipt = authority.appendAudit(caller(request), event);
        return ResponseEntity.status("STORED".equals(receipt.outcome()) ? 200 : 503)
                .cacheControl(CacheControl.noStore()).body(receipt);
    }

    private static OAuthAuthorityService.Caller caller(HttpServletRequest request) {
        Object attribute = request.getAttribute(OAuthAuthorityAuthenticationFilter.CALLER_ATTRIBUTE);
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(attribute instanceof OAuthAuthorityService.Caller caller)
                || !(authentication instanceof IdpAuthenticationToken verified) || !verified.isAuthenticated()
                || verified.getPrincipal() != caller.principal() || !verified.verifiedIssuer().equals(caller.realm().getIssuer())) {
            throw new AccessDeniedException("AUTHORITY_SERVICE_REQUIRED");
        }
        return caller;
    }
}
