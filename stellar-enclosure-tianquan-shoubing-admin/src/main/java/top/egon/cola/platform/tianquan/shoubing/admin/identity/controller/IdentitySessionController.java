package top.egon.cola.platform.tianquan.shoubing.admin.identity.controller;

import io.swagger.v3.oas.annotations.Operation;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import top.egon.cola.component.yuheng.openapi.annotation.EgonApiCatalog;
import top.egon.cola.component.yuheng.openapi.annotation.EgonGatewayPolicy;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.RequiresPermissions;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.vo.OAuthDeviceSessionVO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthDeviceSessionService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthManagementRealmResolver;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;
import top.egon.cola.platform.tianquan.shoubing.admin.support.security.IdpAdminAuthorizationPort;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;

@RestController
@RequiredArgsConstructor
@EgonApiCatalog(businessDomainCode = "xingyuan", businessDomainName = "平台治理域",
        entityDomainCode = "identity-profile", entityDomainName = "统一身份本人信息域", interfaceGroupCode = "tianquan-shoubing-profile")
public class IdentitySessionController {
    @Qualifier("oauthDeviceSessionService") private final OAuthDeviceSessionService sessions;
    @Qualifier("oauthManagementRealmResolver") private final OAuthManagementRealmResolver realms;
    private final IdpAdminAuthorizationPort authorization;

    @PermissionResource(key = "tianquan-shoubing.api.identitySession.list", type = ResourceType.API,
            labelPage = "identity.permissions", labelKey = "api.identitySession.list")
    @RequiresPermissions(codes = IdentityPermissionCodes.IDENTITY_SELF_READ)
    @GetMapping("/api/v1/tianquan-shoubing/me/sessions")
    @Operation(operationId = "tianquan-shoubing-identity-sessions-v1", summary = "查看本人登录设备会话")
    @EgonGatewayPolicy(exposure = EgonGatewayPolicy.Exposure.EXTERNAL)
    public ResponseEntity<List<OAuthDeviceSessionVO>> list(@AuthenticationPrincipal(expression = "identity()") IdentityPrincipal principal) {
        authorization.require(principal, IdentityPermissionCodes.IDENTITY_SELF_READ);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(sessions.list(realms.resolve(principal, null), principal.subject()));
    }

    @PermissionResource(key = "tianquan-shoubing.api.identitySession.revoke", type = ResourceType.API,
            labelPage = "identity.permissions", labelKey = "api.identitySession.revoke")
    @RequiresPermissions(codes = IdentityPermissionCodes.IDENTITY_SELF_SESSION_REVOKE)
    @PostMapping("/api/v1/tianquan-shoubing/me/sessions/{sessionId:[1-9][0-9]{0,18}}/revoke")
    @Operation(operationId = "tianquan-shoubing-identity-session-revoke-v1", summary = "踢出本人的一个设备会话")
    @EgonGatewayPolicy(exposure = EgonGatewayPolicy.Exposure.EXTERNAL)
    public ResponseEntity<Void> revoke(@AuthenticationPrincipal(expression = "identity()") IdentityPrincipal principal,
            @PathVariable long sessionId) {
        authorization.require(principal, IdentityPermissionCodes.IDENTITY_SELF_SESSION_REVOKE);
        sessions.revoke(realms.resolve(principal, null), principal.subject(), sessionId);
        return ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build();
    }
}
