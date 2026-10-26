package top.egon.cola.platform.tianquan.shoubing.admin.identity.controller;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.RequiresPermissions;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import top.egon.cola.component.yuheng.openapi.annotation.EgonApiCatalog;
import top.egon.cola.component.yuheng.openapi.annotation.EgonGatewayPolicy;
import top.egon.cola.platform.tianquan.shoubing.admin.support.security.IdpAdminAuthorizationPort;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;

import java.util.Objects;

@RestController
@Tag(name = "identity-profile-me", description = "统一身份本人信息接口组")
@EgonApiCatalog(
        businessDomainCode = "xingyuan",
        businessDomainName = "平台治理域",
        entityDomainCode = "identity-profile",
        entityDomainName = "统一身份本人信息域",
        interfaceGroupCode = "tianquan-shoubing-profile"
)

public class IdentityProfileController {

    private final IdpAdminAuthorizationPort authorization;

    public IdentityProfileController(
            IdpAdminAuthorizationPort authorization
    ) {
        this.authorization = Objects.requireNonNull(
                authorization,
                "authorization"
        );
    }

    @PermissionResource(key = "tianquan-shoubing.api.identityProfile.me", type = ResourceType.API,
            labelPage = "identity.permissions", labelKey = "api.identityProfile.me")
    @RequiresPermissions(codes = IdentityPermissionCodes.IDENTITY_SELF_READ)
    @GetMapping("/api/v1/tianquan-shoubing/me")
    @Operation(
            operationId = "tianquan-shoubing-identity-me-v1",
            summary = "查询当前统一身份",
            tags = {"tianquan-shoubing", "identity"}
    )
    @EgonGatewayPolicy(
            exposure = EgonGatewayPolicy.Exposure.EXTERNAL
    )
    public IdentityPrincipal me(
            @AuthenticationPrincipal(expression = "identity()") IdentityPrincipal principal
    ) {
        authorization.require(principal, "tianquan-shoubing:identity:self:read");
        return Objects.requireNonNull(principal, "principal");
    }

}
