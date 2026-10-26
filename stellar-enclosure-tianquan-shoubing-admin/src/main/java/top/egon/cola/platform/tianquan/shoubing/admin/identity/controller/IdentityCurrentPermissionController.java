package top.egon.cola.platform.tianquan.shoubing.admin.identity.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import top.egon.cola.component.common.core.pojo.ResultRecord;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.*;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.jianshen.starter.permission.*;

/** Current USER metadata for this host's fixed catalog and executing build. */
@RestController
@io.swagger.v3.oas.annotations.tags.Tag(name="identity-authorization",description="统一身份权限视图")
@top.egon.cola.component.yuheng.openapi.annotation.EgonApiCatalog(businessDomainCode="xingyuan",businessDomainName="平台治理域",
        entityDomainCode="identity-auth",entityDomainName="统一身份认证上下文域",interfaceGroupCode="tianquan-shoubing-auth")
public class IdentityCurrentPermissionController {
    private static final String KEY="tianquan-shoubing.api.authorization.current";
    private final CurrentEffectivePermissionView permissions;
    public IdentityCurrentPermissionController(CurrentEffectivePermissionView permissions) { this.permissions=permissions; }

    @io.swagger.v3.oas.annotations.Operation(operationId="tianquan-shoubing-identity-current-permissions-v1",summary="查询当前身份的有效权限",tags={"tianquan-shoubing","identity"})
    @top.egon.cola.component.yuheng.openapi.annotation.EgonGatewayPolicy(exposure=top.egon.cola.component.yuheng.openapi.annotation.EgonGatewayPolicy.Exposure.EXTERNAL)
    @GetMapping("/api/v1/authorization/effective-permissions")
    @PermissionResource(key=KEY,type=ResourceType.API,labelPage="identity.permissions",labelKey="api.authorization.current",
            access=ResourceAccess.PUBLIC,allowedPrincipals=PermissionManifest.PrincipalType.USER)
    public ResponseEntity<ResultRecord<EffectivePermissionSnapshot>> current(HttpServletRequest request) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(ResultRecord.success(permissions.current(request,KEY)));
    }
}
