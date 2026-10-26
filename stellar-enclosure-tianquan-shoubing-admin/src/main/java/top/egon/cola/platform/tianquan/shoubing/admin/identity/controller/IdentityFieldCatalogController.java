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
public class IdentityFieldCatalogController {
    private static final String KEY="tianquan-shoubing.api.authorization.fields";
    private final PermissionFieldCatalog fields;
    private final org.springframework.beans.factory.ObjectProvider<org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter> adapters;
    private final org.springframework.beans.factory.ObjectProvider<org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping> routes;
    public IdentityFieldCatalogController(PermissionFieldCatalog fields,
            @org.springframework.beans.factory.annotation.Qualifier("requestMappingHandlerAdapter") org.springframework.beans.factory.ObjectProvider<org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter> adapters,
            @org.springframework.beans.factory.annotation.Qualifier("requestMappingHandlerMapping") org.springframework.beans.factory.ObjectProvider<org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping> routes) {
        this.fields=fields;this.adapters=adapters;this.routes=routes;
    }

    @io.swagger.v3.oas.annotations.Operation(operationId="tianquan-shoubing-identity-field-catalog-v1",summary="查询当前目录的字段策略与输入绑定",tags={"tianquan-shoubing","identity"})
    @top.egon.cola.component.yuheng.openapi.annotation.EgonGatewayPolicy(exposure=top.egon.cola.component.yuheng.openapi.annotation.EgonGatewayPolicy.Exposure.EXTERNAL)
    @GetMapping("/api/v1/authorization/field-catalog")
    @PermissionResource(key=KEY,type=ResourceType.API,labelPage="identity.permissions",labelKey="api.authorization.fields",
            access=ResourceAccess.PUBLIC,allowedPrincipals=PermissionManifest.PrincipalType.USER)
    public ResponseEntity<ResultRecord<FieldCatalogSnapshot>> current(HttpServletRequest request) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(ResultRecord.success(fields.currentForHttp(request,KEY,
                adapters.getObject().getMessageConverters(),routes.getObject().getHandlerMethods().values(),
                java.util.Set.of("top.egon.cola.platform.tianquan.shoubing.admin."),java.util.Set.of())));
    }
}
