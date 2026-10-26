package top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

/** Safe Client Resource Grant administration view. */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ClientResourceGrantVO {

    @PermissionResource(key = "tianquan-shoubing.field.ClientResourceGrantVO.clientId", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.clientId")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @NotBlank
    @Size(max = 128)
    private String clientId;
    @PermissionResource(key = "tianquan-shoubing.field.ClientResourceGrantVO.resourceServerId", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.resourceServerId")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @NotBlank
    @Size(max = 128)
    private String resourceServerId;
    @PermissionResource(key = "tianquan-shoubing.field.ClientResourceGrantVO.grantType", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.grantType")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @NotBlank
    @Size(max = 32)
    private String grantType;
    @PermissionResource(key = "tianquan-shoubing.field.ClientResourceGrantVO.tenantId", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.tenantId")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @Size(max = 32)
    private String tenantId;
    @PermissionResource(key = "tianquan-shoubing.field.ClientResourceGrantVO.allowedScopes", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.allowedScopes")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @Size(max = 64)
    private Set<@NotBlank @Size(max = 256) String> allowedScopes;
    @PermissionResource(key = "tianquan-shoubing.field.ClientResourceGrantVO.status", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.status")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @NotBlank
    @Size(max = 16)
    private String status;
    @PermissionResource(key = "tianquan-shoubing.field.ClientResourceGrantVO.version", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.version")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @PositiveOrZero
    private long version;
}
