package top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ResourceGrantType;

/** Input for deleting a Client Resource Grant. */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@Builder
public class DeleteClientResourceGrantDTO {

    @PermissionResource(key = "tianquan-shoubing.field.DeleteClientResourceGrantDTO.grantType", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.grantType")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @NotNull
    private ResourceGrantType grantType;
    @PermissionResource(key = "tianquan-shoubing.field.DeleteClientResourceGrantDTO.tenantId", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.tenantId")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    private String tenantId;
    @PermissionResource(key = "tianquan-shoubing.field.DeleteClientResourceGrantDTO.expectedResourceVersion", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.expectedResourceVersion")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @PositiveOrZero
    private long expectedResourceVersion;
    @PermissionResource(key = "tianquan-shoubing.field.DeleteClientResourceGrantDTO.expectedGrantVersion", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.expectedGrantVersion")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @PositiveOrZero
    private long expectedGrantVersion;
}
