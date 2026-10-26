package top.egon.cola.platform.tianquan.shoubing.admin.identity.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityUserStatus;

/**
 * 更新统一身份用户的输入数据。
 *
 * <p>Input data for updating an identity user.</p>
 */
public record UpdateIdentityUserDTO(
        @PermissionResource(key = "tianquan-shoubing.field.UpdateIdentityUserDTO.displayName", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.displayName")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_UPDATE))
        @NotBlank String displayName,
        @PermissionResource(key = "tianquan-shoubing.field.UpdateIdentityUserDTO.status", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.status")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_UPDATE))
        @NotNull IdentityUserStatus status,
        @PermissionResource(key = "tianquan-shoubing.field.UpdateIdentityUserDTO.expectedVersion", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.expectedVersion")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                write = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_UPDATE))
        @PositiveOrZero long expectedVersion
) {
}
