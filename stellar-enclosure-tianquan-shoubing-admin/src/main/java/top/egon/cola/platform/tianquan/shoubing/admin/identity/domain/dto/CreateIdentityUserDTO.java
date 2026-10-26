package top.egon.cola.platform.tianquan.shoubing.admin.identity.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import jakarta.validation.constraints.NotBlank;

/**
 * 创建统一身份用户的输入数据。
 *
 * <p>Input data for creating an identity user.</p>
 */
public record CreateIdentityUserDTO(
        @PermissionResource(key = "tianquan-shoubing.field.CreateIdentityUserDTO.username", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.username")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_CREATE))
        @NotBlank String username,
        @PermissionResource(key = "tianquan-shoubing.field.CreateIdentityUserDTO.displayName", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.displayName")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_CREATE))
        @NotBlank String displayName
) {
}
