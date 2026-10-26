package top.egon.cola.platform.tianquan.shoubing.admin.identity.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

/**
 * 新建身份用户及其一次性初始密码。
 *
 * <p>Newly created identity user together with its one-time initial password.</p>
 */
public record CreatedIdentityUserVO(
        @PermissionResource(key = "tianquan-shoubing.field.CreatedIdentityUserVO.subject", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.subject")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_CREATE))
        String subject,
        @PermissionResource(key = "tianquan-shoubing.field.CreatedIdentityUserVO.username", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.username")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_CREATE))
        String username,
        @PermissionResource(key = "tianquan-shoubing.field.CreatedIdentityUserVO.displayName", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.displayName")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_CREATE))
        String displayName,
        @PermissionResource(key = "tianquan-shoubing.field.CreatedIdentityUserVO.status", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.status")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_CREATE))
        String status,
        @PermissionResource(key = "tianquan-shoubing.field.CreatedIdentityUserVO.oneTimePassword", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.oneTimePassword")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_CREATE))
        String oneTimePassword
) {
}
