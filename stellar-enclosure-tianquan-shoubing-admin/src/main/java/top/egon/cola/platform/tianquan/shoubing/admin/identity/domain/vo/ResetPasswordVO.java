package top.egon.cola.platform.tianquan.shoubing.admin.identity.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

/**
 * 密码重置结果及新的安全版本信息。
 *
 * <p>Password-reset result together with the new security-version information.</p>
 */
public record ResetPasswordVO(
        @PermissionResource(key = "tianquan-shoubing.field.ResetPasswordVO.subject", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.subject")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_PASSWORD_RESET))
        String subject,
        @PermissionResource(key = "tianquan-shoubing.field.ResetPasswordVO.oneTimePassword", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.oneTimePassword")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_PASSWORD_RESET))
        String oneTimePassword,
        @PermissionResource(key = "tianquan-shoubing.field.ResetPasswordVO.mustChangePassword", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.mustChangePassword")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.BOOLEAN,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_PASSWORD_RESET))
        boolean mustChangePassword
) {
}
