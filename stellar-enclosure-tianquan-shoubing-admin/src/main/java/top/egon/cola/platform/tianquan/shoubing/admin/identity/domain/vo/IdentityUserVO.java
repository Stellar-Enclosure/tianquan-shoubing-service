package top.egon.cola.platform.tianquan.shoubing.admin.identity.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import java.time.Instant;

/**
 * 管理端展示的统一身份用户信息。
 *
 * <p>Identity-user information returned by administration APIs.</p>
 */
public record IdentityUserVO(
        @PermissionResource(key = "tianquan-shoubing.field.IdentityUserVO.subject", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.subject")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_READ))
        String subject,
        @PermissionResource(key = "tianquan-shoubing.field.IdentityUserVO.username", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.username")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_READ))
        String username,
        @PermissionResource(key = "tianquan-shoubing.field.IdentityUserVO.displayName", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.displayName")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_READ))
        String displayName,
        @PermissionResource(key = "tianquan-shoubing.field.IdentityUserVO.status", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.status")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_READ))
        String status,
        @PermissionResource(key = "tianquan-shoubing.field.IdentityUserVO.failedLoginCount", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.failedLoginCount")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_READ))
        int failedLoginCount,
        @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
        @PermissionResource(key = "tianquan-shoubing.field.IdentityUserVO.lockedUntil", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.lockedUntil")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_READ))
        Instant lockedUntil,
        @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
        @PermissionResource(key = "tianquan-shoubing.field.IdentityUserVO.lastLoginAt", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.lastLoginAt")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_READ))
        Instant lastLoginAt,
        @PermissionResource(key = "tianquan-shoubing.field.IdentityUserVO.version", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.version")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_USER_READ))
        long version
) {
}
