package top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.vo;

import com.fasterxml.jackson.annotation.JsonFormat;
import java.time.Instant;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

/** Login metadata only; credential and browser-binding digests never leave the owner. */
public record OAuthDeviceSessionVO(
        @PermissionResource(key = "tianquan-shoubing.field.OAuthDeviceSessionVO.sessionId", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.sessionId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_SELF_READ))
        String sessionId,
        @PermissionResource(key = "tianquan-shoubing.field.OAuthDeviceSessionVO.clientId", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.clientId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_SELF_READ))
        String clientId,
        @PermissionResource(key = "tianquan-shoubing.field.OAuthDeviceSessionVO.clientName", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.clientName")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_SELF_READ))
        String clientName,
        @PermissionResource(key = "tianquan-shoubing.field.OAuthDeviceSessionVO.channel", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.channel")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_SELF_READ))
        String channel,
        @PermissionResource(key = "tianquan-shoubing.field.OAuthDeviceSessionVO.platform", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.platform")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_SELF_READ))
        String platform,
        @PermissionResource(key = "tianquan-shoubing.field.OAuthDeviceSessionVO.userAgent", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.userAgent")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_SELF_READ))
        String userAgent,
        @PermissionResource(key = "tianquan-shoubing.field.OAuthDeviceSessionVO.ipAddress", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.ipAddress")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_SELF_READ))
        String ipAddress,
        @JsonFormat(shape = JsonFormat.Shape.STRING)
        @PermissionResource(key = "tianquan-shoubing.field.OAuthDeviceSessionVO.authenticatedAt", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.authenticatedAt")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_SELF_READ))
        Instant authenticatedAt,
        @JsonFormat(shape = JsonFormat.Shape.STRING)
        @PermissionResource(key = "tianquan-shoubing.field.OAuthDeviceSessionVO.expiresAt", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.expiresAt")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.IDENTITY_SELF_READ))
        Instant expiresAt
) {
}
