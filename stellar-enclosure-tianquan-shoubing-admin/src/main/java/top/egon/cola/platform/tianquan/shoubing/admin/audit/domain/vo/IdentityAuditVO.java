package top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import java.time.Instant;

/**
 * 对管理端安全展示的身份审计记录。
 *
 * <p>Identity audit record exposed safely to administration clients.</p>
 */
public record IdentityAuditVO(
        @PermissionResource(key = "tianquan-shoubing.field.IdentityAuditVO.id", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.id")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.AUDIT_READ))
        String id,
        @PermissionResource(key = "tianquan-shoubing.field.IdentityAuditVO.eventType", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.eventType")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.AUDIT_READ))
        String eventType,
        @PermissionResource(key = "tianquan-shoubing.field.IdentityAuditVO.actorSub", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.actorSub")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.AUDIT_READ))
        String actorSub,
        @PermissionResource(key = "tianquan-shoubing.field.IdentityAuditVO.targetSub", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.targetSub")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.AUDIT_READ))
        String targetSub,
        @PermissionResource(key = "tianquan-shoubing.field.IdentityAuditVO.result", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.result")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.AUDIT_READ))
        String result,
        @PermissionResource(key = "tianquan-shoubing.field.IdentityAuditVO.reason", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.reason")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.AUDIT_READ))
        String reason,
        @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
        @PermissionResource(key = "tianquan-shoubing.field.IdentityAuditVO.occurredAt", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.occurredAt")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.AUDIT_READ))
        Instant occurredAt
) {
}
