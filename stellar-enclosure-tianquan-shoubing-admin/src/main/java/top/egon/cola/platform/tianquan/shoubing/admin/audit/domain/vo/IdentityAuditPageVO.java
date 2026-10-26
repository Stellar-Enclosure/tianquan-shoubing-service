package top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import java.util.List;

/**
 * 身份安全审计的分页结果。
 *
 * <p>Paginated identity security-audit result.</p>
 */
public record IdentityAuditPageVO(
        @PermissionResource(key = "tianquan-shoubing.field.IdentityAuditPageVO.content", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.content")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.AUDIT_READ))
        List<IdentityAuditVO> content,
        @PermissionResource(key = "tianquan-shoubing.field.IdentityAuditPageVO.page", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.page")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.AUDIT_READ))
        int page,
        @PermissionResource(key = "tianquan-shoubing.field.IdentityAuditPageVO.size", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.size")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.AUDIT_READ))
        int size,
        @PermissionResource(key = "tianquan-shoubing.field.IdentityAuditPageVO.totalElements", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.totalElements")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.AUDIT_READ))
        long totalElements,
        @PermissionResource(key = "tianquan-shoubing.field.IdentityAuditPageVO.totalPages", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.totalPages")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.AUDIT_READ))
        int totalPages
) {
}
