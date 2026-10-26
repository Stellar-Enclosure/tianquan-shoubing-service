package top.egon.cola.platform.tianquan.shoubing.admin.tenant.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import top.egon.cola.platform.tianquan.shoubing.admin.tenant.domain.bo.IdentityTenantBO;

import java.time.Instant;

/** Safe Tianquan-Shoubing tenant catalog view; no RBAC or credential fields are exposed. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TenantVO(
        @PermissionResource(key = "tianquan-shoubing.field.TenantVO.tenantId", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.tenantId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_READ))
        String tenantId,
        @PermissionResource(key = "tianquan-shoubing.field.TenantVO.tenantCode", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.tenantCode")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_READ))
        String tenantCode,
        @PermissionResource(key = "tianquan-shoubing.field.TenantVO.tenantName", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.tenantName")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_READ))
        String tenantName,
        @PermissionResource(key = "tianquan-shoubing.field.TenantVO.status", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.status")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_READ))
        IdentityTenantBO.Status status,
        @PermissionResource(key = "tianquan-shoubing.field.TenantVO.settings", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.settings")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_READ))
        JsonNode settings,
        @PermissionResource(key = "tianquan-shoubing.field.TenantVO.version", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.version")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_READ))
        long version,
        @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
        @PermissionResource(key = "tianquan-shoubing.field.TenantVO.createdAt", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.createdAt")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_READ))
        Instant createdAt,
        @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
        @PermissionResource(key = "tianquan-shoubing.field.TenantVO.updatedAt", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.updatedAt")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_READ))
        Instant updatedAt
) {
}
