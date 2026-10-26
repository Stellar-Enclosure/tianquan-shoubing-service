package top.egon.cola.platform.tianquan.shoubing.admin.tenant.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;
import top.egon.cola.platform.tianquan.shoubing.admin.tenant.domain.bo.IdentityTenantBO;

/** Versioned patch for an Tianquan-Shoubing-owned tenant catalog row. */
public record UpdateTenantDTO(
        @PermissionResource(key = "tianquan-shoubing.field.UpdateTenantDTO.expectedVersion", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.expectedVersion")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                write = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_MANAGE))
        @NotNull
        @PositiveOrZero
        Long expectedVersion,
        @PermissionResource(key = "tianquan-shoubing.field.UpdateTenantDTO.tenantName", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.tenantName")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_MANAGE))
        @Size(max = 200)
        String tenantName,
        @PermissionResource(key = "tianquan-shoubing.field.UpdateTenantDTO.settings", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.settings")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                write = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_MANAGE))
        JsonNode settings,
        @PermissionResource(key = "tianquan-shoubing.field.UpdateTenantDTO.status", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.status")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_MANAGE))
        @NotNull
        IdentityTenantBO.Status status
) {
}
