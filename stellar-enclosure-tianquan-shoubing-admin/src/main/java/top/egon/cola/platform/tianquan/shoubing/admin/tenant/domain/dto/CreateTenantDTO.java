package top.egon.cola.platform.tianquan.shoubing.admin.tenant.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Input for creating an Tianquan-Shoubing-owned tenant catalog row. */
public record CreateTenantDTO(
        @PermissionResource(key = "tianquan-shoubing.field.CreateTenantDTO.tenantCode", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.tenantCode")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_MANAGE))
        @NotBlank
        @Pattern(regexp = "^[a-z][a-z0-9-]{2,63}$")
        String tenantCode,
        @PermissionResource(key = "tianquan-shoubing.field.CreateTenantDTO.tenantName", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.tenantName")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_MANAGE))
        @NotBlank
        @Size(max = 200)
        String tenantName,
        @PermissionResource(key = "tianquan-shoubing.field.CreateTenantDTO.settings", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.settings")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
                write = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_MANAGE))
        JsonNode settings
) {
}
