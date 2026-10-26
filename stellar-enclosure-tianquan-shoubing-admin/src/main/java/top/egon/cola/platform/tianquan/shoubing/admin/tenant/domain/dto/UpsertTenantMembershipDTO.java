package top.egon.cola.platform.tianquan.shoubing.admin.tenant.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import jakarta.validation.constraints.NotNull;
import top.egon.cola.platform.tianquan.shoubing.admin.tenant.domain.bo.IdentityTenantMembershipBO;

/** Idempotent membership target state and optional create/version token. */
public record UpsertTenantMembershipDTO(
        @PermissionResource(key = "tianquan-shoubing.field.UpsertTenantMembershipDTO.status", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.status")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_MANAGE))
        @NotNull IdentityTenantMembershipBO.Status status,
        @PermissionResource(key = "tianquan-shoubing.field.UpsertTenantMembershipDTO.expectedVersion", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.expectedVersion")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                write = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_MANAGE))
        Long expectedVersion
) {
}
