package top.egon.cola.platform.tianquan.shoubing.admin.tenant.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import com.fasterxml.jackson.annotation.JsonInclude;
import top.egon.cola.platform.tianquan.shoubing.admin.tenant.domain.bo.IdentityTenantMembershipBO;

import java.time.Instant;

/** Safe tenant membership view with an optional path-owner tenant id. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TenantMembershipVO(
        @PermissionResource(key = "tianquan-shoubing.field.TenantMembershipVO.tenantId", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.tenantId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_READ))
        String tenantId,
        @PermissionResource(key = "tianquan-shoubing.field.TenantMembershipVO.identitySub", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.identitySub")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_READ))
        String identitySub,
        @PermissionResource(key = "tianquan-shoubing.field.TenantMembershipVO.displayName", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.displayName")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_READ))
        String displayName,
        @PermissionResource(key = "tianquan-shoubing.field.TenantMembershipVO.status", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.status")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_READ))
        IdentityTenantMembershipBO.Status status,
        @PermissionResource(key = "tianquan-shoubing.field.TenantMembershipVO.version", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.version")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_READ))
        long version,
        @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
        @PermissionResource(key = "tianquan-shoubing.field.TenantMembershipVO.updatedAt", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.updatedAt")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                plainRead = @PermissionGroup(codes = IdentityPermissionCodes.TENANT_READ))
        Instant updatedAt
) {
}
