package top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import jakarta.validation.constraints.NotBlank;

/**
 * 创建应用环境级 Resource Server 的输入。
 *
 * <p>Input for creating an application-and-environment scoped Resource Server.</p>
 *
 * @param resourceServerId 稳定标识；stable identifier
 * @param resourceUri RFC 8707 Resource URI；RFC 8707 Resource URI
 * @param bizCode 业务域编码；business-domain code
 * @param appCode 应用编码；application code
 * @param environment 环境；environment
 * @param displayName 展示名称；display name
 * @param managementClientId 管理和机器身份 Client；management and machine-identity Client
 * @param rbacApplicationCode USER 入口权限所属应用；application owning USER entry permission
 * @param entryPermissionCode USER 入口权限；USER entry permission
 */
public record CreateResourceServerDTO(
        @PermissionResource(key = "tianquan-shoubing.field.CreateResourceServerDTO.resourceServerId", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.resourceServerId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_CREATE))
        @NotBlank String resourceServerId,
        @PermissionResource(key = "tianquan-shoubing.field.CreateResourceServerDTO.resourceUri", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.resourceUri")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_CREATE))
        @NotBlank String resourceUri,
        @PermissionResource(key = "tianquan-shoubing.field.CreateResourceServerDTO.bizCode", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.bizCode")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_CREATE))
        @NotBlank String bizCode,
        @PermissionResource(key = "tianquan-shoubing.field.CreateResourceServerDTO.appCode", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.appCode")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_CREATE))
        @NotBlank String appCode,
        @PermissionResource(key = "tianquan-shoubing.field.CreateResourceServerDTO.environment", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.environment")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_CREATE))
        @NotBlank String environment,
        @PermissionResource(key = "tianquan-shoubing.field.CreateResourceServerDTO.displayName", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.displayName")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_CREATE))
        @NotBlank String displayName,
        @PermissionResource(key = "tianquan-shoubing.field.CreateResourceServerDTO.managementClientId", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.managementClientId")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_CREATE))
        @NotBlank String managementClientId,
        @PermissionResource(key = "tianquan-shoubing.field.CreateResourceServerDTO.rbacApplicationCode", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.rbacApplicationCode")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_CREATE))
        @NotBlank String rbacApplicationCode,
        @PermissionResource(key = "tianquan-shoubing.field.CreateResourceServerDTO.entryPermissionCode", type = ResourceType.FIELD,
                labelPage = "identity.permissions", labelKey = "field.entryPermissionCode")
        @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
                write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_CREATE))
        @NotBlank String entryPermissionCode
) {
}
