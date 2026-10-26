package top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

/** Resource Server administration view. */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ResourceServerVO {

    @PermissionResource(key = "tianquan-shoubing.field.ResourceServerVO.resourceServerId", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.resourceServerId")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_READ))
    @NotBlank @Size(max = 128)
    private String resourceServerId;
    @PermissionResource(key = "tianquan-shoubing.field.ResourceServerVO.resourceUri", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.resourceUri")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_READ))
    @NotBlank @Size(max = 2048)
    private String resourceUri;
    @PermissionResource(key = "tianquan-shoubing.field.ResourceServerVO.bizCode", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.bizCode")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_READ))
    @NotBlank @Size(max = 128)
    private String bizCode;
    @PermissionResource(key = "tianquan-shoubing.field.ResourceServerVO.appCode", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.appCode")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_READ))
    @NotBlank @Size(max = 128)
    private String appCode;
    @PermissionResource(key = "tianquan-shoubing.field.ResourceServerVO.environment", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.environment")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_READ))
    @NotBlank @Size(max = 128)
    private String environment;
    @PermissionResource(key = "tianquan-shoubing.field.ResourceServerVO.displayName", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.displayName")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_READ))
    @NotBlank @Size(max = 200)
    private String displayName;
    @PermissionResource(key = "tianquan-shoubing.field.ResourceServerVO.managementClientId", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.managementClientId")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_READ))
    @NotBlank @Size(max = 128)
    private String managementClientId;
    @PermissionResource(key = "tianquan-shoubing.field.ResourceServerVO.rbacApplicationCode", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.rbacApplicationCode")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_READ))
    @NotBlank @Size(max = 128)
    private String rbacApplicationCode;
    @PermissionResource(key = "tianquan-shoubing.field.ResourceServerVO.entryPermissionCode", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.entryPermissionCode")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_READ))
    @NotBlank @Size(max = 256)
    private String entryPermissionCode;
    @PermissionResource(key = "tianquan-shoubing.field.ResourceServerVO.status", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.status")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_READ))
    @NotBlank @Size(max = 16)
    private String status;
    @PermissionResource(key = "tianquan-shoubing.field.ResourceServerVO.version", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.version")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_READ))
    @PositiveOrZero
    private long version;
    @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
    @PermissionResource(key = "tianquan-shoubing.field.ResourceServerVO.createdAt", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.createdAt")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_READ))
    private Instant createdAt;
    @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
    @PermissionResource(key = "tianquan-shoubing.field.ResourceServerVO.updatedAt", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.updatedAt")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_READ))
    private Instant updatedAt;
}
