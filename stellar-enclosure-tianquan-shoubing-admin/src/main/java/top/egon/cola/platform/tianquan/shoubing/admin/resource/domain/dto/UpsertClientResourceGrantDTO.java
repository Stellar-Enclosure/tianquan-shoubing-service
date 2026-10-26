package top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.PositiveOrZero;
import java.util.Set;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ResourceGrantType;

/** Input for creating or updating one application-level Client Resource Grant. */
@Data
@NoArgsConstructor
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Accessors(chain = true)
public class UpsertClientResourceGrantDTO {

    @PermissionResource(key = "tianquan-shoubing.field.UpsertClientResourceGrantDTO.grantType", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.grantType")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @NotNull
    private ResourceGrantType grantType;
    @PermissionResource(key = "tianquan-shoubing.field.UpsertClientResourceGrantDTO.tenantId", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.tenantId")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    private String tenantId;
    @PermissionResource(key = "tianquan-shoubing.field.UpsertClientResourceGrantDTO.allowedScopes", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.allowedScopes")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @NotNull
    @Size(max = 64)
    private Set<@NotBlank @Size(max = 128) @Pattern(regexp = "[A-Za-z0-9._:-]{1,128}") String> allowedScopes;
    @PermissionResource(key = "tianquan-shoubing.field.UpsertClientResourceGrantDTO.expectedResourceVersion", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.expectedResourceVersion")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @PositiveOrZero
    private long expectedResourceVersion;
    @PermissionResource(key = "tianquan-shoubing.field.UpsertClientResourceGrantDTO.expectedGrantVersion", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.expectedGrantVersion")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @PositiveOrZero
    private Long expectedGrantVersion;

    /** Builds a request with a defensive copy of its scope set. */
    @Builder
    public static UpsertClientResourceGrantDTO of(ResourceGrantType grantType, String tenantId,
            Set<String> allowedScopes, long expectedResourceVersion, Long expectedGrantVersion) {
        return new UpsertClientResourceGrantDTO(grantType, tenantId,
                allowedScopes == null ? null : Set.copyOf(allowedScopes),
                expectedResourceVersion, expectedGrantVersion);
    }

    public Set<String> getAllowedScopes() {
        return allowedScopes == null ? null : Set.copyOf(allowedScopes);
    }

    public UpsertClientResourceGrantDTO setAllowedScopes(Set<String> values) {
        this.allowedScopes = values == null ? null : Set.copyOf(values);
        return this;
    }
}
