package top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import java.util.Map;
import java.util.Set;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ResourceGrantType;

/** Input for adding or deleting Client Resource Grants for explicit applications. */
@Data
@NoArgsConstructor
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Accessors(chain = true)
public class BatchClientResourceGrantDTO {

    @PermissionResource(key = "tianquan-shoubing.field.BatchClientResourceGrantDTO.bizCode", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.bizCode")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @NotBlank
    private String bizCode;
    @PermissionResource(key = "tianquan-shoubing.field.BatchClientResourceGrantDTO.environment", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.environment")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @NotBlank
    private String environment;
    @PermissionResource(key = "tianquan-shoubing.field.BatchClientResourceGrantDTO.appCodes", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.appCodes")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @NotEmpty
    private List<@NotBlank String> appCodes;
    @PermissionResource(key = "tianquan-shoubing.field.BatchClientResourceGrantDTO.action", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.action")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @NotNull
    private Action action;
    @PermissionResource(key = "tianquan-shoubing.field.BatchClientResourceGrantDTO.grantType", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.grantType")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @NotNull
    private ResourceGrantType grantType;
    @PermissionResource(key = "tianquan-shoubing.field.BatchClientResourceGrantDTO.tenantId", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.tenantId")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    private String tenantId;
    @PermissionResource(key = "tianquan-shoubing.field.BatchClientResourceGrantDTO.allowedScopes", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.allowedScopes")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @NotNull
    private Set<String> allowedScopes;
    @PermissionResource(key = "tianquan-shoubing.field.BatchClientResourceGrantDTO.expectedResourceVersions", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.expectedResourceVersions")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @NotNull
    private Map<String, Long> expectedResourceVersions;
    @PermissionResource(key = "tianquan-shoubing.field.BatchClientResourceGrantDTO.expectedGrantVersions", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.expectedGrantVersions")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.OBJECT,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_GRANT))
    @NotNull
    private Map<String, Long> expectedGrantVersions;

    /** Builds an input with defensive copies of its collections. */
    @Builder
    public static BatchClientResourceGrantDTO of(String bizCode, String environment, List<String> appCodes,
            Action action, ResourceGrantType grantType, String tenantId, Set<String> allowedScopes,
            Map<String, Long> expectedResourceVersions, Map<String, Long> expectedGrantVersions) {
        return new BatchClientResourceGrantDTO(bizCode, environment,
                appCodes == null ? null : List.copyOf(appCodes), action, grantType, tenantId,
                allowedScopes == null ? null : Set.copyOf(allowedScopes),
                expectedResourceVersions == null ? null : Map.copyOf(expectedResourceVersions),
                expectedGrantVersions == null ? null : Map.copyOf(expectedGrantVersions));
    }

    public List<String> getAppCodes() {
        return appCodes == null ? null : List.copyOf(appCodes);
    }

    public BatchClientResourceGrantDTO setAppCodes(List<String> values) {
        this.appCodes = values == null ? null : List.copyOf(values);
        return this;
    }

    public Set<String> getAllowedScopes() {
        return allowedScopes == null ? null : Set.copyOf(allowedScopes);
    }

    public BatchClientResourceGrantDTO setAllowedScopes(Set<String> values) {
        this.allowedScopes = values == null ? null : Set.copyOf(values);
        return this;
    }

    public Map<String, Long> getExpectedResourceVersions() {
        return expectedResourceVersions == null ? null : Map.copyOf(expectedResourceVersions);
    }

    public BatchClientResourceGrantDTO setExpectedResourceVersions(Map<String, Long> values) {
        this.expectedResourceVersions = values == null ? null : Map.copyOf(values);
        return this;
    }

    public Map<String, Long> getExpectedGrantVersions() {
        return expectedGrantVersions == null ? null : Map.copyOf(expectedGrantVersions);
    }

    public BatchClientResourceGrantDTO setExpectedGrantVersions(Map<String, Long> values) {
        this.expectedGrantVersions = values == null ? null : Map.copyOf(values);
        return this;
    }

    /** Grant batch action. */
    public enum Action {
        /** Create or update per-application Grants. */
        UPSERT,
        /** Delete per-application Grants. */
        DELETE
    }
}
