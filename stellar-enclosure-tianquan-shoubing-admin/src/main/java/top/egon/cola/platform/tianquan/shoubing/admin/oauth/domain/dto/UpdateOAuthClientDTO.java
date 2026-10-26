package top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;

/** OAuth client update input. */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@Builder
public class UpdateOAuthClientDTO {

    @PermissionResource(key = "tianquan-shoubing.field.UpdateOAuthClientDTO.clientName", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.clientName")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_UPDATE))
    @NotBlank
    @Size(max = 200)
    private String clientName;

    @PermissionResource(key = "tianquan-shoubing.field.UpdateOAuthClientDTO.status", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.status")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_UPDATE))
    @NotNull
    private OAuthClient.Status status;

    @PermissionResource(key = "tianquan-shoubing.field.UpdateOAuthClientDTO.accessTokenTtlSeconds", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.accessTokenTtlSeconds")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_UPDATE))
    @Min(300)
    @Max(600)
    private int accessTokenTtlSeconds;

    @PermissionResource(key = "tianquan-shoubing.field.UpdateOAuthClientDTO.refreshTokenTtlSeconds", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.refreshTokenTtlSeconds")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_UPDATE))
    @Min(0)
    @Max(604800)
    private int refreshTokenTtlSeconds;

    @PermissionResource(key = "tianquan-shoubing.field.UpdateOAuthClientDTO.expectedVersion", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.expectedVersion")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_UPDATE))
    @PositiveOrZero
    private long expectedVersion;

    @PermissionResource(key = "tianquan-shoubing.field.UpdateOAuthClientDTO.allowedScopes", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.allowedScopes")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_UPDATE))
    @Size(max = 64)
    private List<@NotBlank @Pattern(regexp = "[A-Za-z0-9._:-]{1,128}") String> allowedScopes;

    @PermissionResource(key = "tianquan-shoubing.field.UpdateOAuthClientDTO.browserBound", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.browserBound")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.BOOLEAN,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_UPDATE))
    private Boolean browserBound;

    @PermissionResource(key = "tianquan-shoubing.field.UpdateOAuthClientDTO.postLogoutRedirectUris", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.postLogoutRedirectUris")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_UPDATE))
    @Size(max = 32)
    private List<@NotBlank @Size(max = 2048) String> postLogoutRedirectUris;

    /** Existing callers omit the new browser settings and retain their stored values. */
    public UpdateOAuthClientDTO(String clientName, OAuthClient.Status status, int accessTokenTtlSeconds,
            int refreshTokenTtlSeconds, long expectedVersion, List<String> allowedScopes) {
        this(clientName, status, accessTokenTtlSeconds, refreshTokenTtlSeconds, expectedVersion, allowedScopes, null, null);
    }
}
