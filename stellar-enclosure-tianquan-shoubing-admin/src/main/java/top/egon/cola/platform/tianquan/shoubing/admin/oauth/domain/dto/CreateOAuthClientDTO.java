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
import jakarta.validation.constraints.Size;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.OAuthClientPurposeEnum;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;

/** OAuth client creation input. */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@Builder
public class CreateOAuthClientDTO {

    @PermissionResource(key = "tianquan-shoubing.field.CreateOAuthClientDTO.appId", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.appId")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @Pattern(regexp = "[a-z][a-z0-9-]{2,127}")
    private String appId;

    @PermissionResource(key = "tianquan-shoubing.field.CreateOAuthClientDTO.clientId", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.clientId")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @NotBlank
    @Pattern(regexp = "[A-Za-z0-9._-]{1,128}")
    private String clientId;

    @PermissionResource(key = "tianquan-shoubing.field.CreateOAuthClientDTO.clientName", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.clientName")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @NotBlank
    @Size(max = 200)
    private String clientName;

    @PermissionResource(key = "tianquan-shoubing.field.CreateOAuthClientDTO.clientType", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.clientType")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @NotNull
    private OAuthClient.ClientType clientType;

    @PermissionResource(key = "tianquan-shoubing.field.CreateOAuthClientDTO.purpose", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.purpose")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @NotNull
    private OAuthClientPurposeEnum purpose;

    @PermissionResource(key = "tianquan-shoubing.field.CreateOAuthClientDTO.accessTokenTtlSeconds", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.accessTokenTtlSeconds")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @Min(300)
    @Max(600)
    private int accessTokenTtlSeconds;

    @PermissionResource(key = "tianquan-shoubing.field.CreateOAuthClientDTO.refreshTokenTtlSeconds", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.refreshTokenTtlSeconds")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @Min(0)
    @Max(604800)
    private int refreshTokenTtlSeconds;

    @PermissionResource(key = "tianquan-shoubing.field.CreateOAuthClientDTO.redirectUris", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.redirectUris")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @NotNull
    @Size(max = 16)
    private List<@NotBlank @Size(max = 2048) String> redirectUris;

    @PermissionResource(key = "tianquan-shoubing.field.CreateOAuthClientDTO.resourceUris", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.resourceUris")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @NotNull
    @Size(max = 64)
    private List<@NotBlank @Size(max = 2048) String> resourceUris;

    @PermissionResource(key = "tianquan-shoubing.field.CreateOAuthClientDTO.allowedScopes", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.allowedScopes")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @NotNull
    @Size(max = 64)
    private List<@NotBlank @Pattern(regexp = "[A-Za-z0-9._:-]{1,128}") String> allowedScopes;

    @PermissionResource(key = "tianquan-shoubing.field.CreateOAuthClientDTO.browserBound", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.browserBound")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.BOOLEAN,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    private boolean browserBound;

    @PermissionResource(key = "tianquan-shoubing.field.CreateOAuthClientDTO.postLogoutRedirectUris", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.postLogoutRedirectUris")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @NotNull
    @Size(max = 32)
    @Builder.Default
    private List<@NotBlank @Size(max = 2048) String> postLogoutRedirectUris = List.of();

    /** Preserves the previous creation constructor with browser binding disabled. */
    public CreateOAuthClientDTO(String appId, String clientId, String clientName, OAuthClient.ClientType clientType,
            OAuthClientPurposeEnum purpose, int accessTokenTtlSeconds, int refreshTokenTtlSeconds,
            List<String> redirectUris, List<String> resourceUris, List<String> allowedScopes) {
        this(appId, clientId, clientName, clientType, purpose, accessTokenTtlSeconds, refreshTokenTtlSeconds,
                redirectUris, resourceUris, allowedScopes, false, List.of());
    }
}
