package top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.vo;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

/** Safe OAuth client management view. */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OAuthClientVO {

    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.clientId", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.clientId")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    @NotBlank
    @Size(max = 128)
    private String clientId;
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.appId", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.appId")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    @Size(max = 128)
    private String appId;
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.clientName", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.clientName")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    @NotBlank
    @Size(max = 200)
    private String clientName;
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.clientType", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.clientType")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    @NotBlank
    @Size(max = 16)
    private String clientType;
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.purpose", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.purpose")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    @NotBlank
    @Size(max = 16)
    private String purpose;
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.status", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.status")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    @NotBlank
    @Size(max = 16)
    private String status;
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.pkceRequired", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.pkceRequired")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.BOOLEAN,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    private boolean pkceRequired;
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.browserBound", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.browserBound")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.BOOLEAN,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    private boolean browserBound;
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.postLogoutRedirectUris", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.postLogoutRedirectUris")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    @NotNull
    @Size(max = 32)
    private List<String> postLogoutRedirectUris;
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.accessTokenTtlSeconds", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.accessTokenTtlSeconds")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    private int accessTokenTtlSeconds;
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.refreshTokenTtlSeconds", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.refreshTokenTtlSeconds")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    private int refreshTokenTtlSeconds;
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.redirectUris", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.redirectUris")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    @NotNull
    @Size(max = 16)
    private List<String> redirectUris;
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.resourceUris", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.resourceUris")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    @NotNull
    @Size(max = 64)
    private List<String> resourceUris;
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.allowedScopes", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.allowedScopes")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.ARRAY,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    @NotNull
    @Size(max = 64)
    private List<String> allowedScopes;
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.version", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.version")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    @PositiveOrZero
    private long version;
    @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.createdAt", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.createdAt")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    private Instant createdAt;
    @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.updatedAt", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.updatedAt")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    private Instant updatedAt;
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.secretHint", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.secretHint")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    @Size(max = 8)
    private String secretHint;
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.secretStatus", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.secretStatus")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    @Size(max = 16)
    private String secretStatus;
    @PermissionResource(key = "tianquan-shoubing.field.OAuthClientVO.issuer", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.issuer")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_READ))
    @NotBlank
    @Size(max = 2048)
    private String issuer;
}
