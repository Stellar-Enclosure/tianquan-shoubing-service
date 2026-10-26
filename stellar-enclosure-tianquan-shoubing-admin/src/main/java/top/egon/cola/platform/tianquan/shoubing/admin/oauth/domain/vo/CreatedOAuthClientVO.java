package top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.vo;

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
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.Accessors;

/** One-time client creation result. */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CreatedOAuthClientVO {

    @PermissionResource(key = "tianquan-shoubing.field.CreatedOAuthClientVO.clientId", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.clientId")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @NotBlank
    @Size(max = 128)
    private String clientId;
    @PermissionResource(key = "tianquan-shoubing.field.CreatedOAuthClientVO.appId", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.appId")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @Size(max = 128)
    private String appId;
    @PermissionResource(key = "tianquan-shoubing.field.CreatedOAuthClientVO.clientName", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.clientName")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @NotBlank
    @Size(max = 200)
    private String clientName;
    @PermissionResource(key = "tianquan-shoubing.field.CreatedOAuthClientVO.clientType", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.clientType")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @NotBlank
    @Size(max = 16)
    private String clientType;
    @PermissionResource(key = "tianquan-shoubing.field.CreatedOAuthClientVO.purpose", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.purpose")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @NotBlank
    @Size(max = 16)
    private String purpose;
    @PermissionResource(key = "tianquan-shoubing.field.CreatedOAuthClientVO.status", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.status")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @NotBlank
    @Size(max = 16)
    private String status;
    @PermissionResource(key = "tianquan-shoubing.field.CreatedOAuthClientVO.clientSecret", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.clientSecret")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @Size(max = 128)
    private String clientSecret;
    @PermissionResource(key = "tianquan-shoubing.field.CreatedOAuthClientVO.secretHint", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.secretHint")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @Size(max = 8)
    private String secretHint;
    @PermissionResource(key = "tianquan-shoubing.field.CreatedOAuthClientVO.version", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.version")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @PositiveOrZero
    private long version;
    @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
    @PermissionResource(key = "tianquan-shoubing.field.CreatedOAuthClientVO.createdAt", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.createdAt")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    private Instant createdAt;
    @PermissionResource(key = "tianquan-shoubing.field.CreatedOAuthClientVO.issuer", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.issuer")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_CREATE))
    @NotBlank
    @Size(max = 2048)
    private String issuer;
}
