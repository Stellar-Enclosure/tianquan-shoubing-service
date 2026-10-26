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

/** One-time client secret rotation result. */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RotatedClientSecretVO {

    @PermissionResource(key = "tianquan-shoubing.field.RotatedClientSecretVO.clientId", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.clientId")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_UPDATE))
    @NotBlank
    @Size(max = 128)
    private String clientId;
    @PermissionResource(key = "tianquan-shoubing.field.RotatedClientSecretVO.appId", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.appId")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_UPDATE))
    @Size(max = 128)
    private String appId;
    @PermissionResource(key = "tianquan-shoubing.field.RotatedClientSecretVO.clientSecret", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.clientSecret")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_UPDATE))
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @Size(max = 128)
    private String clientSecret;
    @PermissionResource(key = "tianquan-shoubing.field.RotatedClientSecretVO.secretHint", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.secretHint")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_UPDATE))
    @Size(max = 8)
    private String secretHint;
    @PermissionResource(key = "tianquan-shoubing.field.RotatedClientSecretVO.version", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.version")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_UPDATE))
    @PositiveOrZero
    private long version;
    @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
    @PermissionResource(key = "tianquan-shoubing.field.RotatedClientSecretVO.rotatedAt", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.rotatedAt")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_UPDATE))
    private Instant rotatedAt;
    @PermissionResource(key = "tianquan-shoubing.field.RotatedClientSecretVO.issuer", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.issuer")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_UPDATE))
    @NotBlank
    @Size(max = 2048)
    private String issuer;
}
