package top.egon.cola.platform.tianquan.shoubing.admin.token.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.Accessors;

/** Input for publishing a realm-bound signing key. */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@Builder
public class PublishSigningKeyDTO {

    @PermissionResource(key = "tianquan-shoubing.field.PublishSigningKeyDTO.kid", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.kid")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.SIGNING_KEY_PUBLISH))
    @NotBlank
    @Pattern(regexp = "[A-Za-z0-9_-]{1,128}")
    private String kid;

    @PermissionResource(key = "tianquan-shoubing.field.PublishSigningKeyDTO.encryptedPrivateKey", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.encryptedPrivateKey")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.SIGNING_KEY_PUBLISH))
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @NotBlank
    @Pattern(regexp = "ENC:v1:[A-Za-z0-9][A-Za-z0-9._-]{0,63}:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]{22,}")
    @Size(max = 32_768)
    private String encryptedPrivateKey;

    @PermissionResource(key = "tianquan-shoubing.field.PublishSigningKeyDTO.publicJwk", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.publicJwk")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.SIGNING_KEY_PUBLISH))
    @NotBlank
    @Size(max = 32_768)
    private String publicJwk;
}
