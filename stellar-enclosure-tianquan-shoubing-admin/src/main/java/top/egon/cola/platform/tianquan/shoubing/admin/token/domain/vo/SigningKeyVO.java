package top.egon.cola.platform.tianquan.shoubing.admin.token.domain.vo;

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

/** Signing-key metadata view without private-key material. */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SigningKeyVO {

    @PermissionResource(key = "tianquan-shoubing.field.SigningKeyVO.kid", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.kid")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.SIGNING_KEY_READ))
    @NotBlank @Size(max = 128)
    private String kid;
    @PermissionResource(key = "tianquan-shoubing.field.SigningKeyVO.algorithm", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.algorithm")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.SIGNING_KEY_READ))
    @NotBlank @Size(max = 16)
    private String algorithm;
    @PermissionResource(key = "tianquan-shoubing.field.SigningKeyVO.publicJwk", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.publicJwk")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.SIGNING_KEY_READ))
    @NotBlank @Size(max = 32_768)
    private String publicJwk;
    @PermissionResource(key = "tianquan-shoubing.field.SigningKeyVO.status", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.status")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.SIGNING_KEY_READ))
    @NotBlank @Size(max = 24)
    private String status;
    @PermissionResource(key = "tianquan-shoubing.field.SigningKeyVO.runtimeServing", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.runtimeServing")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.BOOLEAN,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.SIGNING_KEY_READ))
    private boolean runtimeServing;
    @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
    @PermissionResource(key = "tianquan-shoubing.field.SigningKeyVO.activatedAt", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.activatedAt")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.SIGNING_KEY_READ))
    private Instant activatedAt;
    @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
    @PermissionResource(key = "tianquan-shoubing.field.SigningKeyVO.retiredAt", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.retiredAt")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.SIGNING_KEY_READ))
    private Instant retiredAt;
    @PermissionResource(key = "tianquan-shoubing.field.SigningKeyVO.version", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.version")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.SIGNING_KEY_READ))
    @PositiveOrZero
    private long version;
    @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
    @PermissionResource(key = "tianquan-shoubing.field.SigningKeyVO.createdAt", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.createdAt")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.SIGNING_KEY_READ))
    private Instant createdAt;
    @com.fasterxml.jackson.annotation.JsonFormat(shape = com.fasterxml.jackson.annotation.JsonFormat.Shape.STRING)
    @PermissionResource(key = "tianquan-shoubing.field.SigningKeyVO.updatedAt", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.updatedAt")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.SIGNING_KEY_READ))
    private Instant updatedAt;
    @PermissionResource(key = "tianquan-shoubing.field.SigningKeyVO.issuer", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.issuer")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            plainRead = @PermissionGroup(codes = IdentityPermissionCodes.SIGNING_KEY_READ))
    @NotBlank @Size(max = 2048)
    private String issuer;
}
