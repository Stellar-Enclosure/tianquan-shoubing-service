package top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import jakarta.validation.constraints.PositiveOrZero;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

/** Request to rotate one Confidential Client Secret. */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@Builder
public class RotateClientSecretDTO {

    @PermissionResource(key = "tianquan-shoubing.field.RotateClientSecretDTO.expectedVersion", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.expectedVersion")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_UPDATE))
    @PositiveOrZero
    private long expectedVersion;
}
