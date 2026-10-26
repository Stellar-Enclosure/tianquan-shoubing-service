package top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

/** OAuth 客户端集合字段的单值变更输入。 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@Builder
public class OAuthValueDTO {

    @PermissionResource(key = "tianquan-shoubing.field.OAuthValueDTO.value", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.value")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.STRING,
            write = @PermissionGroup(codes = IdentityPermissionCodes.OAUTH_CLIENT_UPDATE))
    @NotBlank
    private String value;
}
