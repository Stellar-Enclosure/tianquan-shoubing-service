package top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.dto;

import top.egon.cola.platform.tianquan.jianshen.contract.permission.PermissionManifest;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.ResourceType;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.FieldPermissions;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionGroup;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.annotation.PermissionResource;
import top.egon.cola.platform.tianquan.shoubing.admin.permission.IdentityPermissionCodes;

import jakarta.validation.constraints.PositiveOrZero;

/**
 * Resource Server 变更使用的乐观锁版本。
 *
 * <p>Optimistic-lock version used by a Resource Server mutation.</p>
 *
 * @param expectedVersion 客户端已读取的版本；version previously read by the caller
 */
public record ResourceVersionDTO(@PermissionResource(key = "tianquan-shoubing.field.ResourceVersionDTO.expectedVersion", type = ResourceType.FIELD,
            labelPage = "identity.permissions", labelKey = "field.expectedVersion")
    @FieldPermissions(valueType = PermissionManifest.JsonFieldType.NUMBER,
            write = @PermissionGroup(codes = IdentityPermissionCodes.RESOURCE_SERVER_STATUS))
    @PositiveOrZero long expectedVersion) {
}
