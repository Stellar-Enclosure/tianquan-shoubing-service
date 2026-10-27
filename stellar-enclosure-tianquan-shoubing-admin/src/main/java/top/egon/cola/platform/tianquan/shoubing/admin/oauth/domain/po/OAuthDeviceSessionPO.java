package top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.po;

import com.baomidou.mybatisplus.annotation.FieldStrategy;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableName;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.Accessors;
import lombok.experimental.SuperBuilder;
import top.egon.cola.component.common.mybatis.model.EgonModel;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
@TableName(value = "oauth_device_session", schema = "tianquan_oauth", autoResultMap = true)
public class OAuthDeviceSessionPO extends EgonModel<OAuthDeviceSessionPO> {
    @TableField(value = "client_pk", updateStrategy = FieldStrategy.NEVER)
    private Long clientPk;

    @ToString.Exclude
    @TableField(value = "subject", updateStrategy = FieldStrategy.NEVER)
    private String subject;

    @ToString.Exclude
    @TableField(value = "authentication_jti_digest", updateStrategy = FieldStrategy.NEVER)
    private String authenticationJtiDigest;

    @TableField(value = "authenticated_at", updateStrategy = FieldStrategy.NEVER)
    private Instant authenticatedAt;

    @TableField(value = "expires_at")
    private Instant expiresAt;

    @ToString.Exclude
    @TableField(value = "user_agent", updateStrategy = FieldStrategy.NEVER)
    private String userAgent;

    @ToString.Exclude
    @TableField(value = "ip_address", updateStrategy = FieldStrategy.NEVER)
    private String ipAddress;

    @TableField(value = "status")
    private String status;

    @TableField(value = "revoked_at")
    private Instant revokedAt;

    @TableField(value = "reason_code")
    private String reasonCode;

}
