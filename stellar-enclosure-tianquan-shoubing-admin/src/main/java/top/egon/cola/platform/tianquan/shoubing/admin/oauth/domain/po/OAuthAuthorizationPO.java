package top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.po;

import com.baomidou.mybatisplus.annotation.FieldStrategy;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableName;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.Accessors;
import lombok.experimental.SuperBuilder;
import top.egon.cola.component.common.mybatis.model.EgonColaModelValidationGroups;
import top.egon.cola.component.common.mybatis.model.EgonModel;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.OAuthStringListJsonbTypeHandler;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
@TableName(value = "oauth_authorization", schema = "tianquan_oauth", autoResultMap = true)
public class OAuthAuthorizationPO extends EgonModel<OAuthAuthorizationPO> {

    @TableField(value = "client_pk", updateStrategy = FieldStrategy.NEVER)
    @NotNull(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class,
            EgonColaModelValidationGroups.Persisted.class})
    @Positive(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class,
            EgonColaModelValidationGroups.Persisted.class})
    private Long clientPk;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @TableField(value = "principal_name", updateStrategy = FieldStrategy.NEVER)
    @NotBlank(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class,
            EgonColaModelValidationGroups.Persisted.class})
    @Size(max = 128, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class,
            EgonColaModelValidationGroups.Persisted.class})
    private String principalName;

    @TableField(value = "principal_type", updateStrategy = FieldStrategy.NEVER)
    @NotBlank(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class,
            EgonColaModelValidationGroups.Persisted.class})
    @Pattern(regexp = "USER|SERVICE", groups = {
            EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class,
            EgonColaModelValidationGroups.Persisted.class})
    private String principalType;

    @TableField(value = "grant_type", updateStrategy = FieldStrategy.NEVER)
    @NotBlank(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class,
            EgonColaModelValidationGroups.Persisted.class})
    @Pattern(regexp = "authorization_code|client_credentials", groups = {
            EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class,
            EgonColaModelValidationGroups.Persisted.class})
    @Size(max = 32, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class,
            EgonColaModelValidationGroups.Persisted.class})
    private String grantType;

    @TableField(value = "authorized_scopes", typeHandler = OAuthStringListJsonbTypeHandler.class)
    @NotNull(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class,
            EgonColaModelValidationGroups.Persisted.class})
    @Size(max = 64, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class,
            EgonColaModelValidationGroups.Persisted.class})
    private List<@NotBlank(groups = {EgonColaModelValidationGroups.Insert.class,
            EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
            @Size(max = 128, groups = {EgonColaModelValidationGroups.Insert.class,
                    EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
            String> authorizedScopes;

    @TableField(value = "audiences", typeHandler = OAuthStringListJsonbTypeHandler.class,
            updateStrategy = FieldStrategy.NEVER)
    @NotNull(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class,
            EgonColaModelValidationGroups.Persisted.class})
    @Size(max = 64, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class,
            EgonColaModelValidationGroups.Persisted.class})
    private List<@NotBlank(groups = {EgonColaModelValidationGroups.Insert.class,
            EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
            @Size(max = 2048, groups = {EgonColaModelValidationGroups.Insert.class,
                    EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
            String> audiences;

    @TableField("status")
    @NotBlank(groups = {EgonColaModelValidationGroups.Insert.class,
            EgonColaModelValidationGroups.Update.class,
            EgonColaModelValidationGroups.Persisted.class})
    @Pattern(regexp = "PENDING_CONSENT|ACTIVE|REVOKED|EXPIRED|CANCELLED", groups = {
            EgonColaModelValidationGroups.Insert.class,
            EgonColaModelValidationGroups.Update.class,
            EgonColaModelValidationGroups.Persisted.class})
    private String status;

    @TableField(value = "auth_time", updateStrategy = FieldStrategy.NEVER)
    private Instant authTime;

    @TableField(value = "acr", updateStrategy = FieldStrategy.NEVER)
    @Size(max = 64, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class,
            EgonColaModelValidationGroups.Persisted.class})
    private String acr;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @TableField("attributes_ciphertext")
    @NotBlank(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class,
            EgonColaModelValidationGroups.Persisted.class})
    private String attributesCiphertext;

    @TableField(value = "absolute_expires_at", updateStrategy = FieldStrategy.NEVER)
    @NotNull(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class,
            EgonColaModelValidationGroups.Persisted.class})
    private Instant absoluteExpiresAt;

    @TableField("revoked_at")
    private Instant revokedAt;

    @lombok.Builder.Default
    @com.baomidou.mybatisplus.annotation.TableField(value = "requested_scopes", typeHandler = top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.OAuthStringListJsonbTypeHandler.class, updateStrategy = com.baomidou.mybatisplus.annotation.FieldStrategy.NEVER)
    private List<String> requestedScopes = java.util.List.of();

    @com.baomidou.mybatisplus.annotation.TableField(value = "resource_uri", updateStrategy = com.baomidou.mybatisplus.annotation.FieldStrategy.NEVER)
    private String resourceUri;

    @com.fasterxml.jackson.annotation.JsonIgnore
    @lombok.ToString.Exclude
    @lombok.EqualsAndHashCode.Exclude
    @com.baomidou.mybatisplus.annotation.TableField(value = "authentication_jti_digest", updateStrategy = com.baomidou.mybatisplus.annotation.FieldStrategy.NEVER)
    private String authenticationJtiDigest;

    @com.fasterxml.jackson.annotation.JsonIgnore
    @lombok.ToString.Exclude
    @lombok.EqualsAndHashCode.Exclude
    @com.baomidou.mybatisplus.annotation.TableField(value = "client_browser_binding_digest", updateStrategy = com.baomidou.mybatisplus.annotation.FieldStrategy.NEVER)
    private String clientBrowserBindingDigest;

    @com.fasterxml.jackson.annotation.JsonIgnore
    @lombok.ToString.Exclude
    @lombok.EqualsAndHashCode.Exclude
    @com.baomidou.mybatisplus.annotation.TableField(value = "interaction_id", updateStrategy = com.baomidou.mybatisplus.annotation.FieldStrategy.NEVER)
    private String interactionId;

    @com.baomidou.mybatisplus.annotation.TableField(value = "refresh_generation")
    private long refreshGeneration;

    @com.baomidou.mybatisplus.annotation.TableField(value = "retain_until")
    private Instant retainUntil;
}
