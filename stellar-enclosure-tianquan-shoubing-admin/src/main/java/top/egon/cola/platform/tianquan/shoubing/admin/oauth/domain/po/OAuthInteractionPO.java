package top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.po;

import com.baomidou.mybatisplus.annotation.FieldStrategy;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableName;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.PositiveOrZero;
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
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.dao.OAuthJsonbTypeHandler;

/** Tenant-bound durable interaction facts. */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
@TableName(value = "oauth_interaction", schema = "tianquan_oauth", autoResultMap = true)
public class OAuthInteractionPO extends EgonModel<OAuthInteractionPO> {

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @TableField(value = "interaction_id", updateStrategy = FieldStrategy.NEVER)
    @NotBlank(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Size(max = 64, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String interactionId;

    @TableField(value = "purpose", updateStrategy = FieldStrategy.NEVER)
    @NotBlank(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Size(max = 128, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String purpose;

    @TableField(value = "client_pk", updateStrategy = FieldStrategy.NEVER)
    private Long clientPk;

    @TableField(value = "resource_uri", updateStrategy = FieldStrategy.NEVER)
    @Size(max = 2048, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String resourceUri;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @TableField(value = "redirect_uri", updateStrategy = FieldStrategy.NEVER)
    @Size(max = 2048, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String redirectUri;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @TableField(value = "request_digest", updateStrategy = FieldStrategy.NEVER)
    @NotBlank(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Size(max = 64, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Pattern(regexp = "[0-9a-f]{64}", groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String requestDigest;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @TableField(value = "request_ciphertext", updateStrategy = FieldStrategy.NEVER)
    @NotBlank(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Size(max = 131072, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String requestCiphertext;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @TableField(value = "browser_binding_digest", updateStrategy = FieldStrategy.NEVER)
    @NotBlank(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Size(max = 64, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Pattern(regexp = "[0-9a-f]{64}", groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String browserBindingDigest;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @TableField(value = "client_browser_binding_digest", updateStrategy = FieldStrategy.NEVER)
    @Size(max = 64, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Pattern(regexp = "[0-9a-f]{64}", groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String clientBrowserBindingDigest;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @TableField(value = "csrf_digest")
    @NotBlank(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Size(max = 64, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Pattern(regexp = "[0-9a-f]{64}", groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String csrfDigest;

    @TableField(value = "requested_scopes", typeHandler = OAuthStringListJsonbTypeHandler.class, updateStrategy = FieldStrategy.NEVER)
    @NotNull(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Size(max = 64, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private List<String> requestedScopes;

    @TableField(value = "approved_scopes", typeHandler = OAuthStringListJsonbTypeHandler.class)
    @NotNull(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Size(max = 64, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private List<String> approvedScopes;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @TableField(value = "code_challenge", updateStrategy = FieldStrategy.NEVER)
    @Size(max = 128, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String codeChallenge;

    @TableField(value = "code_challenge_method", updateStrategy = FieldStrategy.NEVER)
    @Size(max = 128, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String codeChallengeMethod;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @TableField(value = "authentication_jti_digest")
    @Size(max = 64, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Pattern(regexp = "[0-9a-f]{64}", groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String authenticationJtiDigest;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @TableField(value = "restricted_subject")
    @Size(max = 128, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String restrictedSubject;

    @TableField(value = "state")
    @NotBlank(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Size(max = 128, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String state;

    @TableField(value = "expires_at", updateStrategy = FieldStrategy.NEVER)
    @NotNull(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private Instant expiresAt;

    @TableField(value = "retain_until")
    @NotNull(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private Instant retainUntil;

    @TableField(value = "consumed_at")
    private Instant consumedAt;

    @TableField(value = "failure_code")
    @Size(max = 128, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String failureCode;
}
