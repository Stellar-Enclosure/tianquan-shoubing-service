package top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.po;

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

/** Tenant-bound durable audit inbox facts. */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
@TableName(value = "oauth_audit_inbox", schema = "tianquan_oauth", autoResultMap = true)
public class OAuthAuditInboxPO extends EgonModel<OAuthAuditInboxPO> {

    @TableField(value = "event_id", updateStrategy = FieldStrategy.NEVER)
    @NotBlank(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Size(max = 64, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String eventId;

    @TableField(value = "event_fingerprint", updateStrategy = FieldStrategy.NEVER)
    @NotBlank(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Size(max = 64, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Pattern(regexp = "[0-9a-f]{64}", groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String eventFingerprint;

    @TableField(value = "schema_version", updateStrategy = FieldStrategy.NEVER)
    @NotNull(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @PositiveOrZero(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private Integer schemaVersion;

    @TableField(value = "source_client_pk", updateStrategy = FieldStrategy.NEVER)
    @NotNull(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private Long sourceClientPk;

    @TableField(value = "source_issuer", updateStrategy = FieldStrategy.NEVER)
    @NotBlank(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Size(max = 2048, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String sourceIssuer;

    @TableField(value = "source_resource_uri", updateStrategy = FieldStrategy.NEVER)
    @NotBlank(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Size(max = 2048, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String sourceResourceUri;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @TableField(value = "event_payload", typeHandler = OAuthJsonbTypeHandler.class, updateStrategy = FieldStrategy.NEVER)
    @NotNull(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private JsonNode eventPayload;

    @TableField(value = "occurred_at", updateStrategy = FieldStrategy.NEVER)
    @NotNull(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private Instant occurredAt;

    @TableField(value = "received_at", updateStrategy = FieldStrategy.NEVER)
    @NotNull(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private Instant receivedAt;

    @TableField(value = "state")
    @NotBlank(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @Size(max = 128, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String state;

    @TableField(value = "attempt_count")
    @NotNull(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @PositiveOrZero(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private Integer attemptCount;

    @TableField(value = "next_attempt_at")
    @NotNull(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private Instant nextAttemptAt;

    @TableField(value = "claim_owner")
    @Size(max = 128, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String claimOwner;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @TableField(value = "claim_token")
    @Size(max = 64, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String claimToken;

    @TableField(value = "claim_generation")
    @NotNull(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    @PositiveOrZero(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private Long claimGeneration;

    @TableField(value = "lease_until")
    private Instant leaseUntil;

    @TableField(value = "terminal_at")
    private Instant terminalAt;

    @TableField(value = "failure_code")
    @Size(max = 128, groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private String failureCode;

    @TableField(value = "processing_deadline", updateStrategy = FieldStrategy.NEVER)
    @NotNull(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private Instant processingDeadline;

    @TableField(value = "retain_until", updateStrategy = FieldStrategy.NEVER)
    @NotNull(groups = {EgonColaModelValidationGroups.Insert.class, EgonColaModelValidationGroups.Update.class, EgonColaModelValidationGroups.Persisted.class})
    private Instant retainUntil;
}
