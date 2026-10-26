package top.egon.cola.platform.tianquan.shoubing.admin.audit.domain.bo;

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
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.Accessors;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@Builder(toBuilder = true)
public class OAuthAuditInboxBO {

    private Long id;
    @PositiveOrZero
    private long version;

    @NotBlank
    @Size(max = 64)
    private String eventId;

    @NotBlank
    @Size(max = 64)
    @Pattern(regexp = "[0-9a-f]{64}")
    private String eventFingerprint;

    @NotNull
    @PositiveOrZero
    private Integer schemaVersion;

    @NotNull
    private Long sourceClientPk;

    @NotBlank
    @Size(max = 2048)
    private String sourceIssuer;

    @NotBlank
    @Size(max = 2048)
    private String sourceResourceUri;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @NotNull
    private JsonNode eventPayload;

    @NotNull
    private Instant occurredAt;

    @NotNull
    private Instant receivedAt;

    @NotBlank
    @Size(max = 128)
    private String state;

    @NotNull
    @PositiveOrZero
    private Integer attemptCount;

    @NotNull
    private Instant nextAttemptAt;

    @Size(max = 128)
    private String claimOwner;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @Size(max = 64)
    private String claimToken;

    @NotNull
    @PositiveOrZero
    private Long claimGeneration;

    private Instant leaseUntil;

    private Instant terminalAt;

    @Size(max = 128)
    private String failureCode;

    @NotNull
    private Instant processingDeadline;

    @NotNull
    private Instant retainUntil;
}
