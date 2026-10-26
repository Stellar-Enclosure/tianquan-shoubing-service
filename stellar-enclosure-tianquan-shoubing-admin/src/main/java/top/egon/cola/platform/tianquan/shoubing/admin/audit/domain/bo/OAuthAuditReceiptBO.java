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
public class OAuthAuditReceiptBO {

    private Long id;
    @PositiveOrZero
    private long version;

    @NotBlank
    @Size(max = 64)
    private String receiptId;

    @NotNull
    private Long inboxPk;

    @NotBlank
    @Size(max = 64)
    private String eventId;

    @NotBlank
    @Size(max = 64)
    @Pattern(regexp = "[0-9a-f]{64}")
    private String eventFingerprint;

    @NotNull
    private Long sourceClientPk;

    @NotBlank
    @Size(max = 2048)
    private String sourceIssuer;

    @NotBlank
    @Size(max = 2048)
    private String sourceResourceUri;

    @NotBlank
    @Size(max = 128)
    private String outcome;

    private Long auditPk;

    @NotNull
    private Instant confirmedAt;

    @NotNull
    private Instant retainUntil;
}
