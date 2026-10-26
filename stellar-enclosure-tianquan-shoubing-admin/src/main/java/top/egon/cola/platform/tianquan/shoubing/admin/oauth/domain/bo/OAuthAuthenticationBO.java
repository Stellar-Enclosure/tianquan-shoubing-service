package top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo;

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
public class OAuthAuthenticationBO {

    private Long id;
    @PositiveOrZero
    private long version;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @NotBlank
    @Size(max = 64)
    @Pattern(regexp = "[0-9a-f]{64}")
    private String jtiDigest;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @NotBlank
    @Size(max = 128)
    private String subject;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @NotBlank
    @Size(max = 64)
    @Pattern(regexp = "[0-9a-f]{64}")
    private String browserBindingDigest;

    @NotNull
    @PositiveOrZero
    private Long subjectGeneration;

    @NotNull
    @PositiveOrZero
    private Long realmGeneration;

    @NotNull
    private Instant authenticatedAt;

    @NotBlank
    @Size(max = 64)
    private String acr;

    @NotBlank
    @Size(max = 128)
    private String status;

    @NotNull
    private Instant expiresAt;

    @NotNull
    private Instant retainUntil;

    private Instant revokedAt;

    @Size(max = 128)
    private String reasonCode;
}
