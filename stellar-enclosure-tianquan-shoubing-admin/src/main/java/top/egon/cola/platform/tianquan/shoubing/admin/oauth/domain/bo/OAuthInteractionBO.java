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
public class OAuthInteractionBO {

    private Long id;
    @PositiveOrZero
    private long version;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @NotBlank
    @Size(max = 64)
    private String interactionId;

    @NotBlank
    @Size(max = 128)
    private String purpose;

    private Long clientPk;

    @Size(max = 2048)
    private String resourceUri;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @Size(max = 2048)
    private String redirectUri;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @NotBlank
    @Size(max = 64)
    @Pattern(regexp = "[0-9a-f]{64}")
    private String requestDigest;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @NotBlank
    @Size(max = 131072)
    private String requestCiphertext;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @NotBlank
    @Size(max = 64)
    @Pattern(regexp = "[0-9a-f]{64}")
    private String browserBindingDigest;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @Size(max = 64)
    @Pattern(regexp = "[0-9a-f]{64}")
    private String clientBrowserBindingDigest;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @NotBlank
    @Size(max = 64)
    @Pattern(regexp = "[0-9a-f]{64}")
    private String csrfDigest;

    @NotNull
    @Size(max = 64)
    private List<String> requestedScopes;

    @NotNull
    @Size(max = 64)
    private List<String> approvedScopes;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @Size(max = 128)
    private String codeChallenge;

    @Size(max = 128)
    private String codeChallengeMethod;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @Size(max = 64)
    @Pattern(regexp = "[0-9a-f]{64}")
    private String authenticationJtiDigest;

    @JsonIgnore
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @Size(max = 128)
    private String restrictedSubject;

    @NotBlank
    @Size(max = 128)
    private String state;

    @NotNull
    private Instant expiresAt;

    @NotNull
    private Instant retainUntil;

    private Instant consumedAt;

    @Size(max = 128)
    private String failureCode;
}
