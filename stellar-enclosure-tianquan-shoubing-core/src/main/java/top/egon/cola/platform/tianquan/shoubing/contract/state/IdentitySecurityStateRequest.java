package top.egon.cola.platform.tianquan.shoubing.contract.state;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.net.URI;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;

/** Sensitive proof is request-only and must never be included in diagnostics. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IdentitySecurityStateRequest {
    @NotNull
    private IdentityStatePurpose purpose;
    @NotBlank @Size(max = 16_384)
    @ToString.Exclude @EqualsAndHashCode.Exclude
    private String accessToken;
    @NotNull
    private URI expectedResource;
    @NotBlank @Size(max = 128)
    private String expectedClientId;
    @Pattern(regexp = "[0-9a-f]{64}")
    @ToString.Exclude @EqualsAndHashCode.Exclude
    private String refreshTokenDigest;
    @Pattern(regexp = "[0-9a-f]{64}")
    @ToString.Exclude @EqualsAndHashCode.Exclude
    private String browserBindingDigest;
}
