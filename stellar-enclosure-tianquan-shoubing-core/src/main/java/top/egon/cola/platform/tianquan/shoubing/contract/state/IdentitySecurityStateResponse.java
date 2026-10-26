package top.egon.cola.platform.tianquan.shoubing.contract.state;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import top.egon.cola.platform.tianquan.shoubing.contract.OAuthSecurityVersionBO;

/** NumericDate expiry fields use integer seconds; IDs and refresh generation stay decimal strings. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IdentitySecurityStateResponse {
    private IdentityStatePurpose purpose;
    private boolean eligible;
    private String reasonCode;
    private String issuer;
    private String resource;
    private String clientId;
    private String subject;
    private String authorizationId;
    private String authenticationJti;
    private String refreshGeneration;
    private Long authorizationExpiresAt;
    private Long authenticationExpiresAt;
    private OAuthSecurityVersionBO securityVersion;

    public static IdentitySecurityStateResponse denied(IdentityStatePurpose purpose, String reasonCode) {
        return builder().purpose(purpose).eligible(false).reasonCode(reasonCode).build();
    }
}
