package top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo;

import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.Accessors;

/** One client on one SSO sign-in; active roles remain owned by the account. */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@Builder(toBuilder = true)
public class OAuthDeviceSessionBO {
    private Long id;
    private long version;
    private Long clientPk;
    @ToString.Exclude
    private String subject;
    @ToString.Exclude
    private String authenticationJtiDigest;
    private Instant authenticatedAt;
    private Instant expiresAt;
    @ToString.Exclude
    private String userAgent;
    @ToString.Exclude
    private String ipAddress;
    private String status;
    private Instant revokedAt;
    private String reasonCode;
}
