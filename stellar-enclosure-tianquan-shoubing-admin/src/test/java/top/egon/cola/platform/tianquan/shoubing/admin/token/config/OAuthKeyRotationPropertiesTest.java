package top.egon.cola.platform.tianquan.shoubing.admin.token.config;

import java.time.Duration;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OAuthKeyRotationPropertiesTest {
    private final OAuthKeyRotationProperties properties = new OAuthKeyRotationProperties();

    @Test
    void verificationWindowFollowsSsoLifetimeAndClockSkew() {
        assertThat(properties.verificationOverlap(Duration.ofHours(8), Duration.ofSeconds(30)))
                .isEqualTo(Duration.ofHours(8).plusSeconds(30));
        assertThat(properties.verificationOverlap(Duration.ofMinutes(1), Duration.ZERO))
                .isEqualTo(Duration.ofSeconds(690));
        properties.setVerificationOverlap(Duration.ofHours(12));
        assertThat(properties.verificationOverlap(Duration.ofHours(8), Duration.ofSeconds(60)))
                .isEqualTo(Duration.ofHours(12));
    }

    @Test
    void rejectsAnExplicitWindowShorterThanTheSsoLifetime() {
        properties.setVerificationOverlap(Duration.ofHours(8));
        assertThatThrownBy(() -> properties.verificationOverlap(Duration.ofHours(8), Duration.ofSeconds(30)))
                .hasMessage("OAUTH_KEY_VERIFICATION_OVERLAP_TOO_SHORT");
    }
}
