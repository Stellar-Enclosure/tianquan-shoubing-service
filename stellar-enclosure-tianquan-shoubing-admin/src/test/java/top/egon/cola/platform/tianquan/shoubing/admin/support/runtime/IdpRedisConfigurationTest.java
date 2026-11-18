package top.egon.cola.platform.tianquan.shoubing.admin.support.runtime;

import org.junit.jupiter.api.Test;
import org.redisson.config.Config;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IdpRedisConfigurationTest {

    @Test
    void cloudRequiresNamedTlsClusterAndReadsSecretsSeparately() {
        var config = IdpRedisConfiguration.sharedRedisConfig(
                "rediss://redis-a.data-system.svc.cluster.local:6379,rediss://redis-b.data-system.svc.cluster.local:6379",
                "idp-workload", "fixture-credential", Duration.ofSeconds(2), false);
        assertThat(config.isClusterConfig()).isTrue();
        assertThat(config.useClusterServers().getNodeAddresses()).containsExactly(
                "rediss://redis-a.data-system.svc.cluster.local:6379", "rediss://redis-b.data-system.svc.cluster.local:6379");
        assertThat(config.getUsername()).isEqualTo("idp-workload");
        assertThat(config.getPassword()).isEqualTo("fixture-credential");
    }

    @Test
    void onlyAnExplicitLocalProfileMayUseLoopbackPlaintext() {
        Config local = IdpRedisConfiguration.sharedRedisConfig("redis://127.0.0.1:23299", "", "",
                Duration.ofMillis(600), true);
        assertThat(local.isClusterConfig()).isFalse();
        assertThat(local.useSingleServer().getAddress()).isEqualTo("redis://127.0.0.1:23299");
        assertThatThrownBy(() -> IdpRedisConfiguration.sharedRedisConfig("redis://127.0.0.1:23299", "", "",
                Duration.ofMillis(600), false)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> IdpRedisConfiguration.sharedRedisConfig("redis://other.local:23299", "", "",
                Duration.ofMillis(600), true)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsUnboundAndAmbiguousRedisBootstrapSettings() {
        for (String endpoints : new String[] {
                "",
                "rediss://a.example:6379",
                "rediss://a.example:6379,rediss://a.example:6379",
                "rediss://a.example:6379,redis://b.example:6379",
                "rediss://a.example:6379,rediss://user:pass@b.example:6379",
                "rediss://a.example:6379,rediss://b.example:6379/1",
                "rediss://a.example:6379,rediss://b.example:6379?redirect=1",
                "rediss://a.example:6379,rediss://b.example:6379#redirect",
                "rediss://a.example:6379,rediss://b.example:65536",
                "rediss://a.example:6379,rediss://b.example:6379,"}) {
            assertThatThrownBy(() -> IdpRedisConfiguration.sharedRedisConfig(endpoints,
                    "idp-workload", "fixture-credential", Duration.ofSeconds(2), false))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageNotContaining("user:pass");
        }
        assertThatThrownBy(() -> IdpRedisConfiguration.sharedRedisConfig(
                "rediss://a.example:6379,rediss://b.example:6379", "", "", Duration.ofSeconds(2), false))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
