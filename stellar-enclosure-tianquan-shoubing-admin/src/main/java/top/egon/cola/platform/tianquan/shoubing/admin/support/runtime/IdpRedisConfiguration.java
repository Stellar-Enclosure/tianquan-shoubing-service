package top.egon.cola.platform.tianquan.shoubing.admin.support.runtime;

import org.redisson.Redisson;
import org.redisson.api.RedissonClient;
import org.redisson.config.BaseConfig;
import org.redisson.config.Config;
import org.redisson.config.SslVerificationMode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;

import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Set;

/** Supplies the shared issuing and RPC admission authority from deployment bootstrap settings. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "egon.cola.component.id.redis", name = "enabled", havingValue = "true")
public class IdpRedisConfiguration {

    private static final Set<String> LOOPBACK_HOSTS = Set.of("127.0.0.1", "localhost", "[::1]");

    @Bean(name = "redissonClient", destroyMethod = "shutdown")
    @ConditionalOnMissingBean(name = "redissonClient")
    RedissonClient sharedIssuingAndAdmissionRedis(
            @Value("${egon.tianquan-shoubing.shared-redis.endpoints:}") String endpoints,
            @Value("${egon.tianquan-shoubing.shared-redis.username:}") String username,
            @Value("${egon.tianquan-shoubing.shared-redis.password:}") String password,
            @Value("${egon.tianquan-shoubing.shared-redis.timeout:2s}") Duration timeout,
            Environment environment) {
        boolean local = environment.acceptsProfiles(Profiles.of("local & !cloud-native"));
        return Redisson.create(sharedRedisConfig(endpoints, username, password, timeout, local));
    }

    static Config sharedRedisConfig(String endpoints, String username, String password, Duration timeout,
                                    boolean local) {
        if (timeout.compareTo(Duration.ofMillis(100)) < 0 || timeout.compareTo(Duration.ofSeconds(10)) > 0) {
            throw new IllegalArgumentException("Shared Redis timeout must be within 100ms and 10s");
        }
        var nodes = new LinkedHashSet<String>();
        for (String entry : endpoints.split(",", -1)) {
            String node = redisNode(entry.trim(), local);
            if (!nodes.add(node) || nodes.size() > 16) {
                throw new IllegalArgumentException("Shared Redis cluster seeds must be unique and bounded");
            }
        }
        Config config = new Config().setSslVerificationMode(SslVerificationMode.STRICT);
        if (!username.isBlank()) {
            config.setUsername(username);
        }
        if (!password.isBlank()) {
            config.setPassword(password);
        }
        if (local && nodes.size() == 1 && nodes.getFirst().startsWith("redis://")) {
            configureTimeout(config.useSingleServer().setAddress(nodes.getFirst()), timeout);
            return config;
        }
        if (nodes.size() < 2 || nodes.stream().anyMatch(node -> !node.startsWith("rediss://"))
                || username.isBlank() || password.isBlank()) {
            throw new IllegalArgumentException("Shared Redis requires distinct TLS cluster seeds and a dedicated ACL user");
        }
        configureTimeout(config.useClusterServers().addNodeAddress(nodes.toArray(String[]::new)), timeout);
        return config;
    }

    private static String redisNode(String entry, boolean local) {
        URI uri;
        try {
            uri = URI.create(entry);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("Invalid shared Redis seed address");
        }
        if (uri.getHost() == null || uri.getPort() < 1 || uri.getPort() > 65535 || uri.getUserInfo() != null
                || uri.getRawQuery() != null || uri.getRawFragment() != null || !"".equals(uri.getRawPath())) {
            throw new IllegalArgumentException("Invalid shared Redis seed address");
        }
        if ("rediss".equals(uri.getScheme()) || local && "redis".equals(uri.getScheme())
                && LOOPBACK_HOSTS.contains(uri.getHost())) {
            return uri.toASCIIString();
        }
        throw new IllegalArgumentException("Shared Redis seed transport must use TLS");
    }

    private static void configureTimeout(BaseConfig<?> config, Duration timeout) {
        int milliseconds = Math.toIntExact(timeout.toMillis());
        config.setConnectTimeout(milliseconds).setTimeout(milliseconds);
    }
}
