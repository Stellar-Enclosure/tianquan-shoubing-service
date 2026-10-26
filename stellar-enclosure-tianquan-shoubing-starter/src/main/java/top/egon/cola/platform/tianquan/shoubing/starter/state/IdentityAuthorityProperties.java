package top.egon.cola.platform.tianquan.shoubing.starter.state;

import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;

/** Immutable destinations are assembled once; no identity or authorization decisions are cached here. */
@Data
@ConfigurationProperties("egon.cola.platform.tianquan.shoubing.authority")
public class IdentityAuthorityProperties {
    private URI baseUri;
    private Duration timeout = Duration.ofSeconds(2);
    private Map<String, Binding> bindings = new LinkedHashMap<>();

    @Data
    public static class Binding {
        private URI issuer;
        private URI sourceResource;
        private String registrationId;
        private URI audience;
        private ServiceTokenContext context;
        private String tenantId;
        private Set<String> scopes = Set.of(IdentityAuthorityScopes.STATE_RESOLVE, IdentityAuthorityScopes.AUDIT_APPEND);
    }
}
