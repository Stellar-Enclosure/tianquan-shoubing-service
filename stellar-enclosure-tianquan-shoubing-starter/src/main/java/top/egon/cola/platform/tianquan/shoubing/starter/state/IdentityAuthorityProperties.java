package top.egon.cola.platform.tianquan.shoubing.starter.state;

import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import lombok.Data;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingProperties.Reference;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingVO.Operation;

/** Immutable destinations are assembled once; no identity or authorization decisions are cached here. */
@Data
@Validated
@ConfigurationProperties("egon.cola.platform.tianquan.shoubing.authority")
public class IdentityAuthorityProperties {
    private URI baseUri;
    private Duration timeout = Duration.ofSeconds(2);
    @Valid
    @NotNull
    private Map<String, @NotNull @Valid Binding> bindings = new LinkedHashMap<>();

    @Data
    public static class Binding {
        private URI issuer;
        private URI sourceResource;
        private String registrationId;
        private URI audience;
        private ServiceTokenContext context;
        private String tenantId;
        private Set<String> scopes = Set.of(IdentityAuthorityScopes.STATE_RESOLVE, IdentityAuthorityScopes.AUDIT_APPEND);
        @NotNull
        private Map<@NotNull Operation, @NotNull @Valid Reference> transportBindings = new LinkedHashMap<>();
    }
}
