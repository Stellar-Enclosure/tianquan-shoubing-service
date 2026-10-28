package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import org.springframework.boot.context.properties.ConfigurationProperties;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Deployment-owned, finite delegation bindings; requests never choose trusted services or scopes. */
@ConfigurationProperties("egon.tianquan-shoubing.execution-grants")
public record OAuthExecutionGrantProperties(boolean enabled, List<Binding> bindings) {
    public OAuthExecutionGrantProperties {
        bindings = bindings == null ? List.of() : List.copyOf(bindings);
        if (bindings.size() > 256 || enabled && bindings.isEmpty()
                || bindings.stream().map(Binding::identity).distinct().count() != bindings.size()) {
            throw new IllegalArgumentException("EXECUTION_GRANT_BINDINGS_INVALID");
        }
        bindings.forEach(Binding::fingerprint);
    }

    public record Binding(String issuer, long tenantId, Service source, Service verifier, String purpose,
                          Set<String> requiredUserScopes, Set<String> sessionUserScopes, Duration maxLifetime) {
        public Binding {
            secureIssuer(issuer);
            if (tenantId <= 0 || source == null || verifier == null || purpose == null
                    || !purpose.matches("[A-Z][A-Z0-9_]{0,95}")
                    || source.clientPk() == verifier.clientPk() || source.resourceUri().equals(verifier.resourceUri())) {
                throw new IllegalArgumentException("EXECUTION_GRANT_BINDING_INVALID");
            }
            requiredUserScopes = scopes(requiredUserScopes, false);
            sessionUserScopes = scopes(sessionUserScopes, true);
            maxLifetime = maxLifetime == null ? Duration.ofHours(1) : maxLifetime;
            if (maxLifetime.compareTo(Duration.ofSeconds(1)) < 0 || maxLifetime.compareTo(Duration.ofHours(8)) > 0) {
                throw new IllegalArgumentException("EXECUTION_GRANT_LIFETIME_INVALID");
            }
        }

        private String identity() { return issuer + "|" + tenantId + "|" + source.clientPk() + "|" + purpose; }

        String fingerprint() {
            return CanonicalJson.digest(Map.of("version", 1, "issuer", issuer, "tenant", Long.toString(tenantId),
                    "source", source.values(), "verifier", verifier.values(), "purpose", purpose,
                    "requiredUserScopes", requiredUserScopes.stream().sorted().toList(),
                    "sessionUserScopes", sessionUserScopes.stream().sorted().toList(), "maxLifetime", maxLifetime.toString()));
        }
    }

    public record Service(long clientPk, String clientId, String appId, String businessCode,
                          String applicationCode, String environment, String resourceUri) {
        public Service { new ExecutionGrantEnvelope.ServiceBinding(clientPk, clientId, appId,
                businessCode, applicationCode, environment, resourceUri); }

        ExecutionGrantEnvelope.ServiceBinding binding() {
            return new ExecutionGrantEnvelope.ServiceBinding(clientPk, clientId, appId,
                    businessCode, applicationCode, environment, resourceUri);
        }

        Map<String, Object> values() {
            return Map.of("clientPk", Long.toString(clientPk), "clientId", clientId, "appId", appId,
                    "businessCode", businessCode, "applicationCode", applicationCode, "environment", environment,
                    "resourceUri", resourceUri);
        }

        @Override public String toString() { return "ExecutionGrantServiceBinding[redacted]"; }
    }

    static Set<String> scopes(Set<String> values, boolean allowEmpty) {
        values = values == null ? Set.of() : Set.copyOf(values);
        if ((!allowEmpty && values.isEmpty()) || values.size() > 32
                || values.stream().anyMatch(scope -> !scope.matches("[A-Za-z0-9:._-]{1,128}"))) {
            throw new IllegalArgumentException("EXECUTION_GRANT_SCOPE_INVALID");
        }
        return values;
    }

    static void secureIssuer(String value) {
        try {
            URI uri = URI.create(value);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                    || uri.getQuery() != null || uri.getFragment() != null || !uri.normalize().equals(uri)
                    || value.length() > 2048) throw new IllegalArgumentException();
        } catch (RuntimeException invalid) {
            throw new IllegalArgumentException("EXECUTION_GRANT_ISSUER_INVALID");
        }
    }
}
