package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import org.springframework.boot.context.properties.ConfigurationProperties;
import top.egon.cola.platform.tianquan.jianshen.contract.permission.CanonicalJson;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Deployment-owned bindings for SERVICE subjects; no request chooses a trusted service. */
@ConfigurationProperties("egon.tianquan-shoubing.service-execution-grants")
public record OAuthServiceExecutionGrantProperties(boolean enabled, List<Binding> bindings) {
    public OAuthServiceExecutionGrantProperties {
        bindings = bindings == null ? List.of() : List.copyOf(bindings);
        if (bindings.size() > 256 || enabled && bindings.isEmpty()
                || bindings.stream().map(Binding::identity).distinct().count() != bindings.size()) {
            throw new IllegalArgumentException("SERVICE_EXECUTION_GRANT_BINDINGS_INVALID");
        }
        bindings.forEach(Binding::fingerprint);
    }

    public record Binding(String issuer, long tenantId, OAuthExecutionGrantProperties.Service source,
            OAuthExecutionGrantProperties.Service verifier, OAuthExecutionGrantProperties.Service subject,
            String purpose, Set<String> requiredServiceScopes, Set<String> sessionServiceScopes, Duration maxLifetime) {
        public Binding {
            OAuthExecutionGrantProperties.secureIssuer(issuer);
            if (tenantId <= 0 || source == null || verifier == null || subject == null || purpose == null
                    || !purpose.matches("[A-Z][A-Z0-9_]{0,95}") || source.clientPk() == verifier.clientPk()
                    || source.resourceUri().equals(verifier.resourceUri()) || subject.clientPk() == verifier.clientPk()
                    || subject.resourceUri().equals(verifier.resourceUri())) {
                throw new IllegalArgumentException("SERVICE_EXECUTION_GRANT_BINDING_INVALID");
            }
            requiredServiceScopes = OAuthExecutionGrantProperties.scopes(requiredServiceScopes, false);
            sessionServiceScopes = OAuthExecutionGrantProperties.scopes(sessionServiceScopes, true);
            maxLifetime = maxLifetime == null ? Duration.ofHours(1) : maxLifetime;
            if (maxLifetime.compareTo(Duration.ofSeconds(1)) < 0 || maxLifetime.compareTo(Duration.ofHours(8)) > 0) {
                throw new IllegalArgumentException("SERVICE_EXECUTION_GRANT_LIFETIME_INVALID");
            }
        }

        private String identity() {
            return issuer + "|" + tenantId + "|" + source.clientPk() + "|" + subject.clientPk() + "|" + purpose;
        }

        boolean matches(StoredServiceExecutionProof proof) {
            return proof != null && issuer.equals(proof.issuer()) && tenantId == proof.tenantId()
                    && source.resourceUri().equals(proof.resourceUri()) && subject.clientPk() == proof.clientPk()
                    && subject.clientId().equals(proof.clientId()) && subject.appId().equals(proof.appId())
                    && subject.businessCode().equals(proof.businessCode()) && subject.applicationCode().equals(proof.applicationCode())
                    && subject.environment().equals(proof.environment()) && subject.resourceUri().equals(proof.sourceResourceUri());
        }

        String fingerprint() {
            return CanonicalJson.digest(Map.of("version", 1, "issuer", issuer, "tenant", Long.toString(tenantId),
                    "source", source.values(), "verifier", verifier.values(), "subject", subject.values(), "purpose", purpose,
                    "requiredServiceScopes", requiredServiceScopes.stream().sorted().toList(),
                    "sessionServiceScopes", sessionServiceScopes.stream().sorted().toList(), "maxLifetime", maxLifetime.toString()));
        }

    }
}
