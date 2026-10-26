package top.egon.cola.platform.tianquan.shoubing.starter.state;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceOAuth2Client;
import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpServiceTokenRequest;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TrustedIssuerRegistry;

/** Finite issuer-to-client routing; configuration is validated without acquiring or sharing a USER credential. */
public final class ConfiguredIdentityAuthorityClients implements IdentityAuthorityClientResolver {
    private final Map<AuthorityBinding, IdentityAuthorityClient> clients;
    private final URI defaultResource;

    public ConfiguredIdentityAuthorityClients(IdentityAuthorityProperties properties, IdpStarterProperties starter,
            TrustedIssuerRegistry issuers, IdpServiceOAuth2Client serviceOAuth, ObjectMapper mapper) {
        Objects.requireNonNull(properties, "properties");
        Objects.requireNonNull(serviceOAuth, "serviceOAuth");
        var transport = HttpIdentityAuthorityClient.boundedTransport(properties.getTimeout());
        this.defaultResource = Objects.requireNonNull(starter.getResourceUri(), "resourceUri");
        var configured = properties.getBindings();
        if (configured == null || configured.isEmpty() || configured.size() > 4096) {
            throw new IllegalStateException("IDENTITY_AUTHORITY_BINDINGS_REQUIRED");
        }
        Map<AuthorityBinding, IdentityAuthorityClient> values = new LinkedHashMap<>();
        configured.forEach((name, binding) -> {
            if (name == null || !name.matches("[A-Za-z0-9._-]{1,128}") || binding == null || binding.getIssuer() == null) {
                throw new IllegalStateException("IDENTITY_AUTHORITY_BINDING_INVALID");
            }
            var trusted = issuers.findByIssuer(binding.getIssuer().toASCIIString())
                    .orElseThrow(() -> new IllegalStateException("IDENTITY_AUTHORITY_ISSUER_UNTRUSTED"));
            var context = trusted.realmType() == TrustedIssuerRegistry.RealmType.TENANT
                    ? ServiceTokenContext.TENANT : ServiceTokenContext.PLATFORM;
            if (binding.getContext() != context || !Objects.equals(binding.getTenantId(), trusted.tenantId())
                    || binding.getScopes() == null || !binding.getScopes().containsAll(Set.of(
                            IdentityAuthorityScopes.STATE_RESOLVE, IdentityAuthorityScopes.AUDIT_APPEND))) {
                throw new IllegalStateException("IDENTITY_AUTHORITY_CONTEXT_INVALID");
            }
            URI sourceResource = binding.getSourceResource() == null ? defaultResource : binding.getSourceResource();
            if (!sourceResource.isAbsolute() || !sourceResource.equals(sourceResource.normalize()) || sourceResource.getFragment() != null
                    || sourceResource.getUserInfo() != null || sourceResource.toASCIIString().length() > 2048) {
                throw new IllegalStateException("IDENTITY_AUTHORITY_SOURCE_RESOURCE_INVALID");
            }
            var request = new IdpServiceTokenRequest(binding.getRegistrationId(), starter.getServiceClient().getAppId(),
                    binding.getAudience(), binding.getContext(), binding.getTenantId(), Set.copyOf(binding.getScopes()));
            var key = serviceOAuth.authorizationKey(request);
            if (!binding.getIssuer().toASCIIString().equals(key.issuer()) || values.putIfAbsent(new AuthorityBinding(binding.getIssuer(), sourceResource),
                    new HttpIdentityAuthorityClient(properties.getBaseUri(), transport, mapper, serviceOAuth, request)) != null) {
                throw new IllegalStateException("IDENTITY_AUTHORITY_REGISTRATION_INVALID");
            }
        });
        if (issuers.activeIssuers().stream().anyMatch(issuer -> !values.containsKey(new AuthorityBinding(issuer.issuer(), defaultResource)))) {
            throw new IllegalStateException("IDENTITY_AUTHORITY_BINDING_INCOMPLETE");
        }
        this.clients = Map.copyOf(values);
    }

    @Override
    public IdentityAuthorityClient forIssuer(URI verifiedIssuer) {
        return forResource(verifiedIssuer, defaultResource);
    }

    @Override
    public IdentityAuthorityClient forResource(URI verifiedIssuer, URI expectedResource) {
        var client = clients.get(new AuthorityBinding(Objects.requireNonNull(verifiedIssuer, "verifiedIssuer"),
                Objects.requireNonNull(expectedResource, "expectedResource")));
        if (client == null) { throw new IllegalStateException("IDENTITY_AUTHORITY_RESOURCE_UNBOUND"); }
        return client;
    }
    private record AuthorityBinding(URI issuer, URI resource) { }
}
