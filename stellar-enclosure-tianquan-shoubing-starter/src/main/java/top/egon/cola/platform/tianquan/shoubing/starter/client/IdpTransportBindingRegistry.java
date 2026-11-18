package top.egon.cola.platform.tianquan.shoubing.starter.client;

import top.egon.cola.platform.tianquan.shoubing.starter.client.IdpTransportBindingVO.Operation;

import java.net.URI;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** A fixed snapshot of deployment routes. A configured family cannot fall back on a mismatch. */
public final class IdpTransportBindingRegistry {

    private static final int MAX_BINDINGS = 512;
    private static final IdpTransportBindingRegistry EMPTY = new IdpTransportBindingRegistry(List.of());

    private final Map<String, IdpTransportBindingVO> byId;
    private final Map<RouteKey, IdpTransportBindingVO> routes;
    private final Set<ScopeKey> configuredScopes;

    public IdpTransportBindingRegistry(
            IdpTransportBindingProperties properties, IdpTransportBindingConverter converter) {
        this(project(properties, converter));
    }

    public IdpTransportBindingRegistry(Collection<IdpTransportBindingVO> bindings) {
        Objects.requireNonNull(bindings, "bindings");
        if (bindings.size() > MAX_BINDINGS) {
            throw new IllegalArgumentException("IDP_TRANSPORT_BINDING_LIMIT");
        }
        var indexedBindings = new HashMap<String, IdpTransportBindingVO>();
        var indexedRoutes = new HashMap<RouteKey, IdpTransportBindingVO>();
        var scopes = new HashSet<ScopeKey>();
        for (IdpTransportBindingVO binding : bindings) {
            Objects.requireNonNull(binding, "binding");
            if (indexedBindings.putIfAbsent(binding.bindingId(), binding) != null
                    || indexedRoutes.putIfAbsent(RouteKey.from(binding), binding) != null) {
                throw new IllegalArgumentException("IDP_TRANSPORT_BINDING_CONFLICT");
            }
            scopes.add(new ScopeKey(binding.registrationId(), binding.operation().family()));
        }
        byId = Map.copyOf(indexedBindings);
        routes = Map.copyOf(indexedRoutes);
        configuredScopes = Set.copyOf(scopes);
    }

    public static IdpTransportBindingRegistry empty() {
        return EMPTY;
    }

    public boolean hasBindings(String registrationId, Operation operation) {
        return operation != null && configuredScopes.contains(new ScopeKey(registrationId, operation.family()));
    }

    public Optional<IdpTransportBindingVO> select(URI issuer, URI canonicalEndpoint, URI resource,
            String registrationId, Operation operation, String method) {
        if (!hasBindings(registrationId, operation)) {
            return Optional.empty();
        }
        IdpTransportBindingVO binding = routes.get(new RouteKey(issuer, canonicalEndpoint, resource,
                registrationId, operation, method));
        if (binding == null) {
            throw mismatch();
        }
        return Optional.of(binding);
    }

    public IdpTransportBindingVO require(String bindingId, long version,
            URI issuer, URI canonicalEndpoint, URI resource, String registrationId, Operation operation, String method) {
        if (bindingId == null || version <= 0) {
            throw mismatch();
        }
        IdpTransportBindingVO binding = byId.get(bindingId);
        var expected = new RouteKey(issuer, canonicalEndpoint, resource, registrationId, operation, method);
        if (binding == null || version != binding.version() || !expected.equals(RouteKey.from(binding))) {
            throw mismatch();
        }
        return binding;
    }

    private static Collection<IdpTransportBindingVO> project(
            IdpTransportBindingProperties properties, IdpTransportBindingConverter converter) {
        Objects.requireNonNull(properties, "properties");
        Objects.requireNonNull(converter, "converter");
        var inputs = Objects.requireNonNull(properties.getBindings(), "bindings");
        if (inputs.size() > MAX_BINDINGS) {
            throw new IllegalArgumentException("IDP_TRANSPORT_BINDING_LIMIT");
        }
        return inputs.entrySet().stream().map(entry -> {
            var configured = Objects.requireNonNull(entry.getValue(), "binding");
            String id = entry.getKey();
            if (configured.getBindingId() != null && !configured.getBindingId().equals(id)) {
                throw mismatch();
            }
            return converter.toTarget(configured.toBuilder().bindingId(id).build());
        }).toList();
    }

    private static IllegalArgumentException mismatch() {
        return new IllegalArgumentException("IDP_TRANSPORT_BINDING_MISMATCH");
    }

    private record ScopeKey(String registrationId, Operation family) {}

    private record RouteKey(URI issuer, URI endpoint, URI resource, String registrationId,
            Operation operation, String method) {

        static RouteKey from(IdpTransportBindingVO binding) {
            return new RouteKey(binding.canonicalIssuer(), binding.canonicalEndpoint(), binding.resource(),
                    binding.registrationId(), binding.operation(), binding.method());
        }
    }
}
