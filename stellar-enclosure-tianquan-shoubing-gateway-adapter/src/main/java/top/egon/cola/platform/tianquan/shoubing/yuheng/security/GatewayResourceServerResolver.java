package top.egon.cola.platform.tianquan.shoubing.yuheng.security;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import top.egon.cola.platform.tianquan.shoubing.yuheng.autoconfigure.IdpGatewayAdapterProperties;

/** Selects a fixed expected Resource from server-owned route attributes; it stores no security state. */
public final class GatewayResourceServerResolver {
    private final Map<RouteScope, URI> routes;
    private final Set<URI> resources;

    public GatewayResourceServerResolver(Map<String, IdpGatewayAdapterProperties.RouteResource> bindings) {
        if (bindings == null || bindings.isEmpty() || bindings.size() > 1024) {
            throw new IllegalArgumentException("GATEWAY_RESOURCE_BINDINGS_REQUIRED");
        }
        Map<RouteScope, URI> values = new LinkedHashMap<>();
        Set<URI> targets = new java.util.LinkedHashSet<>();
        bindings.forEach((name, binding) -> {
            if (name == null || !name.matches("[A-Za-z0-9._-]{1,128}") || binding == null) {
                throw new IllegalArgumentException("GATEWAY_RESOURCE_BINDING_INVALID");
            }
            URI target = resource(binding.getResourceUri());
            targets.add(target);
            if (binding.getBizCode() != null || binding.getAppCode() != null || binding.getEnvironment() != null) {
                RouteScope scope = new RouteScope(identifier(binding.getBizCode()), identifier(binding.getAppCode()),
                        identifier(binding.getEnvironment()));
                if (values.putIfAbsent(scope, target) != null) { throw new IllegalArgumentException("GATEWAY_RESOURCE_ROUTE_DUPLICATE"); }
            }
        });
        this.routes = Map.copyOf(values);
        this.resources = Set.copyOf(targets);
    }

    public Set<URI> targetResources() { return resources; }

    /** Only Gateway-produced context attributes are accepted; request headers never enter this resolver. */
    public URI resolve(Map<String, String> attributes) {
        Objects.requireNonNull(attributes, "attributes");
        String direct = attributes.get("tianquan-shoubing.resource-uri");
        URI target = null;
        if (direct != null) {
            try { target = resource(URI.create(direct)); }
            catch (IllegalArgumentException invalid) { throw new ResourceResolutionException("TIANQUAN_SHOUBING_RESOURCE_URI_INVALID"); }
            if (!resources.contains(target)) { throw new ResourceResolutionException("TIANQUAN_SHOUBING_RESOURCE_NOT_BOUND"); }
        }
        boolean hasRoute = attributes.containsKey("tianquan-shoubing.biz-code")
                || attributes.containsKey("tianquan-shoubing.app-code") || attributes.containsKey("tianquan-shoubing.env");
        if (hasRoute || target == null) {
            RouteScope scope;
            try { scope = new RouteScope(identifier(attributes.get("tianquan-shoubing.biz-code")),
                    identifier(attributes.get("tianquan-shoubing.app-code")), identifier(attributes.get("tianquan-shoubing.env"))); }
            catch (IllegalArgumentException invalid) { throw new ResourceResolutionException("TIANQUAN_SHOUBING_RESOURCE_ROUTE_INVALID"); }
            URI selected = routes.get(scope);
            if (selected == null) { throw new ResourceResolutionException("TIANQUAN_SHOUBING_RESOURCE_NOT_BOUND"); }
            if (target != null && !target.equals(selected)) { throw new ResourceResolutionException("TIANQUAN_SHOUBING_RESOURCE_ROUTE_MISMATCH"); }
            target = selected;
        }
        return target;
    }

    private static URI resource(URI value) {
        if (value == null || !value.isAbsolute() || !value.equals(value.normalize()) || value.getFragment() != null
                || value.getUserInfo() != null || value.toASCIIString().length() > 2048) {
            throw new IllegalArgumentException("GATEWAY_RESOURCE_URI_INVALID");
        }
        return value;
    }

    private static String identifier(String value) {
        if (value == null || !value.matches("[A-Za-z0-9._-]{1,128}")) { throw new IllegalArgumentException("GATEWAY_ROUTE_IDENTIFIER_INVALID"); }
        return value;
    }

    private record RouteScope(String business, String application, String environment) { }

    public static final class ResourceResolutionException extends RuntimeException {
        public ResourceResolutionException(String message) { super(message); }
        public ResourceResolutionException(String message, Throwable cause) { super(message, cause); }
    }
}
