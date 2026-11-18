package top.egon.cola.platform.tianquan.shoubing.starter.client;

import java.net.URI;
import java.util.Set;
import java.util.regex.Pattern;

/** The reviewed OAuth identity and its exact Kubernetes transport destination. */
public record IdpTransportBindingVO(
        String bindingId,
        long version,
        URI canonicalIssuer,
        URI canonicalEndpoint,
        URI resource,
        String registrationId,
        Operation operation,
        String method,
        String path,
        String namespace,
        String service,
        int port,
        Transport transport) {

    private static final Pattern LABEL = Pattern.compile("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?");
    private static final Pattern REGISTRATION = Pattern.compile("[A-Za-z0-9._-]{1,128}");
    private static final Set<String> RESOURCE_METHODS =
            Set.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS");

    public IdpTransportBindingVO {
        requireLabel(bindingId);
        requireLabel(namespace);
        requireLabel(service);
        requireCanonical(canonicalIssuer);
        requireCanonical(canonicalEndpoint);
        requireCanonical(resource);
        if (version <= 0 || !isRegistration(registrationId) || operation == null
                || port <= 0 || port > 65535 || transport == null) {
            throw invalidBinding();
        }
        String endpointPath = canonicalEndpoint.getRawPath();
        if (path == null || path.length() > 1024 || !path.startsWith("/") || path.contains("//")
                || path.contains("%") || !path.equals(endpointPath)
                || path.codePoints().anyMatch(value -> value < 0x21 || value > 0x7e)
                || !operation.accepts(method, transport)) {
            throw invalidBinding();
        }
    }

    public URI physicalUri() {
        return URI.create("http://" + service + "." + namespace + ".svc.cluster.local:" + port + path);
    }

    static void requireCanonical(URI uri) {
        if (uri == null || !"https".equals(uri.getScheme()) || uri.getHost() == null
                || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                || uri.getPort() == 0 || uri.getPort() > 65535 || !uri.normalize().equals(uri)) {
            throw invalidBinding();
        }
    }

    private static boolean isRegistration(String value) {
        return value != null && REGISTRATION.matcher(value).matches();
    }

    private static void requireLabel(String value) {
        if (value == null || !LABEL.matcher(value).matches()) {
            throw invalidBinding();
        }
    }

    private static IllegalArgumentException invalidBinding() {
        return new IllegalArgumentException("IDP_TRANSPORT_BINDING_INVALID");
    }

    public enum Transport {
        HTTP, H2C
    }

    public enum Operation {
        TOKEN,
        RESOURCE,
        AUTHORITY_RESOLVE,
        AUTHORITY_AUDIT,
        EXECUTION_ISSUE,
        EXECUTION_RESOLVE,
        EXECUTION_REVOKE,
        SERVICE_EXECUTION_ISSUE,
        SERVICE_EXECUTION_RESOLVE,
        SERVICE_EXECUTION_REVOKE,
        JWKS,
        RPC;

        Operation family() {
            return switch (this) {
                case AUTHORITY_RESOLVE, AUTHORITY_AUDIT -> AUTHORITY_RESOLVE;
                case EXECUTION_ISSUE, EXECUTION_RESOLVE, EXECUTION_REVOKE,
                        SERVICE_EXECUTION_ISSUE, SERVICE_EXECUTION_RESOLVE, SERVICE_EXECUTION_REVOKE -> EXECUTION_ISSUE;
                default -> this;
            };
        }

        private boolean accepts(String method, Transport transport) {
            if (this == RPC) {
                return "POST".equals(method) && transport == Transport.H2C;
            }
            if (transport != Transport.HTTP || method == null) {
                return false;
            }
            return switch (this) {
                case RESOURCE -> RESOURCE_METHODS.contains(method);
                case JWKS -> "GET".equals(method);
                default -> "POST".equals(method);
            };
        }
    }
}
