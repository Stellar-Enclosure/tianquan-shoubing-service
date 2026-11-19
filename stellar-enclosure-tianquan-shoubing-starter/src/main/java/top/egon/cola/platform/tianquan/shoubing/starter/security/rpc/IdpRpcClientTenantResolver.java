package top.egon.cola.platform.tianquan.shoubing.starter.security.rpc;

import org.springframework.security.core.Authentication;
import top.egon.cola.component.rpc.consumer.interceptor.RpcClientInvocation;

import java.util.Optional;

/**
 * Opt-in adapter for a host application's already-authorized tenant context.
 * Called synchronously only after an exact native SERVICE/TENANT binding has matched.
 * This adapter must not derive authority from request payloads, wire metadata or MDC.
 */
@FunctionalInterface
public interface IdpRpcClientTenantResolver {

    /**
     * Returns a trusted tenant, or empty to retain the existing verified IdP-principal selection.
     * The authentication may be null. A null Optional or an exception rejects the call without
     * fallback; implementations must reject an invalid context for a target they take ownership of.
     */
    Optional<String> resolve(RpcClientInvocation invocation, Authentication authentication);

    /**
     * Optional canonical issuer pin captured synchronously under the same verified SERVICE/TENANT
     * binding as resolve. A pin is enforced inside the OAuth client's registration snapshot;
     * the eventual asynchronous credential task never calls this resolver again.
     * Existing functional implementations retain their original unpinned issuer strategy.
     */
    default Optional<String> expectedIssuer(RpcClientInvocation invocation, Authentication authentication) {
        return Optional.empty();
    }
}
