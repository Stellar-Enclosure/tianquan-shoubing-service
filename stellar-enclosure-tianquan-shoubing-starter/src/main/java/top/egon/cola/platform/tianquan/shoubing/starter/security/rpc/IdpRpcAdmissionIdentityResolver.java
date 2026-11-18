package top.egon.cola.platform.tianquan.shoubing.starter.security.rpc;

import com.google.protobuf.Message;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.annotation.Validated;
import top.egon.cola.component.rpc.provider.server.RpcAdmissionIdentityResolver;
import top.egon.cola.component.rpc.provider.server.RpcAdmissionIdentityVO;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;

import java.net.URI;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/** Adapts the method-authorized OAuth identity to the native RPC admission boundary. */
@Slf4j
@Validated
public class IdpRpcAdmissionIdentityResolver implements RpcAdmissionIdentityResolver {

    @Override
    public RpcAdmissionIdentityVO resolve(String fullMethodName, Message request) {
        var method = IdpRpcSecurityContext.authorizedMethodOrNull();
        var principal = IdpRpcSecurityContext.currentPrincipalOrNull();
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (method == null || principal == null
                || !(authentication instanceof IdpAuthenticationToken accepted)
                || !accepted.isAuthenticated()) {
            throw unauthenticated();
        }
        if (!(principal instanceof ServiceIdentityPrincipal service)
                || service.scopeContext() != ServiceTokenContext.TENANT
                || accepted.getPrincipal() != principal
                || !method.fullMethodName().equals(fullMethodName)) {
            throw denied();
        }
        URI issuer;
        try {
            issuer = accepted.verifiedIssuer();
        } catch (IllegalStateException missingIssuer) {
            throw unauthenticated();
        }
        Set<String> scopes = IdpRpcSecurityContext.currentScopesOrNull();
        if (!method.issuer().equals(issuer) || !method.resource().equals(service.resourceUri())
                || scopes == null || !scopes.equals(service.scopes())
                || !matchesAuthorities(accepted, scopes)) {
            throw denied();
        }
        var proof = IdpRpcSecurityContext.currentProofOrNull();
        if (!Objects.equals(proof, accepted.getDetails())
                || proof != null && (!method.issuer().equals(proof.issuer())
                || !method.resource().equals(proof.resource()))) {
            throw denied();
        }
        // Signature, expiry, current authority and strict audit were checked by the upstream
        // interceptor before it created this method frame. Neither the request body nor wire
        // metadata can supply a tenant, client or resource to this bridge.
        try {
            String tenant = service.tenantId();
            if (tenant == null || tenant.length() > 19) {
                throw denied();
            }
            long tenantId = Long.parseLong(tenant);
            if (tenantId <= 0L || !Long.toString(tenantId).equals(tenant)) {
                throw denied();
            }
            return new RpcAdmissionIdentityVO(tenantId, service.clientId(), method.resource().toASCIIString());
        } catch (IllegalArgumentException unsupportedIdentity) {
            throw denied();
        }
    }

    private boolean matchesAuthorities(IdpAuthenticationToken authentication, Set<String> scopes) {
        Set<String> expected = scopes.stream().map(scope -> "SCOPE_" + scope).collect(Collectors.toUnmodifiableSet());
        var authorities = authentication.getAuthorities();
        return authorities.size() == expected.size()
                && authorities.stream().allMatch(authority -> authority != null && expected.contains(authority.getAuthority()))
                && authorities.stream().map(authority -> authority.getAuthority()).distinct().count() == expected.size();
    }

    private StatusRuntimeException unauthenticated() {
        return Status.UNAUTHENTICATED.withDescription("RPC authenticated method identity is required").asRuntimeException();
    }

    private StatusRuntimeException denied() {
        return Status.PERMISSION_DENIED.withDescription("RPC admission identity is not authorized").asRuntimeException();
    }
}
