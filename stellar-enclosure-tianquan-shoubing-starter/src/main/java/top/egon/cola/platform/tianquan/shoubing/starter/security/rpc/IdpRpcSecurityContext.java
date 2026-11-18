package top.egon.cola.platform.tianquan.shoubing.starter.security.rpc;

import io.grpc.Context;
import java.net.URI;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.NotBlank;
import top.egon.cola.component.rpc.consumer.reference.RpcServiceTargetVO;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.IdpAuthorizationObservationContextBO;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import top.egon.cola.platform.tianquan.shoubing.contract.IdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.IdpPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.starter.security.AccessTokenVerification;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.context.request.RequestContextHolder;
import org.slf4j.MDC;

import java.util.Objects;
import java.util.Set;

/**
 * Carries one verified USER or SERVICE identity through gRPC callbacks. Only USER tokens are
 * retained for relay; Spring credentials stay empty and each callback restores prior thread state.
 */
public final class IdpRpcSecurityContext {

    private static final Context.Key<IdpPrincipal> PRINCIPAL =
            Context.key("egon-tianquan-shoubing-user-principal");
    private static final Context.Key<String> TOKEN =
            Context.key("egon-tianquan-shoubing-user-token");

    private static final Context.Key<TokenAuditProofBO> PROOF = Context.key("egon-tianquan-shoubing-audit-proof");
    private static final Context.Key<Set<String>> SCOPES = Context.key("egon-tianquan-shoubing-oauth-scopes");
    private static final Context.Key<IdpAuthorizationObservationContextBO> OBSERVATION = Context.key("egon-tianquan-shoubing-authorization-observation");
    private static final Context.Key<URI> ISSUER = Context.key("egon-tianquan-shoubing-verified-issuer");
    private static final Context.Key<AuthorizedMethodVO> AUTHORIZED_METHOD = Context.key("egon-tianquan-shoubing-authorized-method");

    private IdpRpcSecurityContext() {
    }

    /**
     * Creates a child gRPC context containing the verified USER principal and token.
     *
     * @param principal verified USER principal
     * @param token verified raw USER access token
     * @return child context scoped to the current RPC
     */
    public static Context with(IdentityPrincipal principal, String token) {
        return with(principal, token, null);
    }

    public static Context with(IdentityPrincipal principal, String token, TokenAuditProofBO proof) {
        return with(principal, token, proof, null, Set.of());
    }

    public static Context with(IdpPrincipal principal, String token, TokenAuditProofBO proof,
            IdpAuthorizationObservationContextBO marker) {
        return with(principal, token, proof, marker, principal instanceof ServiceIdentityPrincipal service ? service.scopes() : Set.of());
    }

    public static Context with(IdpPrincipal principal, String token, TokenAuditProofBO proof,
            IdpAuthorizationObservationContextBO marker, Set<String> scopes) {
        return with(principal, token, proof, marker, scopes, null, null);
    }

    static Context with(IdpPrincipal principal, String token, TokenAuditProofBO proof,
            IdpAuthorizationObservationContextBO marker, Set<String> scopes, URI verifiedIssuer,
            AuthorizedMethodVO authorizedMethod) {
        var verified = new AccessTokenVerification.Valid<>(Objects.requireNonNull(principal, "principal"), scopes, proof, verifiedIssuer);
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("verified access token is required");
        }
        // Suppress a parent USER relay slot on a nested SERVICE call.
        return Context.current().withValues(PRINCIPAL, principal, TOKEN, principal instanceof IdentityPrincipal ? token : null)
                .withValues(PROOF, proof, SCOPES, verified.scopes(), OBSERVATION, marker)
                .withValues(ISSUER, verifiedIssuer, AUTHORIZED_METHOD, authorizedMethod);
    }

    /**
     * Returns the verified USER token in the current gRPC callback, if present.
     *
     * @return verified token or {@code null}
     */
    public static TokenAuditProofBO currentProofOrNull() { return PROOF.get(); }
    public static IdpPrincipal currentPrincipalOrNull() { return PRINCIPAL.get(); }
    public static IdpAuthorizationObservationContextBO currentAuthorizationObservationContext() { return OBSERVATION.get(); }
    static Set<String> currentScopesOrNull() { return SCOPES.get(); }
    static AuthorizedMethodVO authorizedMethodOrNull() { return AUTHORIZED_METHOD.get(); }

    static Context withoutAuthorizedMethod() {
        return Context.current().withValue(AUTHORIZED_METHOD, null);
    }

    public static String currentTokenOrNull() {
        return PRINCIPAL.get() instanceof IdentityPrincipal ? TOKEN.get() : null;
    }

    /**
     * Runs a callback with an identity-only Spring Security context and restores the exact
     * previous context afterward.
     *
     * @param principal verified USER principal
     * @param callback downstream callback
     */
    public static void runWithSpringSecurity(
            IdentityPrincipal principal,
            Runnable callback
    ) {
        runWithSpringSecurity(principal, currentProofOrNull(), callback);
    }

    public static void runWithSpringSecurity(IdentityPrincipal principal, TokenAuditProofBO proof, Runnable callback) {
        Set<String> scopes = Objects.equals(PRINCIPAL.get(), principal) && Objects.equals(PROOF.get(), proof) && SCOPES.get() != null
                ? SCOPES.get() : Set.of();
        runWithSpringSecurity(principal, scopes, proof, callback);
    }

    public static void runWithSpringSecurity(IdpPrincipal principal, Set<String> scopes, TokenAuditProofBO proof, Runnable callback) {
        URI issuer = Objects.equals(PRINCIPAL.get(), principal) && Objects.equals(PROOF.get(), proof)
                && Objects.equals(SCOPES.get(), scopes) ? ISSUER.get() : null;
        runWithSpringSecurity(principal, scopes, proof, issuer, callback);
    }

    static void runWithSpringSecurity(IdpPrincipal principal, Set<String> scopes, TokenAuditProofBO proof,
            URI verifiedIssuer, Runnable callback) {
        runWithSpringSecurity(authentication(principal, scopes, proof, verifiedIssuer), callback);
    }

    static IdpAuthenticationToken authentication(IdpPrincipal principal, Set<String> scopes,
            TokenAuditProofBO proof, URI verifiedIssuer) {
        Objects.requireNonNull(principal, "principal");
        var checked = new AccessTokenVerification.Valid<>(principal, scopes, proof, verifiedIssuer);
        var authentication = new IdpAuthenticationToken(principal, checked.scopes().stream()
                .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope)).toList(), verifiedIssuer);
        authentication.setDetails(proof);
        return authentication;
    }

    static void runWithSpringSecurity(IdpAuthenticationToken authentication, Runnable callback) {
        Objects.requireNonNull(authentication, "authentication");
        Objects.requireNonNull(callback, "callback");
        if (!authentication.isAuthenticated()) {
            throw new IllegalStateException("RPC_AUTHENTICATION_STATE_INVALID");
        }
        IdpPrincipal principal = authentication.getPrincipal();
        SecurityContext previous = SecurityContextHolder.getContext();
        var previousMdc = MDC.getCopyOfContextMap();
        var previousAttributes = RequestContextHolder.getRequestAttributes();
        SecurityContext current = SecurityContextHolder.createEmptyContext();
        current.setAuthentication(authentication);
        try {
            SecurityContextHolder.setContext(current);
            RequestContextHolder.resetRequestAttributes();
            if (principal.tenantId() == null) { MDC.remove("tenantId"); } else { MDC.put("tenantId", principal.tenantId()); }
            MDC.put("userId", principal instanceof ServiceIdentityPrincipal service ? service.clientId() : principal.subject());
            MDC.put("egon.auth.actor-kind", principal instanceof ServiceIdentityPrincipal ? "SERVICE" : "USER");
            callback.run();
        } finally {
            SecurityContextHolder.setContext(previous);
            RequestContextHolder.setRequestAttributes(previousAttributes);
            MDC.clear();
            if (previousMdc != null) { MDC.setContextMap(previousMdc); }
        }
    }

    /** Server-owned evidence that a required TENANT SERVICE method policy accepted this call. */
    record AuthorizedMethodVO(@NotBlank String fullMethodName, @NotNull URI issuer, @NotNull URI resource) {
        AuthorizedMethodVO {
            if (!RpcServiceTargetVO.isNativeMethodName(fullMethodName) || !canonicalHttps(issuer) || !canonicalHttps(resource)) {
                throw new IllegalArgumentException("RPC_AUTHORIZED_METHOD_INVALID");
            }
        }

        private static boolean canonicalHttps(URI value) {
            return value != null && value.isAbsolute() && !value.isOpaque() && "https".equals(value.getScheme())
                    && value.getHost() != null && value.getUserInfo() == null && value.getQuery() == null
                    && value.getFragment() == null && value.getPort() != 0 && value.getPort() <= 65535
                    && value.normalize().equals(value);
        }
    }
}
