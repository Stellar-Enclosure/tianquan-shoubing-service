package top.egon.cola.platform.tianquan.shoubing.yuheng.security;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import top.egon.cola.platform.tianquan.shoubing.starter.security.TenantIssuerAuthenticationManagerComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.VerifiedPrincipalConverter;
import top.egon.cola.component.yuheng.core.security.AuthenticationFailure;
import top.egon.cola.component.yuheng.core.security.GatewayAuthContext;
import top.egon.cola.platform.tianquan.shoubing.contract.IdpPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpObservedVerificationComponent;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.TokenAuditProofBO;
import top.egon.cola.platform.tianquan.shoubing.yuheng.security.domain.GatewayVerifiedIdentityBO;
import top.egon.cola.platform.tianquan.shoubing.starter.security.AccessTokenVerification;
import top.egon.cola.platform.tianquan.shoubing.starter.security.IdpJwtVerifier;

import java.time.Clock;
import java.util.Objects;
import java.util.Set;

/**
 * Adapts the shared USER/SERVICE verifier to the Gateway authentication SPI.
 */
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public final class IdpGatewayJwtVerifier
        implements IdpIdentityAuthenticationProvider.TokenVerifier {

    @Qualifier("gatewayResourceServerResolver")
    private final GatewayResourceServerResolver resources;
    @Qualifier("idpClock")
    private final Clock clock;
    @Qualifier("tenantIssuerAuthenticationManagerComponent")
    private final TenantIssuerAuthenticationManagerComponent issuerManager;
    @Qualifier("identityAuthorityClientResolver")
    private final top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClientResolver authority;
    @Qualifier("verifiedPrincipalConverter")
    private final VerifiedPrincipalConverter principalConverter;
    @Qualifier("idpObservedVerificationComponent")
    private final IdpObservedVerificationComponent observations;

    /** Fixed routing selects a target; the authority checks its current state for this exact token and resource. */
    public static IdpGatewayJwtVerifier createConfigured(GatewayResourceServerResolver resources, Clock clock,
            TenantIssuerAuthenticationManagerComponent issuerManager,
            top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClientResolver authority,
            VerifiedPrincipalConverter principalConverter, IdpObservedVerificationComponent observations) {
        if (issuerManager == null || !issuerManager.isConfigured()) { throw new IllegalStateException("GATEWAY_TRUSTED_ISSUERS_REQUIRED"); }
        if (observations == null || !observations.enabled()) { throw new IllegalStateException("IDENTITY_DURABLE_AUDIT_REQUIRED"); }
        return new IdpGatewayJwtVerifier(Objects.requireNonNull(resources, "resources"), Objects.requireNonNull(clock, "clock"),
                issuerManager, Objects.requireNonNull(authority, "authority"),
                Objects.requireNonNull(principalConverter, "principalConverter"), observations);
    }

    @Override
    public Verification verify(GatewayAuthContext context, String token) {
        java.net.URI resource;
        try { resource = resources.resolve(Objects.requireNonNull(context, "context").attributes()); }
        catch (GatewayResourceServerResolver.ResourceResolutionException invalid) {
            if (!observations.authenticationFailure()) { throw new IllegalStateException("OAUTH_AUDIT_DELIVERY_UNAVAILABLE"); }
            return Verification.invalid(invalid.getMessage());
        }
        var state = new top.egon.cola.platform.tianquan.shoubing.starter.security.impl.DatabaseOAuthRevocationReader(authority, resource);
        IdpJwtVerifier verifier = IdpJwtVerifier.createDatabaseConfigured(resource, clock, issuerManager, state, principalConverter, observations);
        AccessTokenVerification<IdpPrincipal> result = observations.observe(
                capture -> verifier.verifyAny(token, capture), resource, context.traceId());
        if (result instanceof AccessTokenVerification.Valid<IdpPrincipal> valid) {
            return Verification.valid(valid.principal(), valid.scopes(), valid.proof());
        }
        if (result instanceof AccessTokenVerification.Expired<?>) { return Verification.expired("JWT_EXPIRED"); }
        if (result instanceof AccessTokenVerification.Unavailable<?>) { throw new IllegalStateException("OAUTH_SECURITY_STATE_UNAVAILABLE"); }
        return Verification.invalid(((AccessTokenVerification.Invalid<IdpPrincipal>) result).reasonCode());
    }

    public record Verification(
            IdpPrincipal principal,
            AuthenticationFailure failure,
            String reason,
            @com.fasterxml.jackson.annotation.JsonIgnore Set<String> scopes,
            @com.fasterxml.jackson.annotation.JsonIgnore @jakarta.validation.Valid
            TokenAuditProofBO proof) {

        public Verification {
            scopes = new GatewayVerifiedIdentityBO(proof, scopes).verifiedScopes();
        }

        public Verification(IdpPrincipal principal, AuthenticationFailure failure, String reason) {
            this(principal, failure, reason,
                    principal instanceof ServiceIdentityPrincipal service ? service.scopes() : Set.of(), null);
        }

        static Verification valid(IdpPrincipal principal) {
            return new Verification(
                    Objects.requireNonNull(principal, "principal"),
                    AuthenticationFailure.NONE,
                    null);
        }

        static Verification valid(IdpPrincipal principal, Set<String> scopes, TokenAuditProofBO proof) {
            return new Verification(Objects.requireNonNull(principal, "principal"), AuthenticationFailure.NONE, null, scopes, proof);
        }

        static Verification expired(String reason) {
            return new Verification(null, AuthenticationFailure.EXPIRED, reason);
        }

        static Verification invalid(String reason) {
            return new Verification(null, AuthenticationFailure.INVALID, reason);
        }

        @Override public String toString() { return "Verification[failure=" + failure + ", reason=" + reason + "]"; }
    }

}
