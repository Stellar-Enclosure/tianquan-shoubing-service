package top.egon.cola.platform.tianquan.shoubing.starter.security.impl;

import java.net.URI;
import java.util.Objects;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentitySecurityStateRequest;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityStatePurpose;
import top.egon.cola.platform.tianquan.shoubing.starter.security.OAuthRevocationReader;
import top.egon.cola.platform.tianquan.shoubing.starter.security.domain.VerifiedJwtBO;
import top.egon.cola.platform.tianquan.shoubing.starter.state.IdentityAuthorityClientResolver;

/** Queries the database owner for every locally verified access proof; failures never use a cached decision. */
public final class DatabaseOAuthRevocationReader implements OAuthRevocationReader {
    private final IdentityAuthorityClientResolver clients;
    private final URI resource;

    public DatabaseOAuthRevocationReader(IdentityAuthorityClientResolver clients, URI resource) {
        this.clients = Objects.requireNonNull(clients, "clients");
        this.resource = Objects.requireNonNull(resource, "resource");
    }

    @Override
    public Result check(VerifiedJwtBO proof) {
        try {
            proof.validate();
            var request = IdentitySecurityStateRequest.builder().purpose(IdentityStatePurpose.ACCESS_VALIDATION)
                    .accessToken(proof.getJwt().getTokenValue()).expectedResource(resource)
                    .expectedClientId(proof.getJwt().getClaimAsString("client_id")).build();
            var state = clients.forResource(proof.getTrustedIssuer().issuer(), resource).resolve(request);
            if (state == null || state.getPurpose() != IdentityStatePurpose.ACCESS_VALIDATION || (state.getReasonCode() == null || !state.getReasonCode().matches("[A-Z0-9_]{1,96}"))) {
                return Result.unavailable("IDENTITY_AUTHORITY_RESPONSE_INVALID");
            }
            if (!state.isEligible()) { return Result.revoked(state.getReasonCode()); }
            if (!Objects.equals(state.getIssuer(), proof.getTrustedIssuer().issuer().toASCIIString())
                    || !Objects.equals(state.getSubject(), proof.getSubject())
                    || state.getAuthorizationExpiresAt() == null
                    || state.getAuthorizationExpiresAt() < proof.getExpiresAt().getEpochSecond()
                    || !Objects.equals(state.getAuthorizationId(), proof.getAuthorizationId())
                    || !Objects.equals(state.getClientId(), request.getExpectedClientId())
                    || !Objects.equals(state.getResource(), resource.toASCIIString())
                    || !Objects.equals(state.getSecurityVersion(), proof.getSecurityVersion())) {
                return Result.unavailable("IDENTITY_AUTHORITY_RESPONSE_INVALID");
            }
            return Result.valid();
        } catch (RuntimeException unavailable) {
            return Result.unavailable("IDENTITY_AUTHORITY_UNAVAILABLE");
        }
    }
}
