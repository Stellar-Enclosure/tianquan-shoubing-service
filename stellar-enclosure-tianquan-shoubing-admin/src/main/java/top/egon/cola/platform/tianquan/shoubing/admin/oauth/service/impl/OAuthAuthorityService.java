package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.component.common.crypto.digest.Digests;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.service.impl.OAuthAuditDeliveryService;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.repository.IdentityUserRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthenticationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.OAuthClientPurposeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthenticationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthorizationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthorityTokenVerifier.VerifiedAccess;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.bo.OAuthResourceBO;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthGrantRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthResourceRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthTokenTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthRevocationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthTokenRepository;
import top.egon.cola.platform.tianquan.shoubing.contract.OAuthSecurityVersionBO;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceIdentityPrincipal;
import top.egon.cola.platform.tianquan.shoubing.contract.ServiceTokenContext;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuditReceipt;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentitySecurityStateRequest;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentitySecurityStateResponse;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityStatePurpose;
import top.egon.cola.platform.tianquan.shoubing.core.audit.TokenUsageAuditEvent;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityUserStatus;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;
import top.egon.cola.platform.tianquan.shoubing.core.port.TenantMembershipPort;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ClientResourceGrant;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ResourceGrantType;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ResourceServerStatus;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties;

/** Terminates identity-state and audit requests at the PostgreSQL owner without remote recursion. */
@Service("oauthAuthorityService")
@RequiredArgsConstructor
public class OAuthAuthorityService {

    @Qualifier("oauthAuthorityTokenVerifier") private final OAuthAuthorityTokenVerifier verifier;
    @Qualifier("oAuthAuthorizationRepository") private final OAuthAuthorizationRepository authorizations;
    @Qualifier("oAuthClientRepository") private final OAuthClientRepository clients;
    @Qualifier("oAuthTokenRepository") private final OAuthTokenRepository tokens;
    @Qualifier("oAuthAuthenticationRepository") private final OAuthAuthenticationRepository authentications;
    @Qualifier("oAuthSecurityStateRepository") private final OAuthSecurityStateRepository securityStates;
    @Qualifier("oAuthRevocationRepository") private final OAuthRevocationRepository revocations;
    @Qualifier("oAuthResourceRepository") private final OAuthResourceRepository resources;
    @Qualifier("oAuthGrantRepository") private final OAuthGrantRepository grants;
    @Qualifier("identityUserRepository") private final IdentityUserRepository users;
    @Qualifier("tenantMembershipPort") private final TenantMembershipPort memberships;
    @Qualifier("oauthManagementRealmResolver") private final OAuthManagementRealmResolver managementRealms;
    @Qualifier("oauthAuditDeliveryService") private final OAuthAuditDeliveryService auditDelivery;
    @Qualifier("idpStarterProperties") private final IdpStarterProperties properties;
    @Qualifier("idpClock") private final Clock clock;

    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public Caller authenticateService(String compact, String requiredScope) {
        VerifiedAccess proof = verifier.verify(compact, properties.getResourceUri(), null, false);
        if (!"SERVICE".equals(proof.text("principal_type"))) { throw denied("AUTHORITY_SERVICE_REQUIRED"); }
        CurrentFacts facts = current(proof, compact);
        Set<String> scopes = scopes(proof);
        if (!scopes.contains(requiredScope)) { throw denied("AUTHORITY_SCOPE_REQUIRED"); }
        OAuthResourceBO source = resources.findBySource(managementRealms.platformRealm(), proof.text("source_biz"),
                proof.text("source_app"), proof.text("source_env"))
                .filter(value -> value.getStatus() == ResourceServerStatus.ACTIVE)
                .orElseThrow(() -> denied("AUTHORITY_SOURCE_NOT_ACTIVE"));
        if (!Objects.equals(source.getManagementClientId(), facts.client().getClientId())
                || !Objects.equals(proof.text("app_id"), facts.client().getAppId())) {
            throw denied("AUTHORITY_SOURCE_BINDING_INVALID");
        }
        var principal = new ServiceIdentityPrincipal(proof.claims().getSubject(), tenant(proof.realm()), facts.client().getClientId(),
                proof.claims().getJWTID(), properties.getResourceUri(), facts.resource().getVersion(), scopes,
                source.getBizCode(), source.getAppCode(), source.getEnvironment(), proof.text("credential_id"),
                proof.claims().getIssueTime().toInstant(), proof.claims().getExpirationTime().toInstant(), facts.client().getAppId(),
                proof.realm().getBusinessTenantId() == null ? ServiceTokenContext.PLATFORM : ServiceTokenContext.TENANT);
        return new Caller(principal, proof.realm(), facts.client().getId(), source.getResourceUri());
    }

    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public IdentitySecurityStateResponse resolve(Caller caller, IdentitySecurityStateRequest request) {
        Objects.requireNonNull(caller, "caller"); Objects.requireNonNull(request, "request");
        IdentityStatePurpose purpose = Objects.requireNonNull(request.getPurpose(), "purpose");
        boolean refresh = purpose == IdentityStatePurpose.REFRESH_CONTEXT;
        if (!caller.principal().scopes().contains(IdentityAuthorityScopes.STATE_RESOLVE)
                || refresh && !caller.principal().scopes().contains(IdentityAuthorityScopes.REFRESH_CONTEXT)
                || !caller.sourceResource().equals(request.getExpectedResource())) {
            throw denied("AUTHORITY_TARGET_NOT_BOUND");
        }
        return resolveTarget(caller.realm(), request);
    }

    /** Owner adapter for its fixed resource; external callers still require the dedicated SERVICE chain. */
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public IdentitySecurityStateResponse resolveOwnedResource(TrustedRealmBO realm, IdentitySecurityStateRequest request) {
        if (request == null || request.getPurpose() != IdentityStatePurpose.ACCESS_VALIDATION
                || !properties.getResourceUri().equals(request.getExpectedResource())) {
            throw denied("AUTHORITY_LOCAL_TARGET_NOT_BOUND");
        }
        return resolveTarget(realm, request);
    }

    private IdentitySecurityStateResponse resolveTarget(TrustedRealmBO expectedRealm, IdentitySecurityStateRequest request) {
        var purpose = request.getPurpose();
        boolean refresh = purpose == IdentityStatePurpose.REFRESH_CONTEXT;
        try {
            VerifiedAccess proof = verifier.verify(request.getAccessToken(), request.getExpectedResource(), request.getExpectedClientId(), refresh);
            if (!expectedRealm.getIssuer().equals(proof.realm().getIssuer())) { throw denied("AUTHORITY_TENANT_NOT_BOUND"); }
            CurrentFacts facts = current(proof, request.getAccessToken());
            if (refresh) { requireRefreshContext(request, proof, facts); }
            var response = IdentitySecurityStateResponse.builder().purpose(purpose).eligible(true).reasonCode("IDENTITY_STATE_CURRENT")
                    .issuer(proof.realm().getIssuer().toASCIIString()).resource(request.getExpectedResource().toASCIIString())
                    .clientId(facts.client().getClientId()).subject(proof.claims().getSubject())
                    .authorizationId(Long.toString(facts.authorization().getId()))
                    .authorizationExpiresAt(facts.authorization().getAbsoluteExpiresAt().getEpochSecond()).securityVersion(facts.version());
            if (facts.authentication() != null) {
                response.authenticationJti(proof.text("authn_jti"))
                        .authenticationExpiresAt(facts.authentication().getExpiresAt().getEpochSecond())
                        .refreshGeneration(Long.toString(facts.authorization().getRefreshGeneration()));
            }
            return response.build();
        } catch (OAuth2AuthenticationException rejected) {
            if ("temporarily_unavailable".equals(rejected.getError().getErrorCode())) { throw rejected; }
            return IdentitySecurityStateResponse.denied(purpose, "IDENTITY_STATE_REJECTED");
        }
    }

    public IdentityAuditReceipt appendAudit(Caller caller, TokenUsageAuditEvent event) {
        Objects.requireNonNull(caller, "caller"); Objects.requireNonNull(event, "event");
        if (!caller.principal().scopes().contains(IdentityAuthorityScopes.AUDIT_APPEND)
                || !caller.sourceResource().toASCIIString().equals(event.resource())
                || !caller.realm().getIssuer().equals(event.issuer())) { throw denied("AUTHORITY_AUDIT_TARGET_NOT_BOUND"); }
        var receipt = auditDelivery.append(caller.realm(), caller.clientPk(), caller.realm().getIssuer().toASCIIString(),
                caller.sourceResource().toASCIIString(), event);
        return new IdentityAuditReceipt(receipt.getReceiptId(), receipt.getEventId(), receipt.getEventFingerprint(),
                receipt.getSourceIssuer(), caller.principal().clientId(), receipt.getSourceResourceUri(), receipt.getOutcome(), receipt.getConfirmedAt());
    }

    /** The local producer identity comes from the owner's registered resource, never event fields. */
    public IdentityAuditReceipt appendOwnedAudit(TrustedRealmBO realm, TokenUsageAuditEvent event) {
        if (event == null || !properties.getResourceUri().toASCIIString().equals(event.resource())
                || !realm.getIssuer().equals(event.issuer())) { throw denied("AUTHORITY_LOCAL_AUDIT_NOT_BOUND"); }
        var resource = resources.findByResourceUri(managementRealms.platformRealm(), properties.getResourceUri())
                .filter(value -> value.getStatus() == ResourceServerStatus.ACTIVE)
                .orElseThrow(() -> denied("AUTHORITY_LOCAL_RESOURCE_NOT_ACTIVE"));
        var client = clients.findByClientId(realm, resource.getManagementClientId())
                .filter(value -> value.getStatus() == OAuthClient.Status.ACTIVE)
                .orElseThrow(() -> denied("AUTHORITY_LOCAL_CLIENT_NOT_ACTIVE"));
        var receipt = auditDelivery.append(realm, client.getId(), realm.getIssuer().toASCIIString(), event.resource(), event);
        return new IdentityAuditReceipt(receipt.getReceiptId(), receipt.getEventId(), receipt.getEventFingerprint(),
                receipt.getSourceIssuer(), client.getClientId(), receipt.getSourceResourceUri(), receipt.getOutcome(), receipt.getConfirmedAt());
    }

    private CurrentFacts current(VerifiedAccess proof, String compact) {
        TrustedRealmBO realm = proof.realm();
        boolean user = "USER".equals(proof.text("principal_type"));
        OAuthClientBO client = clients.findById(realm, proof.clientPk())
                .filter(value -> value.getStatus() == OAuthClient.Status.ACTIVE && value.getClientId().equals(proof.text("client_id"))
                        && (value.getPurpose() == OAuthClientPurposeEnum.USER) == user)
                .orElseThrow(() -> invalid("JWT_CLIENT_NOT_ACTIVE"));
        OAuthAuthorizationBO family = authorizations.findById(realm, proof.authorizationId())
                .filter(value -> "ACTIVE".equals(value.getStatus()) && value.getAbsoluteExpiresAt().isAfter(clock.instant())
                        && Objects.equals(value.getClientPk(), client.getId())
                        && Objects.equals(value.getPrincipalName(), proof.claims().getSubject())
                        && Objects.equals(value.getPrincipalType(), proof.text("principal_type"))
                        && value.getAudiences().equals(proof.claims().getAudience()))
                .orElseThrow(() -> invalid("JWT_AUTHORIZATION_NOT_ACTIVE"));
        var token = tokens.findByTokenDigest(realm, Digests.sha256Hex(compact))
                .filter(value -> value.getTokenType() == OAuthTokenTypeEnum.ACCESS && value.getRevokedAt() == null
                        && Objects.equals(value.getAuthorizationPk(), family.getId()) && Objects.equals(value.getJti(), proof.claims().getJWTID()))
                .orElseThrow(() -> invalid("JWT_TOKEN_FACT_MISSING"));
        URI target = URI.create(proof.claims().getAudience().getFirst());
        OAuthResourceBO resource = resources.findByResourceUri(managementRealms.platformRealm(), target)
                .filter(value -> value.getStatus() == ResourceServerStatus.ACTIVE)
                .orElseThrow(() -> invalid("JWT_RESOURCE_NOT_ACTIVE"));
        if (!user && number(proof, "resource_version") != resource.getVersion()) { throw invalid("JWT_RESOURCE_VERSION_STALE"); }
        var grant = grants.findGrant(realm, client.getId(), resource.getResourceServerId(),
                        user ? ResourceGrantType.USER_DELEGATION : ResourceGrantType.CLIENT_CREDENTIALS)
                .filter(value -> value.getStatus() == ClientResourceGrant.Status.ACTIVE
                        && value.getResourceVersion() == resource.getVersion())
                .orElseThrow(() -> invalid("JWT_RESOURCE_GRANT_NOT_ACTIVE"));
        Set<String> requestedScopes = scopes(proof);
        Set<String> resourceScopes = new TreeSet<>(requestedScopes);
        if (user) { resourceScopes.removeAll(Set.of("openid", "profile", "email")); }
        if (!family.getAuthorizedScopes().containsAll(requestedScopes) || !client.getAllowedScopes().containsAll(requestedScopes)
                || !grant.getAllowedScopes().containsAll(resourceScopes)) {
            throw invalid("JWT_SCOPE_NO_LONGER_ALLOWED");
        }
        OAuthSecurityVersionBO version = version(proof, user);
        generation(realm, OAuthSecurityTargetEnum.REALM, "self", version.getRealm());
        generation(realm, OAuthSecurityTargetEnum.CLIENT, Long.toString(client.getId()), version.getClient());
        if (user) { generation(realm, OAuthSecurityTargetEnum.SUBJECT, proof.claims().getSubject(), version.getSubject()); }
        for (var revoked : List.of(Map.entry(OAuthSecurityTargetEnum.JTI, proof.claims().getJWTID()),
                Map.entry(OAuthSecurityTargetEnum.AUTHORIZATION, Long.toString(family.getId())), Map.entry(OAuthSecurityTargetEnum.KID, proof.keyId()))) {
            if (revocations.findByTarget(realm, revoked.getKey(), revoked.getValue()).isPresent()) { throw invalid("JWT_REVOKED"); }
        }
        OAuthAuthenticationBO authentication = null;
        if (user) {
            users.findByIdentitySub(proof.claims().getSubject()).filter(value -> value.status() == IdentityUserStatus.ACTIVE)
                    .orElseThrow(() -> invalid("JWT_ACCOUNT_NOT_ACTIVE"));
            var membership = memberships.resolve(proof.claims().getSubject(), tenant(realm));
            if (membership == null || membership.status() != TenantMembershipPort.MembershipStatus.ACTIVE) { throw invalid("JWT_MEMBERSHIP_NOT_ACTIVE"); }
            String jtiDigest = Digests.sha256Hex(proof.text("authn_jti"));
            if (!Objects.equals(jtiDigest, family.getAuthenticationJtiDigest())) { throw invalid("JWT_AUTHENTICATION_BINDING_INVALID"); }
            authentication = authentications.findByJtiDigest(realm, jtiDigest)
                    .filter(value -> !"REVOKED".equals(value.getStatus()) && value.getRevokedAt() == null
                            && value.getSubject().equals(proof.claims().getSubject())
                            && value.getAcr().equals(proof.text("acr"))
                            && value.getAuthenticatedAt().getEpochSecond() == number(proof, "auth_time")
                            && value.getSubjectGeneration().equals(version.getSubject()) && value.getRealmGeneration() == version.getRealm())
                    .orElseThrow(() -> invalid("JWT_AUTHENTICATION_REVOKED"));
            if (number(proof, "authorization_expires_at") != family.getAbsoluteExpiresAt().getEpochSecond()
                    || number(proof, "authn_expires_at") != authentication.getExpiresAt().getEpochSecond()
                    || refreshGeneration(proof) > family.getRefreshGeneration()) { throw invalid("JWT_FAMILY_FACT_MISMATCH"); }
        }
        return new CurrentFacts(client, family, authentication, resource, version);
    }

    private void requireRefreshContext(IdentitySecurityStateRequest request, VerifiedAccess proof, CurrentFacts facts) {
        if (!facts.client().isBrowserBound() || facts.authentication() == null
                || request.getRefreshTokenDigest() == null || !request.getRefreshTokenDigest().matches("[0-9a-f]{64}")
                || request.getBrowserBindingDigest() == null || !request.getBrowserBindingDigest().matches("[0-9a-f]{64}")
                || !Objects.equals(request.getBrowserBindingDigest(), facts.authorization().getClientBrowserBindingDigest())
                || refreshGeneration(proof) != facts.authorization().getRefreshGeneration()) {
            throw invalid("JWT_REFRESH_CONTEXT_NOT_BOUND");
        }
        tokens.findByTokenDigest(proof.realm(), request.getRefreshTokenDigest())
                .filter(value -> value.getTokenType() == OAuthTokenTypeEnum.REFRESH && value.getConsumedAt() == null
                        && value.getRevokedAt() == null && value.getExpiresAt().isAfter(clock.instant())
                        && Objects.equals(value.getAuthorizationPk(), facts.authorization().getId())
                        && value.getRefreshGeneration() != null && value.getRefreshGeneration() == facts.authorization().getRefreshGeneration())
                .orElseThrow(() -> invalid("JWT_REFRESH_GENERATION_NOT_CURRENT"));
    }

    private void generation(TrustedRealmBO realm, OAuthSecurityTargetEnum target, String key, long expected) {
        securityStates.findByTarget(realm, target, key).filter(value -> value.isEnabled() && value.getGeneration() == expected)
                .orElseThrow(() -> invalid("JWT_SECURITY_VERSION_STALE"));
    }

    private static OAuthSecurityVersionBO version(VerifiedAccess proof, boolean user) {
        Object raw = proof.claims().getClaim("security_version");
        if (!(raw instanceof Map<?, ?> fields) || fields.size() != (user ? 3 : 2)
                || !fields.containsKey("realm") || !fields.containsKey("client") || user != fields.containsKey("subject")) {
            throw invalid("JWT_SECURITY_VERSION_INVALID");
        }
        return OAuthSecurityVersionBO.builder().realm(integer(fields.get("realm"))).client(integer(fields.get("client")))
                .subject(user ? integer(fields.get("subject")) : null).build();
    }

    private static Set<String> scopes(VerifiedAccess proof) {
        String value = proof.text("scope");
        TreeSet<String> scopes = new TreeSet<>(Arrays.asList(value.split(" ", -1)));
        if (scopes.isEmpty() || scopes.size() > 64 || scopes.stream().anyMatch(scope -> !scope.matches("[A-Za-z0-9:._-]{1,128}"))) {
            throw invalid("JWT_SCOPE_INVALID");
        }
        return Set.copyOf(scopes);
    }

    private static long refreshGeneration(VerifiedAccess proof) {
        String value = proof.text("refresh_generation");
        if (!value.matches("0|[1-9][0-9]{0,18}")) { throw invalid("JWT_REFRESH_GENERATION_INVALID"); }
        try { return Long.parseLong(value); }
        catch (NumberFormatException overflow) { throw invalid("JWT_REFRESH_GENERATION_INVALID"); }
    }

    private static long number(VerifiedAccess proof, String claim) { return integer(proof.claims().getClaim(claim)); }
    private static long integer(Object raw) {
        if (!(raw instanceof Number number) || number.longValue() < 0 || number.doubleValue() != (double) number.longValue()) {
            throw invalid("JWT_NUMBER_INVALID");
        }
        return number.longValue();
    }
    private static String tenant(TrustedRealmBO realm) { return realm.getBusinessTenantId() == null ? null : realm.getBusinessTenantId().toString(); }
    private static OAuth2AuthenticationException invalid(String reason) { return new OAuth2AuthenticationException(new OAuth2Error("invalid_token", reason, null)); }
    private static AccessDeniedException denied(String reason) { return new AccessDeniedException(reason); }

    public record Caller(ServiceIdentityPrincipal principal, TrustedRealmBO realm, long clientPk, URI sourceResource) { }
    private record CurrentFacts(OAuthClientBO client, OAuthAuthorizationBO authorization, OAuthAuthenticationBO authentication,
            OAuthResourceBO resource, OAuthSecurityVersionBO version) { }
}
