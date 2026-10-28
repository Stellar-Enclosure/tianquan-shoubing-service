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
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthTokenBO;
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
    private volatile OAuthExecutionPrimaryGuard executionPrimary;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setExecutionPrimary(@Qualifier("oauthExecutionPrimaryGuard") OAuthExecutionPrimaryGuard guard) {
        this.executionPrimary = Objects.requireNonNull(guard, "guard");
    }

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
        return new Caller(principal, proof.realm(), facts.client().getId(), source.getResourceUri(),
                facts.version().getRealm(), facts.version().getClient(), facts.authorization().getId(),
                Digests.sha256Hex(compact), facts.token().getRetainUntil(), proof.keyId());
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

    /** Captures only the facts needed to recheck a verified USER; no bearer is retained. */
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    StoredUserExecutionProof captureExecutionUser(Caller caller, URI resource, String userToken) {
        return captureExecutionUser(caller, resource, userToken, IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE);
    }

    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    StoredUserExecutionProof captureExecutionUser(Caller caller, URI resource, String userToken, String requiredScope) {
        requireExecutionPrimary();
        Objects.requireNonNull(caller, "caller");
        caller.realm().validateTrustedPartition();
        if (requiredScope == null || !Set.of(IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE,
                IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE).contains(requiredScope)
                || caller.clientPk() <= 0 || caller.principal().scopeContext() != ServiceTokenContext.TENANT
                || !Objects.equals(caller.principal().tenantId(), tenant(caller.realm()))
                || !caller.principal().scopes().contains(requiredScope)
                || !caller.principal().expiresAt().isAfter(clock.instant()) || resource == null
                || !caller.sourceResource().toASCIIString().equals(resource.toASCIIString())) {
            throw denied("EXECUTION_USER_SOURCE_NOT_BOUND");
        }
        VerifiedAccess proof = verifier.verify(userToken, resource, null, false);
        if (!"USER".equals(proof.text("principal_type"))
                || !caller.realm().getIssuer().toASCIIString().equals(proof.realm().getIssuer().toASCIIString())
                || !Objects.equals(caller.realm().getBusinessTenantId(), proof.realm().getBusinessTenantId())
                || !Objects.equals(caller.realm().getTrustVersion(), proof.realm().getTrustVersion())) {
            throw denied("EXECUTION_USER_REALM_NOT_BOUND");
        }
        CurrentFacts facts = current(proof, userToken);
        requireExecutionLifetime(facts);
        var stored = new StoredUserExecutionProof(proof.realm().getIssuer().toASCIIString(),
                proof.realm().getBusinessTenantId(), proof.realm().getTrustVersion(), proof.claims().getSubject(),
                resource.toASCIIString(), proof.clientPk(), facts.client().getClientId(), proof.authorizationId(),
                Digests.sha256Hex(userToken), proof.claims().getJWTID(), proof.keyId(), scopes(proof),
                facts.version().getRealm(), facts.version().getClient(), facts.version().getSubject(),
                Digests.sha256Hex(proof.text("authn_jti")), proof.text("acr"), number(proof, "auth_time"),
                number(proof, "authn_expires_at"), number(proof, "authorization_expires_at"),
                refreshGeneration(proof), facts.token().getRetainUntil());
        requireExecutionTokenEvidence(facts.token(), stored);
        return stored;
    }

    /** Call only with evidence loaded from an owner-controlled, run-bound execution grant. */
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    ExecutionUserCurrent recheckExecutionUser(TrustedRealmBO realm, StoredUserExecutionProof stored) {
        requireExecutionPrimary();
        Objects.requireNonNull(stored, "stored");
        stored.requireRealm(realm);
        verifier.requireRecordedKey(realm, stored.signingKeyId());
        var version = OAuthSecurityVersionBO.builder().realm(stored.realmGeneration()).client(stored.clientGeneration())
                .subject(stored.subjectGeneration()).build();
        var recorded = new CurrentAccessFacts(realm, true, stored.subject(), stored.clientPk(), stored.clientId(),
                stored.authorizationId(), List.of(stored.resourceUri()), stored.tokenJti(), stored.signingKeyId(),
                stored.scopes(), version, stored.acr(), stored.authenticationTime(), stored.authenticationExpiresAt(),
                stored.authorizationExpiresAt(), stored.refreshGeneration(), 0);
        CurrentFacts facts = currentByDigest(recorded, stored.tokenDigest(), stored.authenticationJtiDigest());
        requireExecutionLifetime(facts);
        requireExecutionTokenEvidence(facts.token(), stored);
        Instant validUntil = facts.authorization().getAbsoluteExpiresAt();
        if (facts.authentication().getExpiresAt().isBefore(validUntil)) validUntil = facts.authentication().getExpiresAt();
        if (facts.token().getRetainUntil().isBefore(validUntil)) validUntil = facts.token().getRetainUntil();
        if (stored.tokenRetainUntil().isBefore(validUntil)) validUntil = stored.tokenRetainUntil();
        if (Instant.ofEpochSecond(stored.authenticationExpiresAt()).isBefore(validUntil)) {
            validUntil = Instant.ofEpochSecond(stored.authenticationExpiresAt());
        }
        if (Instant.ofEpochSecond(stored.authorizationExpiresAt()).isBefore(validUntil)) {
            validUntil = Instant.ofEpochSecond(stored.authorizationExpiresAt());
        }
        if (!validUntil.isAfter(clock.instant())) throw invalid("EXECUTION_USER_PROOF_EXPIRED");
        return new ExecutionUserCurrent(stored.issuer(), stored.tenantId(), stored.subject(), stored.resourceUri(),
                stored.scopes(), validUntil);
    }

    /** Rechecks the authenticated SERVICE in the same primary transaction as the grant operation. */
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    void requireExecutionService(Caller caller, ExecutionGrantEnvelope.ServiceBinding binding,
                                 StoredUserExecutionProof user, String requiredScope) {
        requireExecutionPrimary();
        if (!binding.matches(caller, user, requiredScope, clock.instant())) throw denied("EXECUTION_SERVICE_NOT_BOUND");
        var evidence = new CurrentServiceEvidence(binding, caller.realmGeneration(), caller.clientGeneration(),
                caller.authorizationId(), caller.tokenDigest(), caller.principal().tokenId(), caller.tokenRetainUntil(),
                caller.signingKeyId());
        requireCurrentServiceFacts(caller.realm(), evidence, requiredScope);
    }

    /** Rechecks the original issuing service without retaining its bearer. */
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    void requireRecordedExecutionSource(TrustedRealmBO realm, ExecutionGrantEnvelope envelope, String requiredScope) {
        requireExecutionPrimary();
        envelope.user().requireRealm(realm);
        var evidence = new CurrentServiceEvidence(envelope.source(), envelope.sourceRealmGeneration(),
                envelope.sourceClientGeneration(), envelope.sourceAuthorizationId(), envelope.sourceTokenDigest(),
                envelope.sourceTokenJti(), envelope.sourceTokenRetainUntil(), envelope.sourceSigningKeyId());
        requireCurrentServiceFacts(realm, evidence, requiredScope);
    }

    private void requireCurrentServiceFacts(TrustedRealmBO realm, CurrentServiceEvidence evidence, String requiredScope) {
        var binding = evidence.binding();
        Instant now = clock.instant();
        if (requiredScope == null || !requiredScope.matches("[A-Za-z0-9:._-]{1,128}")
                || !evidence.tokenRetainUntil().isAfter(now)) throw invalid("EXECUTION_SERVICE_PROOF_INVALID");
        verifier.requireRecordedKey(realm, evidence.signingKeyId());
        OAuthClientBO client = clients.findById(realm, binding.clientPk())
                .filter(value -> value.getStatus() == OAuthClient.Status.ACTIVE && value.getPurpose() == OAuthClientPurposeEnum.SERVICE
                        && binding.clientId().equals(value.getClientId()) && binding.appId().equals(value.getAppId())
                        && value.getAllowedScopes().contains(requiredScope))
                .orElseThrow(() -> invalid("EXECUTION_SERVICE_CLIENT_INACTIVE"));
        OAuthAuthorizationBO family = authorizations.findById(realm, evidence.authorizationId())
                .filter(value -> ("ACTIVE".equals(value.getStatus()) || "EXPIRED".equals(value.getStatus())
                            && value.getAbsoluteExpiresAt() != null && !value.getAbsoluteExpiresAt().isAfter(now))
                        && value.getRevokedAt() == null && Objects.equals(value.getClientPk(), client.getId())
                        && "SERVICE".equals(value.getPrincipalType()) && binding.clientId().equals(value.getPrincipalName())
                        && value.getAudiences().equals(List.of(properties.getResourceUri().toASCIIString()))
                        && value.getAuthorizedScopes().contains(requiredScope))
                .orElseThrow(() -> invalid("EXECUTION_SERVICE_AUTHORIZATION_INVALID"));
        OAuthTokenBO token = tokens.findByTokenDigest(realm, evidence.tokenDigest())
                .filter(value -> value.getTokenType() == OAuthTokenTypeEnum.ACCESS && value.getRevokedAt() == null
                        && Objects.equals(value.getAuthorizationPk(), family.getId()) && evidence.tokenJti().equals(value.getJti())
                        && value.getRetainUntil() != null && value.getRetainUntil().isAfter(now))
                .orElseThrow(() -> invalid("EXECUTION_SERVICE_TOKEN_INVALID"));
        resources.findBySource(managementRealms.platformRealm(), binding.businessCode(),
                        binding.applicationCode(), binding.environment())
                .filter(value -> value.getStatus() == ResourceServerStatus.ACTIVE
                        && binding.resourceUri().equals(value.getResourceUri().toASCIIString())
                        && binding.clientId().equals(value.getManagementClientId()))
                .orElseThrow(() -> invalid("EXECUTION_SERVICE_SOURCE_INVALID"));
        var target = resources.findByResourceUri(managementRealms.platformRealm(), properties.getResourceUri())
                .filter(value -> value.getStatus() == ResourceServerStatus.ACTIVE)
                .orElseThrow(() -> invalid("EXECUTION_SERVICE_TARGET_INVALID"));
        grants.findGrant(realm, client.getId(), target.getResourceServerId(), ResourceGrantType.CLIENT_CREDENTIALS)
                .filter(value -> value.getStatus() == ClientResourceGrant.Status.ACTIVE
                        && value.getResourceVersion() == target.getVersion() && value.getAllowedScopes().contains(requiredScope))
                .orElseThrow(() -> invalid("EXECUTION_SERVICE_GRANT_INVALID"));
        generation(realm, OAuthSecurityTargetEnum.REALM, "self", evidence.realmGeneration());
        generation(realm, OAuthSecurityTargetEnum.CLIENT, Long.toString(client.getId()), evidence.clientGeneration());
        for (var revoked : List.of(Map.entry(OAuthSecurityTargetEnum.JTI, evidence.tokenJti()),
                Map.entry(OAuthSecurityTargetEnum.AUTHORIZATION, Long.toString(family.getId())),
                Map.entry(OAuthSecurityTargetEnum.KID, evidence.signingKeyId()))) {
            if (revocations.findByTarget(realm, revoked.getKey(), revoked.getValue()).isPresent()) {
                throw invalid("EXECUTION_SERVICE_REVOKED");
            }
        }
        var metadata = token.getMetadata();
        var claims = metadata == null ? null : metadata.getClaims();
        var version = claims == null ? null : claims.getSecurityVersion();
        if (metadata == null || metadata.getSchemaVersion() != 1 || metadata.isInvalidated() || claims == null
                || claims.getTokenUse() != OAuthTokenTypeEnum.ACCESS || claims.getIssuer() == null
                || !realm.getIssuer().toASCIIString().equals(claims.getIssuer().toASCIIString())
                || !Set.of(properties.getResourceUri()).equals(claims.getAudience())
                || !binding.clientId().equals(claims.getSubject()) || !"SERVICE".equals(claims.getPrincipalType())
                || !"TENANT".equals(claims.getScopeContext()) || !realm.getBusinessTenantId().equals(claims.getTenantId())
                || !binding.clientId().equals(claims.getClientId()) || !binding.appId().equals(claims.getAppId())
                || !Long.toString(binding.clientPk()).equals(claims.getClientRegistrationId())
                || !Long.toString(family.getId()).equals(claims.getAuthorizationId()) || !evidence.tokenJti().equals(claims.getJti())
                || !binding.businessCode().equals(claims.getSourceBiz()) || !binding.applicationCode().equals(claims.getSourceApp())
                || !binding.environment().equals(claims.getSourceEnv()) || claims.getScope() == null
                || !claims.getScope().contains(requiredScope) || claims.getResourceVersion() == null
                || claims.getResourceVersion() != target.getVersion() || version == null
                || version.getRealm() != evidence.realmGeneration() || version.getClient() != evidence.clientGeneration()
                || version.getSubject() != null) {
            throw invalid("EXECUTION_SERVICE_PROOF_MISMATCH");
        }
    }

    private void requireExecutionLifetime(CurrentFacts facts) {
        if (facts.authentication() == null || !"ACTIVE".equals(facts.authentication().getStatus())
                || facts.authentication().getExpiresAt() == null
                || !facts.authentication().getExpiresAt().isAfter(clock.instant())
                || facts.token().getRetainUntil() == null || !facts.token().getRetainUntil().isAfter(clock.instant())) {
            throw invalid("EXECUTION_USER_PROOF_EXPIRED");
        }
    }

    private void requireExecutionPrimary() {
        OAuthExecutionPrimaryGuard guard = executionPrimary;
        if (guard == null) throw new OAuth2AuthenticationException(
                new OAuth2Error("temporarily_unavailable", "EXECUTION_AUTHORITY_PRIMARY_REQUIRED", null));
        guard.requirePrimaryTransaction();
    }

    private static void requireExecutionTokenEvidence(OAuthTokenBO token, StoredUserExecutionProof stored) {
        var metadata = token.getMetadata();
        var claims = metadata == null ? null : metadata.getClaims();
        var security = claims == null ? null : claims.getSecurityVersion();
        if (metadata == null || metadata.getSchemaVersion() != 1 || metadata.isInvalidated() || claims == null
                || claims.getTokenUse() != OAuthTokenTypeEnum.ACCESS || claims.getIssuer() == null
                || !stored.issuer().equals(claims.getIssuer().toASCIIString())
                || !Set.of(URI.create(stored.resourceUri())).equals(claims.getAudience())
                || !stored.subject().equals(claims.getSubject()) || !Long.valueOf(stored.tenantId()).equals(claims.getTenantId())
                || !"USER".equals(claims.getPrincipalType()) || !"TENANT".equals(claims.getScopeContext())
                || !stored.clientId().equals(claims.getClientId())
                || !Long.toString(stored.clientPk()).equals(claims.getClientRegistrationId())
                || !Long.toString(stored.authorizationId()).equals(claims.getAuthorizationId())
                || !stored.tokenJti().equals(claims.getJti()) || !stored.scopes().equals(claims.getScope())
                || claims.getAuthenticationJti() == null
                || !stored.authenticationJtiDigest().equals(Digests.sha256Hex(claims.getAuthenticationJti()))
                || !stored.acr().equals(claims.getAcr()) || claims.getAuthTime() == null
                || stored.authenticationTime() != claims.getAuthTime().getEpochSecond()
                || !Long.valueOf(stored.authorizationExpiresAt()).equals(claims.getAuthorizationExpiresAt())
                || !Long.toString(stored.refreshGeneration()).equals(claims.getRefreshGeneration())
                || security == null || security.getRealm() != stored.realmGeneration()
                || security.getClient() != stored.clientGeneration()
                || !Long.valueOf(stored.subjectGeneration()).equals(security.getSubject())) {
            throw invalid("EXECUTION_USER_PROOF_MISMATCH");
        }
    }

    private CurrentFacts current(VerifiedAccess proof, String compact) {
        boolean user = "USER".equals(proof.text("principal_type"));
        String authenticationDigest = user
                ? Digests.sha256Hex(proof.text("authn_jti")) : null;
        var observed = new CurrentAccessFacts(proof.realm(), user, proof.claims().getSubject(), proof.clientPk(),
                proof.text("client_id"), proof.authorizationId(), List.copyOf(proof.claims().getAudience()),
                proof.claims().getJWTID(), proof.keyId(), scopes(proof), version(proof, user),
                user ? proof.text("acr") : null, user ? number(proof, "auth_time") : 0,
                user ? number(proof, "authn_expires_at") : 0, user ? number(proof, "authorization_expires_at") : 0,
                user ? refreshGeneration(proof) : 0, user ? 0 : number(proof, "resource_version"));
        return currentByDigest(observed, Digests.sha256Hex(compact), authenticationDigest);
    }

    private CurrentFacts currentByDigest(CurrentAccessFacts access, String tokenDigest, String authenticationDigest) {
        TrustedRealmBO realm = access.realm();
        boolean user = access.user();
        OAuthClientBO client = clients.findById(realm, access.clientPk())
                .filter(value -> value.getStatus() == OAuthClient.Status.ACTIVE && value.getClientId().equals(access.clientId())
                        && (value.getPurpose() == OAuthClientPurposeEnum.USER) == user)
                .orElseThrow(() -> invalid("JWT_CLIENT_NOT_ACTIVE"));
        OAuthAuthorizationBO family = authorizations.findById(realm, access.authorizationId())
                .filter(value -> "ACTIVE".equals(value.getStatus()) && value.getAbsoluteExpiresAt().isAfter(clock.instant())
                        && Objects.equals(value.getClientPk(), client.getId())
                        && Objects.equals(value.getPrincipalName(), access.subject())
                        && Objects.equals(value.getPrincipalType(), user ? "USER" : "SERVICE")
                        && value.getAudiences().equals(access.audiences()))
                .orElseThrow(() -> invalid("JWT_AUTHORIZATION_NOT_ACTIVE"));
        var token = tokens.findByTokenDigest(realm, tokenDigest)
                .filter(value -> value.getTokenType() == OAuthTokenTypeEnum.ACCESS && value.getRevokedAt() == null
                        && Objects.equals(value.getAuthorizationPk(), family.getId()) && Objects.equals(value.getJti(), access.tokenJti()))
                .orElseThrow(() -> invalid("JWT_TOKEN_FACT_MISSING"));
        URI target = URI.create(access.audiences().getFirst());
        OAuthResourceBO resource = resources.findByResourceUri(managementRealms.platformRealm(), target)
                .filter(value -> value.getStatus() == ResourceServerStatus.ACTIVE)
                .orElseThrow(() -> invalid("JWT_RESOURCE_NOT_ACTIVE"));
        if (!user && access.resourceVersion() != resource.getVersion()) { throw invalid("JWT_RESOURCE_VERSION_STALE"); }
        var grant = grants.findGrant(realm, client.getId(), resource.getResourceServerId(),
                        user ? ResourceGrantType.USER_DELEGATION : ResourceGrantType.CLIENT_CREDENTIALS)
                .filter(value -> value.getStatus() == ClientResourceGrant.Status.ACTIVE
                        && value.getResourceVersion() == resource.getVersion())
                .orElseThrow(() -> invalid("JWT_RESOURCE_GRANT_NOT_ACTIVE"));
        Set<String> requestedScopes = access.scopes();
        Set<String> resourceScopes = new TreeSet<>(requestedScopes);
        if (user) { resourceScopes.removeAll(Set.of("openid", "profile", "email")); }
        if (!family.getAuthorizedScopes().containsAll(requestedScopes) || !client.getAllowedScopes().containsAll(requestedScopes)
                || !grant.getAllowedScopes().containsAll(resourceScopes)) {
            throw invalid("JWT_SCOPE_NO_LONGER_ALLOWED");
        }
        OAuthSecurityVersionBO version = access.version();
        generation(realm, OAuthSecurityTargetEnum.REALM, "self", version.getRealm());
        generation(realm, OAuthSecurityTargetEnum.CLIENT, Long.toString(client.getId()), version.getClient());
        if (user) { generation(realm, OAuthSecurityTargetEnum.SUBJECT, access.subject(), version.getSubject()); }
        for (var revoked : List.of(Map.entry(OAuthSecurityTargetEnum.JTI, access.tokenJti()),
                Map.entry(OAuthSecurityTargetEnum.AUTHORIZATION, Long.toString(family.getId())), Map.entry(OAuthSecurityTargetEnum.KID, access.keyId()))) {
            if (revocations.findByTarget(realm, revoked.getKey(), revoked.getValue()).isPresent()) { throw invalid("JWT_REVOKED"); }
        }
        OAuthAuthenticationBO authentication = null;
        if (user) {
            users.findByIdentitySub(access.subject()).filter(value -> value.status() == IdentityUserStatus.ACTIVE)
                    .orElseThrow(() -> invalid("JWT_ACCOUNT_NOT_ACTIVE"));
            var membership = memberships.resolve(access.subject(), tenant(realm));
            if (membership == null || membership.status() != TenantMembershipPort.MembershipStatus.ACTIVE) { throw invalid("JWT_MEMBERSHIP_NOT_ACTIVE"); }
            String jtiDigest = authenticationDigest;
            if (jtiDigest == null || !jtiDigest.matches("[0-9a-f]{64}")) { throw invalid("JWT_AUTHENTICATION_BINDING_INVALID"); }
            if (!Objects.equals(jtiDigest, family.getAuthenticationJtiDigest())) { throw invalid("JWT_AUTHENTICATION_BINDING_INVALID"); }
            authentication = authentications.findByJtiDigest(realm, jtiDigest)
                    .filter(value -> !"REVOKED".equals(value.getStatus()) && value.getRevokedAt() == null
                            && value.getSubject().equals(access.subject())
                            && value.getAcr().equals(access.acr())
                            && value.getAuthenticatedAt().getEpochSecond() == access.authenticationTime()
                            && value.getSubjectGeneration().equals(version.getSubject()) && value.getRealmGeneration() == version.getRealm())
                    .orElseThrow(() -> invalid("JWT_AUTHENTICATION_REVOKED"));
            if (access.authorizationExpiresAt() != family.getAbsoluteExpiresAt().getEpochSecond()
                    || access.authenticationExpiresAt() != authentication.getExpiresAt().getEpochSecond()
                    || access.refreshGeneration() > family.getRefreshGeneration()) { throw invalid("JWT_FAMILY_FACT_MISMATCH"); }
        }
        return new CurrentFacts(client, family, authentication, resource, version, token);
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

    public record Caller(ServiceIdentityPrincipal principal, TrustedRealmBO realm, long clientPk, URI sourceResource,
                         Long realmGeneration, Long clientGeneration, Long authorizationId, String tokenDigest,
                         Instant tokenRetainUntil, String signingKeyId) {
        public Caller(ServiceIdentityPrincipal principal, TrustedRealmBO realm, long clientPk, URI sourceResource) {
            this(principal, realm, clientPk, sourceResource, null, null, null, null, null, null);
        }
        @Override public String toString() { return "OAuthAuthorityService.Caller[redacted]"; }
    }
    private record CurrentAccessFacts(TrustedRealmBO realm, boolean user, String subject, long clientPk, String clientId,
            long authorizationId, List<String> audiences, String tokenJti, String keyId, Set<String> scopes,
            OAuthSecurityVersionBO version, String acr, long authenticationTime, long authenticationExpiresAt,
            long authorizationExpiresAt, long refreshGeneration, long resourceVersion) {
        @Override public String toString() { return "CurrentAccessFacts[redacted]"; }
    }
    private record CurrentServiceEvidence(ExecutionGrantEnvelope.ServiceBinding binding, long realmGeneration,
            long clientGeneration, long authorizationId, String tokenDigest, String tokenJti, Instant tokenRetainUntil,
            String signingKeyId) {
        @Override public String toString() { return "CurrentServiceEvidence[redacted]"; }
    }
    private record CurrentFacts(OAuthClientBO client, OAuthAuthorizationBO authorization, OAuthAuthenticationBO authentication,
            OAuthResourceBO resource, OAuthSecurityVersionBO version, OAuthTokenBO token) { }
    record ExecutionUserCurrent(String issuer, long tenantId, String subject, String resource, Set<String> scopes, Instant validUntil) {
        @Override public String toString() { return "ExecutionUserCurrent[redacted]"; }
    }
}
