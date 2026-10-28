package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthRevocationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.TokenRevocationService;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthPayloadCipherComponent;
import top.egon.cola.platform.tianquan.shoubing.contract.state.IdentityAuthorityScopes;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Owner-local issue and verification of one bounded execution intent. */
@Service("oauthExecutionGrantService")
@ConditionalOnProperty(prefix = "egon.tianquan-shoubing.execution-grants", name = "enabled", havingValue = "true")
public class OAuthExecutionGrantService {
    private final OAuthExecutionGrantProperties properties;
    private final OAuthAuthorityService authority;
    private final OAuthExecutionPrimaryGuard primary;
    private final OAuthRevocationRepository revocations;
    private final OpaqueExecutionGrantCodec codec;
    private final Clock clock;
    private final TokenRevocationService revocationWriter;

    public OAuthExecutionGrantService(OAuthExecutionGrantProperties properties, OAuthAuthorityService authority,
            @Qualifier("oauthExecutionPrimaryGuard") OAuthExecutionPrimaryGuard primary,
            @Qualifier("oAuthRevocationRepository") OAuthRevocationRepository revocations,
            @Qualifier("oauthPayloadCipherComponent") OAuthPayloadCipherComponent cipher,
            @Qualifier("jacksonObjectMapper") ObjectMapper mapper, @Qualifier("idpClock") Clock clock) {
        this(properties, authority, primary, revocations, cipher, mapper, clock, null);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public OAuthExecutionGrantService(OAuthExecutionGrantProperties properties, OAuthAuthorityService authority,
            @Qualifier("oauthExecutionPrimaryGuard") OAuthExecutionPrimaryGuard primary,
            @Qualifier("oAuthRevocationRepository") OAuthRevocationRepository revocations,
            @Qualifier("oauthPayloadCipherComponent") OAuthPayloadCipherComponent cipher,
            @Qualifier("jacksonObjectMapper") ObjectMapper mapper, @Qualifier("idpClock") Clock clock,
            @Qualifier("tokenRevocationService") TokenRevocationService revocationWriter) {
        this.properties = Objects.requireNonNull(properties, "properties");
        this.authority = Objects.requireNonNull(authority, "authority");
        this.primary = Objects.requireNonNull(primary, "primary");
        this.revocations = Objects.requireNonNull(revocations, "revocations");
        this.codec = new OpaqueExecutionGrantCodec(cipher, mapper);
        this.clock = Objects.requireNonNull(clock, "clock");
        this.revocationWriter = revocationWriter;
        if (!properties.enabled() || properties.bindings().isEmpty()) throw new IllegalArgumentException("EXECUTION_GRANT_DISABLED");
    }

    /** The caller and USER proof have already entered through the authenticated authority boundary. */
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    Issued issue(OAuthAuthorityService.Caller caller, String userToken, IssueRequest request) {
        primary.requirePrimaryTransaction();
        Objects.requireNonNull(caller, "caller");
        Objects.requireNonNull(request, "request");
        Instant now = clock.instant();
        if (!request.deadlineAt().isAfter(now)) throw rejected();
        StoredUserExecutionProof user = authority.captureExecutionUser(caller, caller.sourceResource(), userToken);
        var binding = properties.bindings().stream().filter(candidate -> candidate.issuer().equals(user.issuer())
                && candidate.tenantId() == user.tenantId() && candidate.purpose().equals(request.purpose())
                && candidate.source().binding().matches(caller, user, IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE, now))
                .findFirst().orElseThrow(OAuthExecutionGrantService::rejected);
        requireScopes(binding, user.scopes(), request.sessionRequired());
        authority.requireExecutionService(caller, binding.source().binding(), user, IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE);
        var current = authority.recheckExecutionUser(caller.realm(), user);
        requireSameUser(user, current);
        if (Instant.ofEpochSecond(user.authenticationTime()).isAfter(now)) throw unavailable();
        Instant expiresAt = earliest(request.deadlineAt(), now.plus(binding.maxLifetime()), current.validUntil(),
                caller.tokenRetainUntil());
        if (!expiresAt.isAfter(now)) throw rejected();
        String id = OpaqueExecutionGrantCodec.grantId(user, binding.source().binding(), request.purpose(), request.intentId());
        if (revocations.findByTarget(caller.realm(), OAuthSecurityTargetEnum.JTI, id).isPresent()) throw rejected();
        var envelope = new ExecutionGrantEnvelope(1, id, binding.source().binding(), binding.verifier().binding(),
                caller.realmGeneration(), caller.clientGeneration(), caller.authorizationId(), caller.tokenDigest(),
                caller.principal().tokenId(), caller.tokenRetainUntil(), caller.signingKeyId(), request.purpose(),
                request.intentId(), request.bindingSha256(), binding.fingerprint(), request.sessionRequired(), now, expiresAt,
                request.deadlineAt(), user);
        var sealed = codec.seal(caller.realm(), envelope);
        Instant finished = clock.instant();
        requireTime(envelope, finished);
        if (!envelope.source().matches(caller, user, IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE, finished)) throw rejected();
        return new Issued(sealed, expiresAt);
    }

    /** Only the configured verifier can resolve identity and intent; RBAC remains Jianshen's responsibility. */
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    Resolution resolve(OAuthAuthorityService.Caller caller, OpaqueExecutionGrantCodec.Ticket ticket) {
        primary.requirePrimaryTransaction();
        Objects.requireNonNull(caller, "caller");
        ExecutionGrantEnvelope envelope;
        try { envelope = codec.open(caller.realm(), ticket); }
        catch (IllegalArgumentException invalid) { throw rejected(); }
        Instant now = clock.instant();
        requireTime(envelope, now);
        var binding = properties.bindings().stream().filter(candidate -> candidate.issuer().equals(envelope.user().issuer())
                && candidate.tenantId() == envelope.user().tenantId() && candidate.purpose().equals(envelope.purpose())
                && candidate.source().binding().equals(envelope.source()) && candidate.verifier().binding().equals(envelope.verifier())
                && candidate.fingerprint().equals(envelope.policySha256()))
                .findFirst().orElseThrow(OAuthExecutionGrantService::rejected);
        if (!envelope.verifier().matches(caller, envelope.user(), IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE, now)) {
            throw rejected();
        }
        authority.requireExecutionService(caller, envelope.verifier(), envelope.user(), IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE);
        if (revocations.findByTarget(caller.realm(), OAuthSecurityTargetEnum.JTI, envelope.grantId()).isPresent()) throw rejected();
        authority.requireRecordedExecutionSource(caller.realm(), envelope, IdentityAuthorityScopes.EXECUTION_GRANT_ISSUE);
        var user = authority.recheckExecutionUser(caller.realm(), envelope.user());
        requireSameUser(envelope.user(), user);
        requireScopes(binding, user.scopes(), envelope.sessionRequired());
        Instant finished = clock.instant();
        requireTime(envelope, finished);
        if (!envelope.verifier().matches(caller, envelope.user(), IdentityAuthorityScopes.EXECUTION_GRANT_RESOLVE, finished)) {
            throw rejected();
        }
        if (envelope.expiresAt().isAfter(user.validUntil())) throw rejected();
        return new Resolution(envelope.grantId(), user.issuer(), user.tenantId(), user.subject(), user.resource(),
                envelope.purpose(), envelope.intentId(), envelope.bindingSha256(), envelope.sessionRequired(),
                envelope.expiresAt(), envelope.intentDeadlineAt(), user.scopes());
    }

    /** A fresh USER proof can revoke all copies of the same resource/run intent. */
    @Transactional(isolation = Isolation.REPEATABLE_READ)
    void revoke(OAuthAuthorityService.Caller caller, String userToken, OpaqueExecutionGrantCodec.Ticket ticket) {
        primary.requirePrimaryTransaction();
        if (revocationWriter == null) throw unavailable();
        Objects.requireNonNull(caller, "caller");
        ExecutionGrantEnvelope envelope;
        try { envelope = codec.open(caller.realm(), ticket); }
        catch (IllegalArgumentException invalid) { throw rejected(); }
        StoredUserExecutionProof current = authority.captureExecutionUser(caller, caller.sourceResource(), userToken,
                IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE);
        if (!envelope.user().issuer().equals(current.issuer()) || envelope.user().tenantId() != current.tenantId()
                || !envelope.user().subject().equals(current.subject())
                || !envelope.user().resourceUri().equals(current.resourceUri())) throw rejected();
        Instant now = clock.instant();
        var binding = properties.bindings().stream().filter(candidate -> candidate.issuer().equals(current.issuer())
                && candidate.tenantId() == current.tenantId() && candidate.purpose().equals(envelope.purpose())
                && candidate.source().resourceUri().equals(envelope.source().resourceUri())
                && candidate.source().binding().matches(caller, current, IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE, now))
                .findFirst().orElseThrow(OAuthExecutionGrantService::rejected);
        authority.requireExecutionService(caller, binding.source().binding(), current, IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE);
        if (!binding.source().binding().matches(caller, current, IdentityAuthorityScopes.EXECUTION_GRANT_REVOKE, clock.instant())) {
            throw rejected();
        }
        try {
            revocationWriter.revokeExecutionGrant(caller.realm(), envelope.grantId(), envelope.intentDeadlineAt());
        } catch (UnsupportedOperationException unavailable) {
            throw unavailable();
        }
    }

    private static void requireScopes(OAuthExecutionGrantProperties.Binding binding, Set<String> scopes, boolean session) {
        if (scopes == null || !scopes.containsAll(binding.requiredUserScopes())
                || session && (binding.sessionUserScopes().isEmpty() || !scopes.containsAll(binding.sessionUserScopes()))) {
            throw rejected();
        }
    }

    private static void requireSameUser(StoredUserExecutionProof stored, OAuthAuthorityService.ExecutionUserCurrent current) {
        if (current == null || !stored.issuer().equals(current.issuer()) || stored.tenantId() != current.tenantId()
                || !stored.subject().equals(current.subject()) || !stored.resourceUri().equals(current.resource())
                || !stored.scopes().equals(current.scopes()) || current.validUntil() == null) throw unavailable();
    }

    private static void requireTime(ExecutionGrantEnvelope value, Instant now) {
        if (now.isBefore(value.notBefore()) || !value.expiresAt().isAfter(now)) throw rejected();
    }

    private static Instant earliest(Instant... values) {
        Instant result = Objects.requireNonNull(values[0], "deadline");
        for (Instant value : values) if (Objects.requireNonNull(value, "expiry").isBefore(result)) result = value;
        return result;
    }

    private static OAuth2AuthenticationException rejected() {
        return new OAuth2AuthenticationException(new OAuth2Error("invalid_grant", "Request rejected", null));
    }

    private static OAuth2AuthenticationException unavailable() {
        return new OAuth2AuthenticationException(new OAuth2Error("temporarily_unavailable", "Request rejected", null));
    }

    record IssueRequest(String purpose, String intentId, String bindingSha256, boolean sessionRequired, Instant deadlineAt) {
        IssueRequest {
            if (purpose == null || !purpose.matches("[A-Z][A-Z0-9_]{0,95}") || intentId == null || intentId.length() != 36
                    || bindingSha256 == null || !bindingSha256.matches("[0-9a-f]{64}") || deadlineAt == null
                    || deadlineAt.isAfter(ExecutionGrantEnvelope.MAX_INTENT_DEADLINE)) {
                throw new IllegalArgumentException("EXECUTION_GRANT_REQUEST_INVALID");
            }
            try {
                if (!UUID.fromString(intentId).toString().equals(intentId)) throw new IllegalArgumentException();
            } catch (IllegalArgumentException malformed) {
                throw new IllegalArgumentException("EXECUTION_GRANT_REQUEST_INVALID");
            }
        }
        @Override public String toString() { return "ExecutionGrantIssueRequest[redacted]"; }
    }

    record Issued(OpaqueExecutionGrantCodec.Ticket ticket, Instant expiresAt) {
        @Override public String toString() { return "ExecutionGrantIssued[redacted]"; }
    }

    record Resolution(String grantId, String issuer, long tenantId, String subject, String resource, String purpose,
                      String intentId, String bindingSha256, boolean sessionRequired, Instant expiresAt,
                      Instant intentDeadlineAt, Set<String> scopes) {
        Resolution { scopes = Set.copyOf(scopes); }
        @Override public String toString() { return "ExecutionGrantResolution[redacted]"; }
    }
}
