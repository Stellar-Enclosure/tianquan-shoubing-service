package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.validation.annotation.Validated;
import top.egon.cola.component.common.crypto.digest.Digests;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthPendingConsentBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthSecuritySnapshotBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter.SasAuthorizationConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.converter.SasRegisteredClientConverter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthorizationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.OAuthTokenIssueService;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthTokenBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthTokenMetadataBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthTokenTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthTokenRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthSecurityProjectionComponent;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.SignedTokenClaimsBO;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;

@Service("tenantAuthorizationService")
@Slf4j
@RequiredArgsConstructor
@Validated
public class TenantAuthorizationServiceImpl implements OAuth2AuthorizationService {

    private static final int TOKEN_QUERY_BATCH_SIZE = 500;

    @Qualifier("tenantIssuerService")
    private final TenantIssuerService tenantIssuerService;
    @Qualifier("oAuthRealmRepository")
    private final OAuthRealmRepository realmRepository;
    @Qualifier("oAuthAuthorizationRepository")
    private final OAuthAuthorizationRepository authorizationRepository;
    @Qualifier("oAuthTokenRepository")
    private final OAuthTokenRepository tokenRepository;
    @Qualifier("oAuthClientRepository")
    private final OAuthClientRepository clientRepository;
    @Qualifier("sasAuthorizationConverterImpl")
    private final SasAuthorizationConverter authorizationConverter;
    @Qualifier("sasRegisteredClientConverterImpl")
    private final SasRegisteredClientConverter clientConverter;
    @Qualifier("jacksonObjectMapper")
    private final ObjectMapper objectMapper;
    @Qualifier("egonColaMybatisPlusClock")
    private final Clock clock;
    @Qualifier("oauthSecurityProjectionComponent")
    private final OAuthSecurityProjectionComponent securityProjection;
    @Qualifier("oauthTokenIssueService")
    private final OAuthTokenIssueService tokenIssueService;
    @Qualifier("oauthBrowserInteractionComponent")
    private final OAuthBrowserInteractionComponent interactions;

    @Override
    @Transactional
    public void save(OAuth2Authorization source) {
        OAuth2Authorization authorization = Objects.requireNonNull(source, "authorization");
        TrustedRealmBO trustedRealm = tenantIssuerService.resolveCurrentIssuer();
        realmRepository.findByRealmKeyForUpdate(trustedRealm)
                .orElseThrow(() -> new IllegalStateException("OAUTH_AUTHORIZATION_REALM_NOT_FOUND"));
        OAuthClientBO client = loadClient(trustedRealm, authorization.getRegisteredClientId());
        client = clientRepository.findByClientIdForUpdate(trustedRealm, client.getClientId())
                .filter(value -> value.getStatus() != null && "ACTIVE".equals(value.getStatus().name()))
                .orElseThrow(() -> new IllegalStateException("OAUTH_AUTHORIZATION_CLIENT_NOT_FOUND"));
        String principalType = AuthorizationGrantType.CLIENT_CREDENTIALS.equals(
                authorization.getAuthorizationGrantType()) ? "SERVICE" : "USER";
        OAuthSecuritySnapshotBO currentSnapshot = securityProjection.snapshotForAuthorization(
                trustedRealm, client.getId(), principalType,
                "USER".equals(principalType) ? authorization.getPrincipalName() : null);
        Long authorizationId = parseSasStorageId(authorization.getId());
        OAuthAuthorizationBO current = authorizationId == null
                ? null
                : authorizationRepository.findByIdForUpdate(trustedRealm, authorizationId).orElse(null);
        if (authorizationId != null && current == null) {
            throw new IllegalStateException("OAUTH_AUTHORIZATION_NOT_FOUND");
        }

        RegisteredClient registeredClient = clientConverter.toTarget(client);
        if (!registeredClient.getAuthorizationGrantTypes().contains(authorization.getAuthorizationGrantType())
                || !client.getAllowedScopes().containsAll(authorization.getAuthorizedScopes())) {
            throw new IllegalArgumentException("OAUTH_AUTHORIZATION_CLIENT_POLICY_MISMATCH");
        }

        if (current == null) {
            Instant startedAt = clock.instant();
            Duration familyLifetime = "USER".equals(principalType)
                    && registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)
                    ? registeredClient.getTokenSettings().getRefreshTokenTimeToLive()
                    : registeredClient.getTokenSettings().getAccessTokenTimeToLive();
            if ("USER".equals(principalType)
                    && !registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
                familyLifetime = familyLifetime.plusSeconds(300)
                        .plus(registeredClient.getTokenSettings().getAuthorizationCodeTimeToLive());
            }
            OAuth2Authorization.Builder initialized = OAuth2Authorization.from(authorization)
                    .attribute(SasAuthorizationConverter.ABSOLUTE_EXPIRES_AT_ATTRIBUTE, startedAt.plus(familyLifetime));
            if (authorization.getAttribute("state") != null) {
                initialized.attribute(SasAuthorizationConverter.PENDING_ISSUED_AT_ATTRIBUTE, startedAt)
                        .attribute(SasAuthorizationConverter.PENDING_EXPIRES_AT_ATTRIBUTE, startedAt.plusSeconds(300));
            }
            authorization = initialized.build();
        }
        OAuthAuthorizationBO value = authorizationConverter.toSource(authorization, current, objectMapper);
        if ("USER".equals(principalType)) {
            value.setStatus(value.getAttributes().getPendingConsent() == null ? "ACTIVE" : "PENDING_CONSENT");
        }
        if (current != null && current.getAttributes().getPendingConsent() != null
                && authorization.getAttribute("state") == null && authorization.getToken(OAuth2AuthorizationCode.class) != null) {
            if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes request)
                    || !"POST".equals(request.getRequest().getMethod()) || request.getRequest().getParameterValues("scope") == null) {
                throw new IllegalArgumentException("OAUTH_CONSENT_SELECTION_REQUIRED");
            }
            Set<String> selected = new HashSet<>(List.of(request.getRequest().getParameterValues("scope")));
            if (!current.getAttributes().getPendingConsent().getRequestedScopes().containsAll(selected)
                    || !authorization.getAuthorizedScopes().containsAll(selected)) {
                throw new IllegalArgumentException("OAUTH_CONSENT_SELECTION_INVALID");
            }
            if (authorization.getAuthorizedScopes().contains("openid")) { selected.add("openid"); }
            value.setAuthorizedScopes(selected.stream().sorted().toList());
        }
        if (current == null) {
            value.setRequestedScopes(authorization.getAttribute(OAuth2AuthorizationRequest.class.getName()) instanceof OAuth2AuthorizationRequest request
                    ? request.getScopes().stream().sorted().toList() : value.getAuthorizedScopes());
            if (value.getAudiences() == null || value.getAudiences().size() != 1) {
                throw new IllegalArgumentException("OAUTH_AUTHORIZATION_RESOURCE_REQUIRED");
            }
            value.setResourceUri(value.getAudiences().getFirst());
            value.setRetainUntil(value.getAbsoluteExpiresAt().plusSeconds(86_400));
            if ("USER".equals(principalType)) {
                if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes browser)
                        || value.getAttributes().getAuthenticationJti() == null) {
                    throw new IllegalArgumentException("OAUTH_AUTHENTICATION_PROOF_REQUIRED");
                }
                var interaction = interactions.require(browser.getRequest(), true);
                value.setAuthenticationJtiDigest(Digests.sha256Hex(value.getAttributes().getAuthenticationJti()));
                value.setInteractionId(interaction.getInteractionId());
                value.setClientBrowserBindingDigest(interaction.getClientBrowserBindingDigest());
                if (!Objects.equals(client.getId(), interaction.getClientPk()) || !value.getResourceUri().equals(interaction.getResourceUri())) {
                    throw new IllegalArgumentException("OAUTH_AUTHORIZATION_INTERACTION_MISMATCH");
                }
            }
        }
        List<OAuthTokenBO> tokenSnapshot = value.getTokens() == null
                ? List.of() : new ArrayList<>(value.getTokens());
        value.setClientPk(client.getId());
        value.setTokens(null);
        long expectedVersion = current == null ? 0L : current.getVersion();
        if (current != null) {
            securityProjection.requireCurrentSnapshot(trustedRealm, client.getId(), principalType,
                    "USER".equals(principalType) ? current.getPrincipalName() : null,
                    current.getAttributes().getSecuritySnapshot());
            value.setId(current.getId());
            value.setVersion(Math.addExact(current.getVersion(), 1L));
            value.getAttributes().setSecuritySnapshot(current.getAttributes().getSecuritySnapshot());
            value.setAbsoluteExpiresAt(current.getAbsoluteExpiresAt());
        } else {
            Long signedAuthorizationId = value.getId();
            value.setId(signedAuthorizationId == null ? SnowflakeIdGenerator.nextLongId() : signedAuthorizationId);
            value.setVersion(0L);
            if (value.getId() == null || value.getId() <= 0L) {
                throw new IllegalStateException("OAUTH_AUTHORIZATION_ID_INVALID");
            }
            if (value.getAttributes() == null) {
                throw new IllegalArgumentException("OAUTH_AUTHORIZATION_ATTRIBUTES_REQUIRED");
            }
            if (value.getAttributes().getSecuritySnapshot() == null) {
                value.getAttributes().setSecuritySnapshot(currentSnapshot);
            } else if (!value.getAttributes().getSecuritySnapshot().equals(currentSnapshot)) {
                throw new IllegalStateException("OAUTH_SECURITY_SNAPSHOT_STALE");
            }
        }
        if (!value.getAbsoluteExpiresAt().isAfter(clock.instant())) {
            throw new IllegalArgumentException("OAUTH_AUTHORIZATION_EXPIRED");
        }
        for (OAuthTokenBO token : tokenSnapshot) {
            if (token.getExpiresAt() == null || token.getExpiresAt().isAfter(value.getAbsoluteExpiresAt())) {
                throw new IllegalArgumentException("OAUTH_TOKEN_EXCEEDS_FAMILY_LIFETIME");
            }
        }
        var nextRefresh = tokenSnapshot.stream().filter(token -> token.getTokenType() == OAuthTokenTypeEnum.REFRESH).findFirst().orElse(null);
        if (current != null && nextRefresh != null && tokenRepository.findByTokenDigest(trustedRealm,
                Digests.sha256Hex(nextRefresh.getTokenValue())).isEmpty()
                && !tokenRepository.findByAuthorization(trustedRealm, current.getId(), OAuthTokenTypeEnum.REFRESH, 0L, 1).isEmpty()) {
            value.setRefreshGeneration(Math.addExact(current.getRefreshGeneration(), 1L));
        }
        for (OAuthTokenBO token : tokenSnapshot) {
            token.setRetainUntil(value.getRetainUntil());
            token.setRefreshGeneration(token.getTokenType() == OAuthTokenTypeEnum.REFRESH ? value.getRefreshGeneration() : null);
        }
        requireSignedAuthorizationMatchesSnapshot(tokenSnapshot, value.getId(), currentSnapshot);

        if ("USER".equals(principalType) && RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes nativeRequest
                && nativeRequest.getRequest().getRequestURI().endsWith("/oauth2/authorize")) {
            if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes browser)) {
                throw new IllegalArgumentException("OAUTH_AUTHORIZATION_BROWSER_REQUIRED");
            }
            interactions.advanceAuthorization(browser.getRequest(), value.getPrincipalName(), value.getAuthenticationJtiDigest(),
                    value.getAuthorizedScopes(), value.getAttributes().getPendingConsent() == null);
        }
        OAuthAuthorizationBO saved = authorizationRepository.save(trustedRealm, value, expectedVersion);
        invalidateTokensMissingFromSnapshot(trustedRealm, saved.getId(), tokenSnapshot);
        saveTokenSnapshot(trustedRealm, saved.getId(), tokenSnapshot);
        if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorization.getAuthorizationGrantType())
                && (current == null || current.getAttributes().getPendingConsent() != null)
                && tokenSnapshot.stream().anyMatch(token -> token.getTokenType() == OAuthTokenTypeEnum.CODE
                        && !token.getMetadata().isInvalidated() && !token.getMetadata().isCodeConsumed())) {
            tokenIssueService.recordAuthorizationCodeCreated(trustedRealm, saved);
        }
    }

    private static void requireSignedAuthorizationMatchesSnapshot(
            List<OAuthTokenBO> tokens,
            Long authorizationId,
            OAuthSecuritySnapshotBO snapshot) {
        if (tokens == null || tokens.isEmpty()) {
            return;
        }
        for (OAuthTokenBO token : tokens) {
            SignedTokenClaimsBO claims = token.getMetadata() == null ? null : token.getMetadata().getClaims();
            if (claims == null || claims.getAuthorizationId() == null) {
                continue;
            }
            if (!Long.toString(authorizationId).equals(claims.getAuthorizationId())
                    || claims.getSecurityVersion() == null
                    || !Objects.equals(claims.getSecurityVersion().getRealm(), snapshot.getRealmGeneration())
                    || !Objects.equals(claims.getSecurityVersion().getClient(), snapshot.getClientGeneration())
                    || !Objects.equals(claims.getSecurityVersion().getSubject(), snapshot.getSubjectGeneration())) {
                throw new IllegalStateException("OAUTH_SIGNED_AUTHORIZATION_STATE_MISMATCH");
            }
        }
    }

    @Override
    @Transactional
    public void remove(OAuth2Authorization source) {
        OAuth2Authorization authorization = Objects.requireNonNull(source, "authorization");
        TrustedRealmBO trustedRealm = tenantIssuerService.resolveCurrentIssuer();
        realmRepository.findByRealmKeyForUpdate(trustedRealm)
                .orElseThrow(() -> new IllegalStateException("OAUTH_AUTHORIZATION_REALM_NOT_FOUND"));
        Long id = parseOptionalPositiveId(authorization.getId());
        if (id == null) {
            return;
        }
        OAuthAuthorizationBO current = authorizationRepository.findByIdForUpdate(trustedRealm, id).orElse(null);
        if (current != null) {
            invalidateTokensMissingFromSnapshot(trustedRealm, id, List.of());
            long version = current.getVersion();
            boolean pending = current.getAttributes().getPendingConsent() != null;
            current.setVersion(version + 1).setStatus(pending ? "CANCELLED" : "REVOKED")
                    .setRevokedAt(pending ? null : clock.instant());
            authorizationRepository.save(trustedRealm, current, version);
            if (pending && RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes browser) {
                interactions.cancelAuthorization(browser.getRequest());
            }
        }
    }

    @Override
    @Transactional(readOnly = true)
    public OAuth2Authorization findById(String id) {
        if (id == null || !id.matches("[1-9][0-9]{0,18}")) {
            return null;
        }
        Long authorizationId = parseOptionalPositiveId(id);
        if (authorizationId == null) {
            return null;
        }
        TrustedRealmBO trustedRealm = tenantIssuerService.resolveCurrentIssuer();
        OAuthAuthorizationBO authorization = authorizationRepository.findById(trustedRealm, authorizationId)
                .filter(value -> "ACTIVE".equals(value.getStatus())
                        && value.getAbsoluteExpiresAt() != null && value.getAbsoluteExpiresAt().isAfter(clock.instant()))
                .orElse(null);
        if (authorization == null) {
            return null;
        }
        RegisteredClient client = clientConverter.toTarget(loadClient(trustedRealm,
                Long.toString(authorization.getClientPk())));
        authorization.setTokens(loadCurrentTokens(trustedRealm, authorization.getId()));
        return authorizationConverter.toTarget(authorization, client, objectMapper, trustedRealm.getIssuer());
    }

    @Override
    @Transactional(readOnly = true)
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (token == null || token.isBlank()) {
            return null;
        }
        TrustedRealmBO trustedRealm = tenantIssuerService.resolveCurrentIssuer();
        if (tokenType != null && "state".equals(tokenType.getValue())) {
            if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes browser)) { return null; }
            var interaction = interactions.require(browser.getRequest(), false);
            var pending = authorizationRepository.findByInteractionId(trustedRealm, interaction.getInteractionId()).orElse(null);
            if (pending == null || !matchesPendingInteraction(pending, token)) { return null; }
            securityProjection.requireCurrentSnapshot(trustedRealm, pending.getClientPk(), "USER", pending.getPrincipalName(),
                    pending.getAttributes().getSecuritySnapshot());
            pending.setTokens(loadCurrentTokens(trustedRealm, pending.getId()));
            return authorizationConverter.toTarget(pending, clientConverter.toTarget(loadClient(trustedRealm,
                    Long.toString(pending.getClientPk()))), objectMapper, trustedRealm.getIssuer());
        }
        String digest = Digests.sha256Hex(token);
        OAuthTokenBO tokenRecord = tokenRepository.findByTokenDigest(trustedRealm, digest).orElse(null);
        if (!isCurrentToken(tokenRecord, token)) {
            return null;
        }
        OAuthTokenTypeEnum requestedType = toTokenType(tokenType);
        if (tokenType != null && (requestedType == null || tokenRecord.getTokenType() != requestedType)) {
            return null;
        }
        OAuthAuthorizationBO authorization = authorizationRepository.findById(trustedRealm,
                        tokenRecord.getAuthorizationPk())
                .filter(value -> "ACTIVE".equals(value.getStatus()))
                .orElse(null);
        if (authorization == null) {
            return null;
        }
        if (authorization.getAbsoluteExpiresAt() == null
                || !authorization.getAbsoluteExpiresAt().isAfter(clock.instant())) {
            return null;
        }
        securityProjection.requireCurrentSnapshot(trustedRealm, authorization.getClientPk(),
                authorization.getPrincipalType(), "USER".equals(authorization.getPrincipalType())
                        ? authorization.getPrincipalName() : null, authorization.getAttributes().getSecuritySnapshot());
        List<OAuthTokenBO> tokens = loadCurrentTokens(trustedRealm, authorization.getId());
        OAuthTokenTypeEnum matchedType = tokenRecord.getTokenType();
        tokens.removeIf(value -> value.getTokenType() == matchedType);
        tokens.add(tokenRecord);
        if (tokens.size() > 5) {
            throw new IllegalStateException("OAUTH_AUTHORIZATION_TOKEN_COUNT_INVALID");
        }
        authorization.setTokens(tokens);
        RegisteredClient client = clientConverter.toTarget(loadClient(trustedRealm,
                Long.toString(authorization.getClientPk())));
        return authorizationConverter.toTarget(authorization, client, objectMapper, trustedRealm.getIssuer());
    }

    private OAuthClientBO loadClient(TrustedRealmBO trustedRealm, String clientId) {
        Long clientPk = parseOptionalPositiveId(clientId);
        if (clientPk == null) {
            throw new IllegalArgumentException("OAUTH_AUTHORIZATION_CLIENT_ID_INVALID");
        }
        return clientRepository.findById(trustedRealm, clientPk)
                .filter(value -> value.getStatus() != null && "ACTIVE".equals(value.getStatus().name()))
                .orElseThrow(() -> new IllegalStateException("OAUTH_AUTHORIZATION_CLIENT_NOT_FOUND"));
    }

    private List<OAuthTokenBO> loadCurrentTokens(TrustedRealmBO trustedRealm, long authorizationId) {
        Map<OAuthTokenTypeEnum, OAuthTokenBO> latest = new EnumMap<>(OAuthTokenTypeEnum.class);
        for (OAuthTokenTypeEnum type : OAuthTokenTypeEnum.values()) {
            long afterId = 0L;
            while (true) {
                List<OAuthTokenBO> batch = tokenRepository.findByAuthorization(
                        trustedRealm, authorizationId, type, afterId, TOKEN_QUERY_BATCH_SIZE);
                if (batch.isEmpty()) {
                    break;
                }
                for (OAuthTokenBO token : batch) {
                    OAuthTokenBO prior = latest.get(type);
                    if (prior == null || tokenComparator().compare(token, prior) > 0) {
                        latest.put(type, token);
                    }
                    if (token.getId() != null && token.getId() > afterId) {
                        afterId = token.getId();
                    }
                }
                if (batch.size() < TOKEN_QUERY_BATCH_SIZE) {
                    break;
                }
            }
        }
        List<OAuthTokenBO> tokens = new ArrayList<>(latest.values());
        tokens.sort(Comparator.comparing(OAuthTokenBO::getTokenType));
        return tokens;
    }

    private void saveTokenSnapshot(
            TrustedRealmBO trustedRealm,
            long authorizationId,
            List<OAuthTokenBO> tokens) {
        if (tokens == null || tokens.size() > 5) {
            throw new IllegalArgumentException("OAUTH_AUTHORIZATION_TOKEN_COUNT_INVALID");
        }
        Set<OAuthTokenTypeEnum> types = new HashSet<>();
        Set<String> digests = new HashSet<>();
        for (OAuthTokenBO token : tokens) {
            if (token.getTokenType() == null || !types.add(token.getTokenType())
                    || token.getTokenValue() == null || token.getTokenValue().isBlank()) {
                throw new IllegalArgumentException("OAUTH_AUTHORIZATION_TOKEN_SNAPSHOT_INVALID");
            }
            String digest = Digests.sha256Hex(token.getTokenValue());
            if (!digests.add(digest)) {
                throw new IllegalArgumentException("OAUTH_AUTHORIZATION_TOKEN_DUPLICATE");
            }
            token.setTokenDigest(digest);
            token.setAuthorizationPk(authorizationId);
            OAuthTokenBO current = tokenRepository.findByTokenDigestForUpdate(trustedRealm, digest).orElse(null);
            long expectedVersion = 0L;
            if (current != null) {
                if (!Objects.equals(current.getAuthorizationPk(), authorizationId)
                        || current.getTokenType() != token.getTokenType()) {
                    throw new IllegalStateException("OAUTH_AUTHORIZATION_TOKEN_IDENTITY_MISMATCH");
                }
                expectedVersion = current.getVersion();
                token.setId(current.getId());
                token.setVersion(Math.addExact(current.getVersion(), 1L));
            } else {
                token.setId(null);
                token.setVersion(0L);
            }
            if (token.getMetadata().isCodeConsumed()) {
                token.setConsumedAt(clock.instant());
            }
            if (token.getMetadata().isInvalidated() && token.getTokenType() != OAuthTokenTypeEnum.CODE) {
                token.setRevokedAt(clock.instant());
            }
            tokenRepository.save(trustedRealm, token, expectedVersion);
        }
    }

    private void invalidateTokensMissingFromSnapshot(
            TrustedRealmBO trustedRealm,
            long authorizationId,
            List<OAuthTokenBO> tokens) {
        Set<String> incomingDigests = tokens.stream()
                .map(OAuthTokenBO::getTokenValue)
                .filter(Objects::nonNull)
                .map(Digests::sha256Hex)
                .collect(java.util.stream.Collectors.toSet());
        for (OAuthTokenTypeEnum type : OAuthTokenTypeEnum.values()) {
            long afterId = 0L;
            while (true) {
                List<OAuthTokenBO> batch = tokenRepository.findByAuthorization(
                        trustedRealm, authorizationId, type, afterId, TOKEN_QUERY_BATCH_SIZE);
                if (batch.isEmpty()) {
                    break;
                }
                for (OAuthTokenBO existing : batch) {
                    if (existing.getId() != null && existing.getId() > afterId) {
                        afterId = existing.getId();
                    }
                    if (incomingDigests.contains(existing.getTokenDigest())
                            || existing.getMetadata() == null || existing.getMetadata().isInvalidated()) {
                        continue;
                    }
                    existing.getMetadata().setInvalidated(true);
                    if (type == OAuthTokenTypeEnum.CODE) {
                        existing.getMetadata().setCodeConsumed(true);
                        existing.setConsumedAt(clock.instant());
                    } else if (type == OAuthTokenTypeEnum.REFRESH) {
                        existing.setConsumedAt(clock.instant());
                    } else {
                        existing.setRevokedAt(clock.instant());
                    }
                    existing.setVersion(Math.addExact(existing.getVersion(), 1L));
                    tokenRepository.save(trustedRealm, existing, existing.getVersion() - 1L);
                }
                if (batch.size() < TOKEN_QUERY_BATCH_SIZE) {
                    break;
                }
            }
        }
    }

    private boolean isCurrentToken(OAuthTokenBO token, String presentedValue) {
        return token != null && token.getTokenValue() != null && sameToken(presentedValue, token.getTokenValue())
                && token.getExpiresAt() != null && token.getExpiresAt().isAfter(clock.instant())
                && token.getRevokedAt() == null && token.getConsumedAt() == null
                && token.getMetadata() != null && !token.getMetadata().isInvalidated()
                && !token.getMetadata().isCodeConsumed();
    }

    private boolean matchesPendingInteraction(OAuthAuthorizationBO authorization, String state) {
        OAuthPendingConsentBO pending = authorization.getAttributes() == null ? null : authorization.getAttributes().getPendingConsent();
        if (pending == null || !pending.getExpiresAt().isAfter(clock.instant()) || !sameToken(state, pending.getConsentState())
                || !(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes request)) { return false; }
        var interaction = interactions.require(request.getRequest(), false);
        var principal = SecurityContextHolder.getContext().getAuthentication();
        return principal instanceof UsernamePasswordAuthenticationToken && principal.isAuthenticated()
                && authorization.getPrincipalName().equals(principal.getName())
                && principal.getDetails() instanceof Map<?, ?> details
                && Objects.equals(authorization.getAuthenticationJtiDigest(), details.get(OAuthAuthenticationJwtService.AUTHENTICATION_DIGEST))
                && sameToken(pending.getBrowserBindingDigest(), interaction.getBrowserBindingDigest())
                && Objects.equals(authorization.getInteractionId(), interaction.getInteractionId())
                && "CONSENT_REQUIRED".equals(interaction.getState());
    }

    private static OAuthTokenTypeEnum toTokenType(OAuth2TokenType tokenType) {
        if (tokenType == null) {
            return null;
        }
        return switch (tokenType.getValue()) {
            case "access_token" -> OAuthTokenTypeEnum.ACCESS;
            case "refresh_token" -> OAuthTokenTypeEnum.REFRESH;
            case "code", "authorization_code" -> OAuthTokenTypeEnum.CODE;
            case "id_token" -> OAuthTokenTypeEnum.ID;
            case "state" -> OAuthTokenTypeEnum.CONSENT_STATE;
            default -> null;
        };
    }

    private static Comparator<OAuthTokenBO> tokenComparator() {
        return Comparator.comparing(OAuthTokenBO::getIssuedAt, Comparator.nullsFirst(Comparator.naturalOrder()))
                .thenComparing(OAuthTokenBO::getId, Comparator.nullsFirst(Comparator.naturalOrder()));
    }

    private static boolean sameToken(String left, String right) {
        return MessageDigest.isEqual(left.getBytes(StandardCharsets.UTF_8), right.getBytes(StandardCharsets.UTF_8));
    }

    private static Long parseOptionalPositiveId(String id) {
        if (id == null) {
            return null;
        }
        if (!id.matches("[1-9][0-9]{0,18}")) {
            throw new IllegalArgumentException("OAUTH_AUTHORIZATION_ID_INVALID");
        }
        try {
            return Long.parseLong(id);
        } catch (NumberFormatException failure) {
            return null;
        }
    }

    private static Long parseSasStorageId(String id) {
        if (id == null) {
            return null;
        }
        if (id.matches("[1-9][0-9]{0,18}")) {
            return parseOptionalPositiveId(id);
        }
        if (id.matches("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")) {
            return null;
        }
        throw new IllegalArgumentException("OAUTH_AUTHORIZATION_ID_INVALID");
    }
}
