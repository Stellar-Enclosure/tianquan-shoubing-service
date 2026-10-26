package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.component.common.crypto.digest.Digests;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.repository.IdentityUserRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthenticationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthenticationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthKeyStatusEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSigningKeyRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthSecurityProjectionComponent;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityUserStatus;
import top.egon.cola.platform.tianquan.shoubing.core.port.TenantMembershipPort;

/** The SSO credential has its own JWT type and purpose; every use checks current PostgreSQL facts. */
@Service("oauthAuthenticationJwtService")
@RequiredArgsConstructor
public class OAuthAuthenticationJwtService {
    public static final String TYPE = "authn+jwt";
    public static final String PURPOSE = "IDP_AUTHENTICATION";
    public static final String AUTHENTICATION_DIGEST = "authenticationJtiDigest";
    @Qualifier("oAuthAuthenticationRepository") private final OAuthAuthenticationRepository authentications;
    @Qualifier("oAuthSigningKeyRepository") private final OAuthSigningKeyRepository keys;
    @Qualifier("oAuthSecurityStateRepository") private final OAuthSecurityStateRepository states;
    @Qualifier("identityUserRepository") private final IdentityUserRepository users;
    @Qualifier("tenantMembershipPort") private final TenantMembershipPort memberships;
    @Qualifier("oauthSecurityProjectionComponent") private final OAuthSecurityProjectionComponent security;
    @Qualifier("tenantJwkSourceComponent") private final JWKSource<SecurityContext> jwkSource;
    @Qualifier("idpClock") private final Clock clock;
    @Value("${egon.tianquan-shoubing.oauth.authentication-ttl:PT8H}") private final Duration ttl;

    @jakarta.annotation.PostConstruct
    void validateConfiguration() {
        if (ttl == null || ttl.compareTo(Duration.ofMinutes(1)) < 0 || ttl.compareTo(Duration.ofHours(8)) > 0) {
            throw new IllegalStateException("OAUTH_AUTHENTICATION_TTL_INVALID");
        }
    }

    @Transactional
    public Issued issue(TrustedRealmBO realm, Long clientPk, String subject, String bindingDigest) {
        validateConfiguration();
        requireIdentity(realm, subject);
        var snapshot = security.snapshotForAuthorization(realm, clientPk, "USER", subject);
        Instant authenticatedAt = clock.instant().truncatedTo(ChronoUnit.SECONDS);
        Instant expiresAt = authenticatedAt.plus(ttl);
        String jti = top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator.nextId();
        var claims = JwtClaimsSet.builder().issuer(realm.getIssuer().toASCIIString()).subject(subject)
                .audience(List.of(realm.getIssuer().toASCIIString())).issuedAt(authenticatedAt).expiresAt(expiresAt).id(jti)
                .claim("purpose", PURPOSE).claim("auth_time", authenticatedAt.getEpochSecond()).claim("acr", "PASSWORD")
                .claim("realm_version", snapshot.getRealmGeneration()).claim("subject_version", snapshot.getSubjectGeneration()).build();
        String token = new NimbusJwtEncoder(jwkSource).encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).type(TYPE).build(), claims)).getTokenValue();
        var fact = OAuthAuthenticationBO.builder().jtiDigest(Digests.sha256Hex(jti)).subject(subject)
                .browserBindingDigest(bindingDigest).realmGeneration(snapshot.getRealmGeneration())
                .subjectGeneration(snapshot.getSubjectGeneration()).authenticatedAt(authenticatedAt).acr("PASSWORD")
                .status("ACTIVE").expiresAt(expiresAt).retainUntil(expiresAt.plusSeconds(86_400)).build();
        fact = authentications.save(realm, fact, 0L);
        return new Issued(token, fact);
    }

    @Transactional(readOnly = true, isolation = org.springframework.transaction.annotation.Isolation.REPEATABLE_READ)
    public UsernamePasswordAuthenticationToken verify(TrustedRealmBO realm, String compact, String bindingDigest) {
        if (compact == null || compact.length() > 16_384 || bindingDigest == null) { throw rejected(); }
        try {
            SignedJWT signed = SignedJWT.parse(compact);
            var header = signed.getHeader();
            if (!JWSAlgorithm.RS256.equals(header.getAlgorithm()) || header.getType() == null
                    || !TYPE.equals(header.getType().toString()) || header.getKeyID() == null
                    || !header.getKeyID().matches("[A-Za-z0-9_-]{1,128}")
                    || header.getJWKURL() != null || header.getX509CertURL() != null
                    || header.getCriticalParams() != null && !header.getCriticalParams().isEmpty()) { throw rejected(); }
            var key = keys.findByKid(realm, header.getKeyID()).orElseThrow(OAuthAuthenticationJwtService::rejected);
            if (key.getStatus() == OAuthKeyStatusEnum.RETIRED || key.getStatus() == OAuthKeyStatusEnum.COMPROMISED
                    || key.getStatus() == OAuthKeyStatusEnum.VERIFY_ONLY
                    && (key.getVerifyUntil() == null || !key.getVerifyUntil().isAfter(clock.instant()))
                    || !signed.verify(new RSASSAVerifier(RSAKey.parse(key.getPublicJwk().toString()).toRSAPublicKey()))) {
                throw rejected();
            }
            var claims = signed.getJWTClaimsSet();
            if (!Set.of("iss", "sub", "aud", "iat", "exp", "jti", "purpose", "auth_time", "acr", "realm_version", "subject_version")
                    .equals(claims.getClaims().keySet()) || !realm.getIssuer().toASCIIString().equals(claims.getIssuer())
                    || !List.of(realm.getIssuer().toASCIIString()).equals(claims.getAudience())
                    || !PURPOSE.equals(claims.getStringClaim("purpose")) || !"PASSWORD".equals(claims.getStringClaim("acr"))
                    || claims.getJWTID() == null || !claims.getJWTID().matches("[1-9][0-9]{0,18}")
                    || claims.getIssueTime() == null || claims.getExpirationTime() == null
                    || claims.getIssueTime().toInstant().isAfter(clock.instant())
                    || !claims.getExpirationTime().toInstant().isAfter(clock.instant())) { throw rejected(); }
            String digest = Digests.sha256Hex(claims.getJWTID());
            var fact = authentications.findByJtiDigest(realm, digest).orElseThrow(OAuthAuthenticationJwtService::rejected);
            if (!"ACTIVE".equals(fact.getStatus()) || !Objects.equals(fact.getSubject(), claims.getSubject())
                    || !Objects.equals(fact.getBrowserBindingDigest(), bindingDigest)
                    || !Objects.equals(fact.getAuthenticatedAt(), claims.getIssueTime().toInstant())
                    || !Objects.equals(fact.getExpiresAt(), claims.getExpirationTime().toInstant())
                    || !Objects.equals(fact.getAcr(), claims.getStringClaim("acr"))
                    || !Objects.equals(fact.getAuthenticatedAt().getEpochSecond(), claims.getLongClaim("auth_time"))
                    || !Objects.equals(fact.getRealmGeneration(), claims.getLongClaim("realm_version"))
                    || !Objects.equals(fact.getSubjectGeneration(), claims.getLongClaim("subject_version"))) { throw rejected(); }
            requireGeneration(realm, OAuthSecurityTargetEnum.REALM, "self", fact.getRealmGeneration());
            requireGeneration(realm, OAuthSecurityTargetEnum.SUBJECT, fact.getSubject(), fact.getSubjectGeneration());
            requireIdentity(realm, fact.getSubject());
            var authentication = UsernamePasswordAuthenticationToken.authenticated(fact.getSubject(), "",
                    List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER"),
                            org.springframework.security.core.authority.FactorGrantedAuthority.withAuthority(
                                    org.springframework.security.core.authority.FactorGrantedAuthority.PASSWORD_AUTHORITY)
                                    .issuedAt(fact.getAuthenticatedAt()).build()));
            authentication.setDetails(Map.of("authTime", fact.getAuthenticatedAt(), "acr", fact.getAcr(),
                    AUTHENTICATION_DIGEST, digest, "authenticationJti", claims.getJWTID(), "authenticationExpiresAt", fact.getExpiresAt()));
            return authentication;
        } catch (java.text.ParseException | com.nimbusds.jose.JOSEException | IllegalArgumentException malformed) {
            throw rejected();
        }
    }

    private void requireGeneration(TrustedRealmBO realm, OAuthSecurityTargetEnum target, String key, long generation) {
        if (states.findByTarget(realm, target, key).filter(value -> value.isEnabled() && value.getGeneration() == generation).isEmpty()) {
            throw rejected();
        }
    }

    private void requireIdentity(TrustedRealmBO realm, String subject) {
        if (realm.getBusinessTenantId() == null || users.findByIdentitySub(subject)
                .filter(value -> value.status() == IdentityUserStatus.ACTIVE).isEmpty()) { throw rejected(); }
        var membership = memberships.resolve(subject, Long.toString(realm.getBusinessTenantId()));
        if (membership == null || membership.status() != TenantMembershipPort.MembershipStatus.ACTIVE) { throw rejected(); }
    }

    private static OAuth2AuthenticationException rejected() {
        return new OAuth2AuthenticationException(new OAuth2Error("invalid_token", "Authentication credential rejected", null));
    }

    public record Issued(@com.fasterxml.jackson.annotation.JsonIgnore String token, OAuthAuthenticationBO fact) {
        @Override public String toString() { return "Issued[redacted]"; }
    }
}
