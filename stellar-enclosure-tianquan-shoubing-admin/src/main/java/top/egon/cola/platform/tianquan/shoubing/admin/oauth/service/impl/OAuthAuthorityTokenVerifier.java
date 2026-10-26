package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.stereotype.Component;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthKeyStatusEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSigningKeyRepository;

/** Local signature verification for authority endpoints; it never calls the remote authority client. */
@Component("oauthAuthorityTokenVerifier")
@RequiredArgsConstructor
public class OAuthAuthorityTokenVerifier {

    @Qualifier("tenantIssuerService") private final TenantIssuerService issuers;
    @Qualifier("oAuthSigningKeyRepository") private final OAuthSigningKeyRepository keys;
    @Qualifier("idpClock") private final Clock clock;

    public VerifiedAccess verify(String compact, URI expectedAudience, String expectedClientId, boolean refreshContext) {
        if (compact == null || compact.isBlank() || compact.length() > 16_384 || expectedAudience == null) {
            throw invalid("JWT_PROOF_REQUIRED");
        }
        try {
            SignedJWT signed = SignedJWT.parse(compact);
            var header = signed.getHeader();
            if (!JWSAlgorithm.RS256.equals(header.getAlgorithm()) || header.getType() == null
                    || !"at+jwt".equals(header.getType().toString()) || header.getKeyID() == null
                    || !header.getKeyID().matches("[A-Za-z0-9_-]{1,128}")
                    || header.getJWKURL() != null || header.getX509CertURL() != null
                    || header.getCriticalParams() != null && !header.getCriticalParams().isEmpty()) {
                throw invalid("JWT_HEADER_INVALID");
            }
            JWTClaimsSet claims = signed.getJWTClaimsSet();
            TrustedRealmBO realm = issuers.resolveExactIssuer(URI.create(required(claims.getIssuer(), "iss")));
            var key = keys.findByKid(realm, header.getKeyID()).orElseThrow(() -> invalid("JWT_KEY_UNKNOWN"));
            if (key.getStatus() == OAuthKeyStatusEnum.RETIRED || key.getStatus() == OAuthKeyStatusEnum.COMPROMISED
                    || key.getStatus() == OAuthKeyStatusEnum.VERIFY_ONLY
                    && (key.getVerifyUntil() == null || !key.getVerifyUntil().isAfter(clock.instant()))
                    || !signed.verify(new RSASSAVerifier(RSAKey.parse(key.getPublicJwk().toString()).toRSAPublicKey()))) {
                throw invalid("JWT_SIGNATURE_INVALID");
            }
            Instant issued = instant(claims.getIssueTime(), "iat");
            Instant before = instant(claims.getNotBeforeTime(), "nbf");
            Instant expires = instant(claims.getExpirationTime(), "exp");
            Instant now = clock.instant();
            if (!expires.isAfter(before) || before.isBefore(issued)
                    || issued.isAfter(now.plusSeconds(30)) || before.isAfter(now.plusSeconds(30))
                    || Duration.between(issued, expires).compareTo(Duration.ofSeconds(600)) > 0
                    || !refreshContext && !expires.isAfter(now.minusSeconds(30))) {
                throw invalid("JWT_TIME_INVALID");
            }
            if (!List.of(expectedAudience.toASCIIString()).equals(claims.getAudience())
                    || claims.getClaim("token_use") != null) { throw invalid("JWT_AUDIENCE_OR_USE_INVALID"); }
            String principal = required(claims.getStringClaim("principal_type"), "principal_type");
            if (!List.of("USER", "SERVICE").contains(principal) || refreshContext && !"USER".equals(principal)) {
                throw invalid("JWT_PRINCIPAL_TYPE_INVALID");
            }
            String clientId = required(claims.getStringClaim("client_id"), "client_id");
            if (expectedClientId != null && !expectedClientId.equals(clientId)) { throw invalid("JWT_CLIENT_MISMATCH"); }
            String tenant = claims.getStringClaim("tenant_id");
            if (realm.getBusinessTenantId() == null
                    ? tenant != null || !"SERVICE".equals(principal) || !"PLATFORM".equals(claims.getStringClaim("scope_context"))
                    : !realm.getBusinessTenantId().toString().equals(tenant) || !"TENANT".equals(claims.getStringClaim("scope_context"))) {
                throw invalid("JWT_ISSUER_TENANT_MISMATCH");
            }
            positive(claims.getStringClaim("authorization_id"), "authorization_id");
            positive(claims.getStringClaim("client_registration_id"), "client_registration_id");
            positive(claims.getJWTID(), "jti"); required(claims.getSubject(), "sub");
            if ("SERVICE".equals(principal) && !clientId.equals(claims.getSubject())) { throw invalid("JWT_SERVICE_SUBJECT_INVALID"); }
            return new VerifiedAccess(realm, claims, header.getKeyID());
        } catch (OAuth2AuthenticationException failure) { throw failure; }
        catch (java.text.ParseException | com.nimbusds.jose.JOSEException | IllegalArgumentException failure) {
            throw invalid("JWT_PROOF_INVALID");
        }
    }

    public record VerifiedAccess(TrustedRealmBO realm, JWTClaimsSet claims, String keyId) {
        public long authorizationId() { return positive(text("authorization_id"), "authorization_id"); }
        public long clientPk() { return positive(text("client_registration_id"), "client_registration_id"); }
        public String text(String claim) {
            try { return required(claims.getStringClaim(claim), claim); }
            catch (java.text.ParseException invalid) { throw invalid("JWT_CLAIM_INVALID"); }
        }
        @Override public String toString() { return "VerifiedAccess[issuer=" + realm.getIssuer() + ",keyId=" + keyId + "]"; }
    }

    private static Instant instant(java.util.Date value, String name) {
        if (value == null) { throw invalid("JWT_" + name.toUpperCase() + "_REQUIRED"); }
        return value.toInstant();
    }

    private static String required(String value, String name) {
        if (value == null || value.isBlank() || !value.equals(value.trim()) || value.length() > 2048) {
            throw invalid("JWT_" + name.toUpperCase() + "_INVALID");
        }
        return value;
    }

    private static long positive(String value, String name) {
        if (value == null || !value.matches("[1-9][0-9]{0,18}")) { throw invalid("JWT_" + name.toUpperCase() + "_INVALID"); }
        try { return Long.parseLong(value); }
        catch (NumberFormatException failure) { throw invalid("JWT_" + name.toUpperCase() + "_INVALID"); }
    }

    private static OAuth2AuthenticationException invalid(String code) {
        return new OAuth2AuthenticationException(new OAuth2Error("invalid_token", code, null));
    }
}
