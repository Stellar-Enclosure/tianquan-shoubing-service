package top.egon.cola.platform.tianquan.shoubing.admin.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthorityTokenVerifier;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSigningKeyBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthKeyStatusEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSigningKeyRepository;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class OAuthAuthorityTokenVerifierTest {
    private static final Instant NOW = Instant.parse("2026-10-23T00:00:00Z");
    private static final URI ISSUER = URI.create("https://idp.example/tenants/101");
    private static final URI RESOURCE = URI.create("https://api.example/orders");
    private static RSAKey key;
    private final TenantIssuerService issuers = mock(TenantIssuerService.class);
    private final OAuthSigningKeyRepository keys = mock(OAuthSigningKeyRepository.class);
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(ISSUER).realmKey("tenant:101")
            .realmType(RealmTypeEnum.TENANT).storagePartitionId(101L).businessTenantId(101L).trustVersion(0L).build();
    private OAuthAuthorityTokenVerifier verifier;
    private OAuthSigningKeyBO keyRow;

    @BeforeAll static void keys() throws Exception { key = new RSAKeyGenerator(2048).keyID("key-1").generate(); }

    @BeforeEach void setUp() throws Exception {
        keyRow = OAuthSigningKeyBO.builder().kid("key-1").status(OAuthKeyStatusEnum.ACTIVE)
                .publicJwk(new ObjectMapper().readTree(key.toPublicJWK().toJSONString())).build();
        when(issuers.resolveExactIssuer(ISSUER)).thenReturn(realm);
        when(keys.findByKid(realm, "key-1")).thenReturn(Optional.of(keyRow));
        verifier = new OAuthAuthorityTokenVerifier(issuers, keys, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test void verifiesARealSignatureAndExactTargetWithoutRemoteCalls() throws Exception {
        var proof = verifier.verify(sign(claims().build(), "at+jwt", key), RESOURCE, "orders-web", false);
        assertEquals(22L, proof.authorizationId()); assertEquals(12L, proof.clientPk());
        assertEquals(ISSUER, proof.realm().getIssuer()); assertEquals("alice", proof.claims().getSubject());
    }

    @Test void invalidSignatureIsRejectedEvenWithValidClaims() throws Exception {
        RSAKey other = new RSAKeyGenerator(2048).keyID("key-1").generate();
        assertThrows(OAuth2AuthenticationException.class,
                () -> verifier.verify(sign(claims().build(), "at+jwt", other), RESOURCE, "orders-web", false));
    }

    @Test void authenticationJwtAndIdTokenTypesCannotEnterAccessVerification() throws Exception {
        for (String type : List.of("JWT", "idp-authn+jwt")) {
            assertThrows(OAuth2AuthenticationException.class,
                    () -> verifier.verify(sign(claims().build(), type, key), RESOURCE, "orders-web", false));
        }
    }

    @Test void wrongAudienceAndClientAreRejected() throws Exception {
        String compact = sign(claims().build(), "at+jwt", key);
        assertThrows(OAuth2AuthenticationException.class,
                () -> verifier.verify(compact, URI.create("https://api.example/other"), "orders-web", false));
        assertThrows(OAuth2AuthenticationException.class,
                () -> verifier.verify(compact, RESOURCE, "another-client", false));
    }

    @Test void onlyTheExplicitRefreshProofPathCanRelaxAccessExpiry() throws Exception {
        String compact = sign(claims().issueTime(Date.from(NOW.minusSeconds(600)))
                .notBeforeTime(Date.from(NOW.minusSeconds(600))).expirationTime(Date.from(NOW.minusSeconds(300))).build(), "at+jwt", key);
        assertThrows(OAuth2AuthenticationException.class, () -> verifier.verify(compact, RESOURCE, "orders-web", false));
        assertNotNull(verifier.verify(compact, RESOURCE, "orders-web", true));
    }

    @Test void refreshProofCannotRelaxSignatureNotBeforeOrPrincipalType() throws Exception {
        assertThrows(OAuth2AuthenticationException.class, () -> verifier.verify(sign(claims()
                .notBeforeTime(Date.from(NOW.plusSeconds(90))).expirationTime(Date.from(NOW.plusSeconds(300))).build(), "at+jwt", key), RESOURCE, "orders-web", true));
        assertThrows(OAuth2AuthenticationException.class, () -> verifier.verify(sign(claims()
                .claim("principal_type", "SERVICE").subject("orders-web").build(), "at+jwt", key), RESOURCE, "orders-web", true));
    }

    @Test void revokedSigningKeyAndPurposeConfusionAreRejected() throws Exception {
        String compact = sign(claims().build(), "at+jwt", key);
        keyRow.setStatus(OAuthKeyStatusEnum.COMPROMISED);
        assertThrows(OAuth2AuthenticationException.class, () -> verifier.verify(compact, RESOURCE, "orders-web", false));
        keyRow.setStatus(OAuthKeyStatusEnum.ACTIVE);
        assertThrows(OAuth2AuthenticationException.class, () -> verifier.verify(sign(claims()
                .claim("token_use", "authentication").build(), "at+jwt", key), RESOURCE, "orders-web", false));
    }

    private static JWTClaimsSet.Builder claims() {
        return new JWTClaimsSet.Builder().issuer(ISSUER.toString()).audience(RESOURCE.toString()).subject("alice")
                .issueTime(Date.from(NOW)).notBeforeTime(Date.from(NOW)).expirationTime(Date.from(NOW.plusSeconds(300)))
                .jwtID("32").claim("authorization_id", "22").claim("client_registration_id", "12")
                .claim("client_id", "orders-web").claim("principal_type", "USER")
                .claim("tenant_id", "101").claim("scope_context", "TENANT");
    }

    private static String sign(JWTClaimsSet claims, String type, RSAKey signingKey) throws Exception {
        SignedJWT signed = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("key-1").type(new JOSEObjectType(type)).build(), claims);
        signed.sign(new RSASSASigner(signingKey)); return signed.serialize();
    }
}
