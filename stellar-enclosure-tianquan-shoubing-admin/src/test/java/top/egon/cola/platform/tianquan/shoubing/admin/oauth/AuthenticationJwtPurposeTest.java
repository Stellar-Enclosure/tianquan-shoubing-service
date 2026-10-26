package top.egon.cola.platform.tianquan.shoubing.admin.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import top.egon.cola.component.common.crypto.digest.Digests;
import top.egon.cola.component.common.id.snowflake.SnowflakeIdGenerator;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.repository.IdentityUserRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthenticationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthSecuritySnapshotBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthAuthenticationRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthenticationJwtService;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSecurityStateBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSigningKeyBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthKeyStatusEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSecurityStateRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.OAuthSigningKeyRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthSecurityProjectionComponent;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityUser;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityUserStatus;
import top.egon.cola.platform.tianquan.shoubing.core.port.TenantMembershipPort;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthenticationJwtPurposeTest {
    private static final Instant NOW = Instant.parse("2026-10-25T00:00:00Z");
    private static final URI ISSUER = URI.create("https://idp.example/tenants/101");
    private static final String BINDING = "a".repeat(64);
    private static RSAKey key;
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(ISSUER).realmKey("tenant:101")
            .realmType(RealmTypeEnum.TENANT).storagePartitionId(101L).businessTenantId(101L).trustVersion(0L).build();
    private final OAuthAuthenticationRepository facts = mock(OAuthAuthenticationRepository.class);
    private final OAuthSigningKeyRepository keys = mock(OAuthSigningKeyRepository.class);
    private final OAuthSecurityStateRepository states = mock(OAuthSecurityStateRepository.class);
    private final IdentityUserRepository users = mock(IdentityUserRepository.class);
    private final TenantMembershipPort memberships = mock(TenantMembershipPort.class);
    private final OAuthSecurityProjectionComponent projection = mock(OAuthSecurityProjectionComponent.class);
    private OAuthAuthenticationJwtService service;
    private OAuthAuthenticationBO fact;

    @BeforeAll static void key() throws Exception {
        key = new RSAKeyGenerator(2048).keyID("authn-key").generate();
        SnowflakeIdGenerator.initialize(0L, Duration.ofMillis(5));
    }

    @BeforeEach void prepare() throws Exception {
        service = serviceAt(NOW);
        fact = OAuthAuthenticationBO.builder().jtiDigest(Digests.sha256Hex("123")) .subject("alice")
                .browserBindingDigest(BINDING).realmGeneration(0L).subjectGeneration(0L).authenticatedAt(NOW).acr("PASSWORD")
                .status("ACTIVE").expiresAt(NOW.plusSeconds(28_800)).retainUntil(NOW.plusSeconds(115_200)).build();
        when(facts.findByJtiDigest(eq(realm), anyString())).thenAnswer(i -> Optional.of(fact));
        when(facts.save(eq(realm), any(), eq(0L))).thenAnswer(i -> i.getArgument(1));
        when(keys.findByKid(realm, "authn-key")).thenReturn(Optional.of(OAuthSigningKeyBO.builder().kid("authn-key")
                .status(OAuthKeyStatusEnum.ACTIVE).publicJwk(new ObjectMapper().readTree(key.toPublicJWK().toJSONString())).build()));
        when(states.findByTarget(eq(realm), any(), anyString())).thenReturn(Optional.of(OAuthSecurityStateBO.builder().enabled(true).generation(0L).build()));
        when(users.findByIdentitySub("alice")).thenReturn(Optional.of(new IdentityUser("alice", "alice", "alice", "Alice", IdentityUserStatus.ACTIVE, 0, null, null, 0L)));
        when(memberships.resolve("alice", "101")).thenReturn(new TenantMembershipPort.TenantMembership("alice", "101", "Tenant", TenantMembershipPort.MembershipStatus.ACTIVE));
        when(projection.snapshotForAuthorization(realm, 11L, "USER", "alice")).thenReturn(OAuthSecuritySnapshotBO.builder().realmGeneration(0L).subjectGeneration(0L).build());
    }

    @Test void signedAuthenticationJwtRestoresOnlyTheCurrentBrowserIdentity() throws Exception {
        var authentication = service.verify(realm, sign(claims().build(), "authn+jwt"), BINDING);
        assertEquals("alice", authentication.getName());
        assertEquals("PASSWORD", ((java.util.Map<?, ?>) authentication.getDetails()).get("acr"));
        verify(facts).findByJtiDigest(realm, Digests.sha256Hex("123"));
    }

    @Test void accessIdAndCsrfJwtTypesCannotBecomeSsoAuthentication() throws Exception {
        for (String type : List.of("at+jwt", "JWT", "csrf+jwt")) {
            String token = sign(claims().build(), type);
            assertThrows(OAuth2AuthenticationException.class, () -> service.verify(realm, token, BINDING));
        }
        verifyNoInteractions(facts);
    }

    @Test void wrongPurposeIssuerAudienceAndExtraAuthorizationClaimsAreRejected() throws Exception {
        var variants = List.of(claims().claim("purpose", "API_ACCESS").build(), claims().issuer("https://other.example/tenants/101").build(),
                claims().audience("https://api.example/orders").build(), claims().claim("scope", "admin").build());
        for (var claims : variants) {
            String token = sign(claims, "authn+jwt");
            assertThrows(OAuth2AuthenticationException.class, () -> service.verify(realm, token, BINDING));
        }
    }

    @Test void stolenCookieWrongBrowserAndRevokedFactAreRejected() throws Exception {
        String token = sign(claims().build(), "authn+jwt");
        assertThrows(OAuth2AuthenticationException.class, () -> service.verify(realm, token, "b".repeat(64)));
        fact.setStatus("REVOKED").setRevokedAt(NOW);
        assertThrows(OAuth2AuthenticationException.class, () -> service.verify(realm, token, BINDING));
    }

    @Test void changedGenerationAndDisabledMembershipRejectTheOldJwt() throws Exception {
        String token = sign(claims().build(), "authn+jwt");
        when(states.findByTarget(eq(realm), any(), anyString())).thenReturn(Optional.of(OAuthSecurityStateBO.builder().enabled(true).generation(1L).build()));
        assertThrows(OAuth2AuthenticationException.class, () -> service.verify(realm, token, BINDING));
        when(states.findByTarget(eq(realm), any(), anyString())).thenReturn(Optional.of(OAuthSecurityStateBO.builder().enabled(true).generation(0L).build()));
        when(memberships.resolve("alice", "101")).thenReturn(null);
        assertThrows(OAuth2AuthenticationException.class, () -> service.verify(realm, token, BINDING));
    }

    @Test void expiryCannotSlideWhenTheSameCookieIsVerifiedAgain() throws Exception {
        String token = sign(claims().build(), "authn+jwt");
        assertNotNull(serviceAt(NOW.plusSeconds(28_799)).verify(realm, token, BINDING));
        assertThrows(OAuth2AuthenticationException.class, () -> serviceAt(NOW.plusSeconds(28_800)).verify(realm, token, BINDING));
        verify(facts, never()).save(any(), any(), anyLong());
    }

    @Test void databaseFailureIsUnavailableAndNeverAnAnonymousSuccess() throws Exception {
        when(facts.findByJtiDigest(eq(realm), anyString())).thenThrow(new org.springframework.dao.DataAccessResourceFailureException("offline"));
        String token = sign(claims().build(), "authn+jwt");
        assertThrows(org.springframework.dao.DataAccessException.class, () -> service.verify(realm, token, BINDING));
    }

    @Test void realIssuanceUsesOnlyAuthenticationPurposeAndPasswordAssurance() throws Exception {
        var issued = service.issue(realm, 11L, "alice", BINDING);
        var jwt = SignedJWT.parse(issued.token());
        assertEquals("authn+jwt", jwt.getHeader().getType().toString());
        assertEquals(List.of(ISSUER.toASCIIString()), jwt.getJWTClaimsSet().getAudience());
        assertEquals("PASSWORD", jwt.getJWTClaimsSet().getStringClaim("acr"));
        assertEquals(NOW.plusSeconds(28_800), issued.fact().getExpiresAt());
        assertFalse(jwt.getJWTClaimsSet().getClaims().containsKey("scope"));
        assertFalse(issued.toString().contains(issued.token()));
    }

    private OAuthAuthenticationJwtService serviceAt(Instant now) {
        return new OAuthAuthenticationJwtService(facts, keys, states, users, memberships, projection,
                (selector, context) -> selector.select(new JWKSet(key)), Clock.fixed(now, ZoneOffset.UTC), Duration.ofHours(8));
    }
    private JWTClaimsSet.Builder claims() {
        return new JWTClaimsSet.Builder().issuer(ISSUER.toASCIIString()).audience(ISSUER.toASCIIString()).subject("alice").jwtID("123")
                .issueTime(Date.from(NOW)).expirationTime(Date.from(NOW.plusSeconds(28_800))).claim("purpose", "IDP_AUTHENTICATION")
                .claim("auth_time", NOW.getEpochSecond()).claim("acr", "PASSWORD").claim("realm_version", 0L).claim("subject_version", 0L);
    }
    private String sign(JWTClaimsSet claims, String type) throws Exception {
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("authn-key").type(new JOSEObjectType(type)).build(), claims);
        jwt.sign(new RSASSASigner(key)); return jwt.serialize();
    }
}
