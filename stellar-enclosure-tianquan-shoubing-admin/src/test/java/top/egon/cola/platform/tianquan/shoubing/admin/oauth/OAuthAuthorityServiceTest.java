package top.egon.cola.platform.tianquan.shoubing.admin.oauth;

import com.nimbusds.jwt.JWTClaimsSet;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import top.egon.cola.component.common.crypto.digest.Digests;
import top.egon.cola.platform.tianquan.shoubing.admin.audit.service.impl.OAuthAuditDeliveryService;
import top.egon.cola.platform.tianquan.shoubing.admin.identity.repository.IdentityUserRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthenticationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthAuthorizationBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthClientBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.OAuthClientPurposeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.RealmTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.*;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthorityService;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthAuthorityTokenVerifier;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl.OAuthManagementRealmResolver;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.bo.OAuthGrantBO;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.domain.bo.OAuthResourceBO;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthGrantRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.resource.repository.OAuthResourceRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthSecurityStateBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.bo.OAuthTokenBO;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthSecurityTargetEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.domain.enums.OAuthTokenTypeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.token.repository.*;
import top.egon.cola.platform.tianquan.shoubing.contract.state.*;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityUser;
import top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityUserStatus;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;
import top.egon.cola.platform.tianquan.shoubing.core.port.TenantMembershipPort;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ClientResourceGrant;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ResourceGrantType;
import top.egon.cola.platform.tianquan.shoubing.core.resource.ResourceServerStatus;
import top.egon.cola.platform.tianquan.shoubing.starter.autoconfigure.IdpStarterProperties;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class OAuthAuthorityServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-23T00:00:00Z");
    private static final URI ISSUER = URI.create("https://idp.example/tenants/101");
    private static final URI AUTHORITY = URI.create("https://api.example/idp"), ORDERS = URI.create("https://api.example/orders");
    private static final List<String> SERVICE_SCOPES = List.of(IdentityAuthorityScopes.STATE_RESOLVE, IdentityAuthorityScopes.REFRESH_CONTEXT, IdentityAuthorityScopes.AUDIT_APPEND);
    private final TrustedRealmBO realm = TrustedRealmBO.builder().issuer(ISSUER).realmKey("tenant:101").realmType(RealmTypeEnum.TENANT)
            .storagePartitionId(101L).businessTenantId(101L).trustVersion(0L).build();
    private final TrustedRealmBO platform = TrustedRealmBO.builder().issuer(URI.create("https://idp.example/platform")).realmKey("platform")
            .realmType(RealmTypeEnum.PLATFORM).storagePartitionId(1L).trustVersion(0L).build();
    private final OAuthAuthorityTokenVerifier verifier = mock(OAuthAuthorityTokenVerifier.class);
    private final OAuthAuthorizationRepository authorizations = mock(OAuthAuthorizationRepository.class);
    private final OAuthClientRepository clients = mock(OAuthClientRepository.class);
    private final OAuthTokenRepository tokens = mock(OAuthTokenRepository.class);
    private final OAuthAuthenticationRepository authentications = mock(OAuthAuthenticationRepository.class);
    private final OAuthSecurityStateRepository states = mock(OAuthSecurityStateRepository.class);
    private final OAuthRevocationRepository revocations = mock(OAuthRevocationRepository.class);
    private final OAuthResourceRepository resources = mock(OAuthResourceRepository.class);
    private final OAuthGrantRepository grants = mock(OAuthGrantRepository.class);
    private final IdentityUserRepository users = mock(IdentityUserRepository.class);
    private final TenantMembershipPort memberships = mock(TenantMembershipPort.class);
    private final OAuthManagementRealmResolver management = mock(OAuthManagementRealmResolver.class);
    private final OAuthAuditDeliveryService audit = mock(OAuthAuditDeliveryService.class);
    private final IdpStarterProperties properties = new IdpStarterProperties();
    private OAuthAuthorityService service;
    private OAuthAuthorizationBO userFamily;
    private OAuthAuthenticationBO authentication;
    private OAuthClientBO userClient;
    private OAuthTokenBO refresh;

    @BeforeEach void setUp() {
        properties.setResourceUri(AUTHORITY);
        service = new OAuthAuthorityService(verifier, authorizations, clients, tokens, authentications, states, revocations,
                resources, grants, users, memberships, management, audit, properties, Clock.fixed(NOW, ZoneOffset.UTC));
        when(management.platformRealm()).thenReturn(platform);
        var serviceClient = OAuthClientBO.builder().id(11L).clientId("orders-service").appId("orders")
                .purpose(OAuthClientPurposeEnum.SERVICE).status(OAuthClient.Status.ACTIVE).allowedScopes(SERVICE_SCOPES).build();
        userClient = OAuthClientBO.builder().id(12L).clientId("orders-web").appId("orders").browserBound(true)
                .purpose(OAuthClientPurposeEnum.USER).status(OAuthClient.Status.ACTIVE).allowedScopes(List.of("openid", "orders:read")).build();
        when(clients.findById(realm, 11L)).thenReturn(Optional.of(serviceClient));
        when(clients.findById(realm, 12L)).thenReturn(Optional.of(userClient));
        when(authorizations.findById(realm, 21L)).thenReturn(Optional.of(family(21L, 11L, "orders-service", "SERVICE", AUTHORITY, SERVICE_SCOPES)));
        userFamily = family(22L, 12L, "alice", "USER", ORDERS, List.of("openid", "orders:read"))
                .setAuthenticationJtiDigest(Digests.sha256Hex("900")).setClientBrowserBindingDigest("b".repeat(64)).setRefreshGeneration(0L);
        when(authorizations.findById(realm, 22L)).thenReturn(Optional.of(userFamily));
        when(tokens.findByTokenDigest(realm, Digests.sha256Hex("service-proof"))).thenReturn(Optional.of(access(31L, 21L, "301")));
        when(tokens.findByTokenDigest(realm, Digests.sha256Hex("user-proof"))).thenReturn(Optional.of(access(32L, 22L, "302")));
        refresh = OAuthTokenBO.builder().id(33L).authorizationPk(22L).tokenType(OAuthTokenTypeEnum.REFRESH)
                .tokenDigest("d".repeat(64)).refreshGeneration(0L).expiresAt(NOW.plusSeconds(28_800)).build();
        when(tokens.findByTokenDigest(realm, "d".repeat(64))).thenReturn(Optional.of(refresh));
        authentication = OAuthAuthenticationBO.builder().subject("alice").jtiDigest(Digests.sha256Hex("900")).realmGeneration(1L)
                .subjectGeneration(3L).status("ACTIVE").acr("PASSWORD").authenticatedAt(NOW).expiresAt(NOW.plusSeconds(28_800)).build();
        when(authentications.findByJtiDigest(realm, Digests.sha256Hex("900"))).thenReturn(Optional.of(authentication));
        var orders = resource("orders", ORDERS).setManagementClientId("orders-service");
        when(resources.findByResourceUri(platform, ORDERS)).thenReturn(Optional.of(orders));
        when(resources.findByResourceUri(platform, AUTHORITY)).thenReturn(Optional.of(resource("idp", AUTHORITY)));
        when(resources.findBySource(platform, "trade", "orders", "test")).thenReturn(Optional.of(orders));
        when(grants.findGrant(realm, 11L, "idp", ResourceGrantType.CLIENT_CREDENTIALS)).thenReturn(Optional.of(grant(11L, "idp", ResourceGrantType.CLIENT_CREDENTIALS, SERVICE_SCOPES)));
        when(grants.findGrant(realm, 12L, "orders", ResourceGrantType.USER_DELEGATION)).thenReturn(Optional.of(grant(12L, "orders", ResourceGrantType.USER_DELEGATION, List.of("orders:read"))));
        when(states.findByTarget(eq(realm), any(), anyString())).thenAnswer(call -> {
            OAuthSecurityTargetEnum type = call.getArgument(1); String key = call.getArgument(2);
            long generation = type == OAuthSecurityTargetEnum.REALM && "self".equals(key) ? 1
                    : type == OAuthSecurityTargetEnum.CLIENT && List.of("11", "12").contains(key) ? 2
                    : type == OAuthSecurityTargetEnum.SUBJECT && "alice".equals(key) ? 3 : -1;
            return generation < 0 ? Optional.empty() : Optional.of(OAuthSecurityStateBO.builder().generation(generation).enabled(true).build());
        });
        when(users.findByIdentitySub("alice")).thenReturn(Optional.of(new IdentityUser("alice", "alice", "alice", "Alice", IdentityUserStatus.ACTIVE, 0, null, NOW, 0)));
        when(memberships.resolve("alice", "101")).thenReturn(new TenantMembershipPort.TenantMembership("alice", "101", "Tenant", TenantMembershipPort.MembershipStatus.ACTIVE));
        when(verifier.verify("service-proof", AUTHORITY, null, false)).thenReturn(proof(false));
        when(verifier.verify(eq("user-proof"), eq(ORDERS), eq("orders-web"), anyBoolean())).thenReturn(proof(true));
    }

    @Test void serviceBindingAndCurrentUserFactsProduceOnlyMinimalBoundState() {
        var response = service.resolve(caller(), request(IdentityStatePurpose.ACCESS_VALIDATION));
        assertTrue(response.isEligible()); assertEquals("22", response.getAuthorizationId());
        assertEquals("900", response.getAuthenticationJti()); assertEquals("0", response.getRefreshGeneration());
        assertEquals(NOW.plusSeconds(28_800).getEpochSecond(), response.getAuthorizationExpiresAt());
        verify(states, never()).save(any(), any(), anyLong()); verifyNoInteractions(audit);
    }

    @Test void refreshRequiresCurrentGenerationAndMatchingBrowserBinding() {
        var request = request(IdentityStatePurpose.REFRESH_CONTEXT);
        assertTrue(service.resolve(caller(), request).isEligible());
        request.setBrowserBindingDigest("e".repeat(64));
        assertFalse(service.resolve(caller(), request).isEligible());
        request.setBrowserBindingDigest("b".repeat(64)); refresh.setConsumedAt(NOW);
        assertFalse(service.resolve(caller(), request).isEligible());
    }

    @Test void refreshDigestFromAnotherFamilyCannotBeUsed() {
        refresh.setAuthorizationPk(999L);
        assertFalse(service.resolve(caller(), request(IdentityStatePurpose.REFRESH_CONTEXT)).isEligible());
    }

    @Test void currentAuthenticationRevocationAndScopeRemovalTakeEffectWithoutReissuingJwt() {
        var caller = caller(); authentication.setStatus("REVOKED").setRevokedAt(NOW);
        assertFalse(service.resolve(caller, request(IdentityStatePurpose.ACCESS_VALIDATION)).isEligible());
        authentication.setStatus("ACTIVE").setRevokedAt(null); userClient.setAllowedScopes(List.of("openid"));
        assertFalse(service.resolve(caller, request(IdentityStatePurpose.ACCESS_VALIDATION)).isEligible());
    }

    @Test void sourceServiceCannotChooseAnUnboundTarget() {
        var request = request(IdentityStatePurpose.ACCESS_VALIDATION); request.setExpectedResource(URI.create("https://api.example/payroll"));
        assertThrows(AccessDeniedException.class, () -> service.resolve(caller(), request));
    }

    @Test void stateStoreFailureIsNotConvertedIntoEligibleOrAnEmptySuccess() {
        var caller = caller();
        when(states.findByTarget(realm, OAuthSecurityTargetEnum.SUBJECT, "alice"))
                .thenThrow(new org.springframework.dao.DataAccessResourceFailureException("unavailable"));
        assertThrows(org.springframework.dao.DataAccessException.class, () -> service.resolve(caller, request(IdentityStatePurpose.ACCESS_VALIDATION)));
    }

    @Test void closedFamilyInvalidatesPreviouslySignedAccessAndRefreshProof() {
        var caller = caller(); userFamily.setStatus("REVOKED");
        var response = service.resolve(caller, request(IdentityStatePurpose.REFRESH_CONTEXT));
        assertFalse(response.isEligible()); assertNull(response.getSubject()); assertNull(response.getAuthorizationId());
    }

    private OAuthAuthorityService.Caller caller() { return service.authenticateService("service-proof", IdentityAuthorityScopes.STATE_RESOLVE); }
    private IdentitySecurityStateRequest request(IdentityStatePurpose purpose) {
        return IdentitySecurityStateRequest.builder().purpose(purpose).accessToken("user-proof").expectedResource(ORDERS)
                .expectedClientId("orders-web").refreshTokenDigest("d".repeat(64)).browserBindingDigest("b".repeat(64)).build();
    }
    private OAuthAuthorityTokenVerifier.VerifiedAccess proof(boolean user) {
        var claims = new JWTClaimsSet.Builder().issuer(ISSUER.toString()).subject(user ? "alice" : "orders-service")
                .audience((user ? ORDERS : AUTHORITY).toString()).issueTime(Date.from(NOW)).expirationTime(Date.from(NOW.plusSeconds(300)))
                .jwtID(user ? "302" : "301").claim("client_registration_id", user ? "12" : "11")
                .claim("authorization_id", user ? "22" : "21").claim("client_id", user ? "orders-web" : "orders-service")
                .claim("principal_type", user ? "USER" : "SERVICE").claim("tenant_id", "101").claim("scope_context", "TENANT")
                .claim("scope", String.join(" ", user ? List.of("openid", "orders:read") : SERVICE_SCOPES))
                .claim("security_version", user ? Map.of("realm", 1, "client", 2, "subject", 3) : Map.of("realm", 1, "client", 2));
        if (user) { claims.claim("authn_jti", "900").claim("acr", "PASSWORD").claim("auth_time", NOW.getEpochSecond()).claim("refresh_generation", "0")
                .claim("authorization_expires_at", NOW.plusSeconds(28_800).getEpochSecond()).claim("authn_expires_at", NOW.plusSeconds(28_800).getEpochSecond()); }
        else { claims.claim("source_biz", "trade").claim("source_app", "orders").claim("source_env", "test").claim("app_id", "orders")
                .claim("credential_id", "credential").claim("resource_version", 1); }
        return new OAuthAuthorityTokenVerifier.VerifiedAccess(realm, claims.build(), "key-1");
    }
    private static OAuthAuthorizationBO family(long id, long client, String subject, String type, URI resource, List<String> scopes) {
        return OAuthAuthorizationBO.builder().id(id).clientPk(client).principalName(subject).principalType(type).audiences(List.of(resource.toString()))
                .resourceUri(resource.toString()).authorizedScopes(scopes).status("ACTIVE").absoluteExpiresAt(NOW.plusSeconds(28_800)).build();
    }
    private static OAuthTokenBO access(long id, long family, String jti) { return OAuthTokenBO.builder().id(id).authorizationPk(family).jti(jti).tokenType(OAuthTokenTypeEnum.ACCESS).build(); }
    private static OAuthResourceBO resource(String id, URI uri) { return OAuthResourceBO.builder().resourceServerId(id).resourceUri(uri).bizCode("trade").appCode(id).environment("test").version(1).status(ResourceServerStatus.ACTIVE).build(); }
    private static OAuthGrantBO grant(long client, String resource, ResourceGrantType type, List<String> scopes) { return OAuthGrantBO.builder().clientPk(client).resourceServerId(resource).grantType(type)
            .status(ClientResourceGrant.Status.ACTIVE).allowedScopes(scopes).resourceVersion(1L).build(); }
}
